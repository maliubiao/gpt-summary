Response:
Let's break down the thought process to answer the request about `image_frame_generator.cc`.

1. **Understand the Goal:** The request asks for the functionalities of this specific file, its relationship with web technologies (JavaScript, HTML, CSS), any logical inferences with input/output examples, and common usage errors.

2. **Initial Scan and Keyword Identification:** I'll first scan the code for prominent keywords and structures to get a general idea. I see things like `DecodeAndScale`, `DecodeToYUV`, `GetYUVAInfo`, `ImageDecoder`, `SkPixmap`, `SkISize`, locks (`base::AutoLock`), and mentions of `client_id`. The file path `blink/renderer/platform/graphics/` suggests it's related to rendering and graphics within the Blink engine.

3. **Function-by-Function Analysis:**  I'll go through each public method and understand its core purpose:

    * **`ImageFrameGenerator` (constructor):**  Initializes the object with image dimensions, whether it's multi-frame, color behavior, auxiliary image data, and supported sizes. This tells me it's about handling image data with various characteristics.

    * **`~ImageFrameGenerator` (destructor):** Removes the generator from the `ImageDecodingStore`. This implies the generator manages some cached or stored decoding information.

    * **`DecodeAndScale`:**  This looks like the main function for decoding image data to a specific `SkPixmap` (a Skia surface for drawing). It takes raw image data, flags for completeness, an index (likely for multi-frame images), the target `SkPixmap`, and a client ID. The "DecodeAndScale" name clearly indicates it decodes and potentially scales the image.

    * **`DecodeToYUV`:**  This handles decoding to YUV color space, used for video and some image formats. It takes raw data, an index, target color type, size and pointer arrays for the YUV planes, and a client ID. This points to specific optimization for certain image/video processing scenarios.

    * **`SetHasAlpha`:**  Records whether a specific frame in a multi-frame image has an alpha channel.

    * **`RecordWhetherMultiDecoded`:**  Tracks if the image is being decoded by multiple clients. This likely relates to performance optimization or debugging.

    * **`HasAlpha`:**  Checks if a specific frame has an alpha channel.

    * **`GetYUVAInfo`:**  Retrieves information about the YUV color format, like subsampling and bit depth. This is crucial for correctly interpreting YUV data.

    * **`GetSupportedDecodeSize`:** Determines the closest supported decoding size to the requested size. This suggests that the generator might not be able to decode to *any* arbitrary size and has predefined supported sizes.

    * **`ClientAutoLock`:** A helper class to manage locking around the decoding process, ensuring thread safety. The `lock_map_` member confirms this.

4. **Identifying Core Functionalities:**  Based on the function analysis, the core functionalities are:

    * **Decoding Image Data:**  The primary function is taking raw image data and turning it into a usable format (either `SkPixmap` or YUV planes).
    * **Scaling:** The `DecodeAndScale` function explicitly mentions scaling.
    * **Multi-Frame Image Handling:** The `index` parameter and `frame_count_` member suggest support for animated images or image sequences.
    * **YUV Decoding:** Dedicated support for decoding to the YUV color space.
    * **Alpha Channel Management:** Tracking and providing information about the alpha channel.
    * **Thread Safety:** The use of locks ensures that decoding can happen safely in a multi-threaded environment.
    * **Resource Management (through `ImageDecodingStore`):** Interacting with a store likely for caching decoded images or related data.
    * **Size Management:** Handling and optimizing for specific supported decoding sizes.

5. **Relating to JavaScript, HTML, and CSS:** Now, think about how these functionalities connect to web technologies:

    * **HTML `<img>` tag:**  When an `<img>` tag is encountered, the browser needs to fetch and decode the image. `ImageFrameGenerator` plays a key role in this decoding process.
    * **CSS `background-image`:** Similar to `<img>`, CSS background images also require decoding.
    * **`<canvas>` element:** JavaScript can use the Canvas API to draw images. The decoded image data provided by `ImageFrameGenerator` is what gets drawn onto the canvas.
    * **JavaScript `Image` object:**  JavaScript can create `Image` objects to load images programmatically. The underlying decoding mechanism would involve components like `ImageFrameGenerator`.
    * **Animated GIFs/WebP/APNG:**  The multi-frame support is crucial for displaying animated images. The `index` parameter corresponds to the specific frame being rendered.
    * **Video `<video>` element:** While not directly handling the *video stream*,  `DecodeToYUV` suggests involvement in video decoding, potentially for poster frames or video processing within the browser.

6. **Logical Inferences and Examples:**

    * **DecodeAndScale:** *Input:* Raw JPEG data, target `SkPixmap` of 100x100. *Output:* The `SkPixmap` will be filled with the decoded and scaled JPEG image data.
    * **DecodeToYUV:** *Input:* Raw H.264 video frame data, pointers to Y, U, and V plane buffers. *Output:* The buffers will be populated with the decoded YUV data.
    * **GetSupportedDecodeSize:** *Input:* Request for 150x150 decoding, `supported_sizes_` contains {50x50, 100x100, 200x200}. *Output:* 200x200 (the smallest supported size that's larger than the request).

7. **Common Usage Errors:** Think about how developers might misuse image loading or encounter issues:

    * **Incorrect Image Format:** Trying to decode a corrupted or unsupported image format. This would likely lead to `decode_failed_` being set.
    * **Insufficient Data:**  Trying to decode a frame when not all the data has been received yet (relevant for progressive loading).
    * **Incorrect YUV Buffer Sizes:** Providing YUV plane buffers that are too small to hold the decoded data.
    * **Concurrency Issues (though handled by the class):** If the locking wasn't implemented correctly, multiple threads trying to decode the same image simultaneously could lead to data corruption. The `ClientAutoLock` is there to prevent this.

8. **Structuring the Answer:**  Finally, organize the information logically, starting with the core functionalities, then moving to the relationships with web technologies, providing concrete examples, and ending with potential errors. Use clear and concise language. The prompt specifically asked for examples, so ensure those are clear and illustrate the concepts.

By following this systematic process, I can extract the relevant information from the code and present it in a comprehensive and understandable way, addressing all aspects of the original request.
这个文件 `blink/renderer/platform/graphics/image_frame_generator.cc` 在 Chromium Blink 渲染引擎中扮演着图像帧生成器的角色。它的主要功能是 **解码图像数据并生成可以用于渲染的图像帧**。

下面详细列举它的功能，并说明它与 JavaScript, HTML, CSS 的关系，以及逻辑推理和常见使用错误：

**主要功能:**

1. **图像解码:**
   - 接收原始的图像数据（例如 JPEG, PNG, GIF, WebP 等格式的字节流）。
   - 使用 `ImageDecoder` 类及其子类来执行实际的解码工作。`ImageDecoder` 会根据图像的格式选择合适的解码器。
   - `DecodeAndScale` 方法是主要的解码和缩放入口点。

2. **图像缩放:**
   - 可以根据需要将解码后的图像缩放到目标尺寸。
   - `GetSupportedDecodeSize` 方法用于确定最合适的解码尺寸，这可能用于优化性能，避免解码出过大的图像。

3. **多帧图像处理:**
   - 支持处理多帧图像，例如 GIF 和 APNG。
   - `index` 参数用于指定要解码的帧的索引。
   - 维护 `frame_count_` 成员变量来记录图像的总帧数。

4. **YUV 格式支持:**
   - 提供将图像解码为 YUV 格式的能力，这对于某些特定的渲染或视频处理场景非常重要。
   - `DecodeToYUV` 方法执行 YUV 解码。
   - `GetYUVAInfo` 方法用于获取 YUV 图像的元数据信息，例如子采样信息和颜色空间。

5. **Alpha 通道处理:**
   - 能够识别和处理图像的 alpha 通道（透明度信息）。
   - `HasAlpha` 方法用于判断指定帧是否包含 alpha 通道。
   - `SetHasAlpha` 方法记录帧的 alpha 信息。

6. **线程安全:**
   - 使用互斥锁 (`base::AutoLock`, `ClientAutoLock`) 来保护内部状态，确保在多线程环境下的安全访问。这对于渲染引擎至关重要，因为图像解码可能发生在不同的线程。

7. **性能优化:**
   - 与 `ImageDecodingStore` 交互，可能用于缓存解码后的图像数据，提高后续访问的效率。
   - 记录解码是否被多个客户端请求 (`RecordWhetherMultiDecoded`)，可能用于性能分析和优化。

**与 JavaScript, HTML, CSS 的关系:**

`ImageFrameGenerator` 本身是用 C++ 编写的，直接与 JavaScript, HTML, CSS 没有直接的语法上的交互。但是，它是浏览器渲染管道中不可或缺的一部分，支撑着这些 Web 技术的功能：

* **HTML `<img>` 标签:** 当浏览器解析到 `<img>` 标签时，会下载图像资源。`ImageFrameGenerator` 负责解码下载的图像数据，使其能够被渲染到页面上。`DecodeAndScale` 方法会被调用，将图像解码并可能缩放到 `<img>` 标签指定的尺寸或默认尺寸。
    * **示例:** `<img src="image.jpg" width="100" height="100">`  当浏览器处理这个标签时，`ImageFrameGenerator` 会解码 `image.jpg`，并可能将其缩放到 100x100 像素。

* **CSS `background-image` 属性:**  CSS 可以使用 `background-image` 属性来设置元素的背景图像。同样，`ImageFrameGenerator` 负责解码这些背景图像，以便浏览器能够绘制它们。
    * **示例:** `.my-div { background-image: url("background.png"); }`  浏览器会使用 `ImageFrameGenerator` 解码 `background.png` 并将其作为 `.my-div` 的背景绘制出来。

* **JavaScript `Image` 对象和 `<canvas>` 元素:** JavaScript 可以使用 `Image` 对象预加载图像，或者将图像绘制到 `<canvas>` 元素上。`ImageFrameGenerator` 提供的解码能力是这些操作的基础。当 JavaScript 将 `Image` 对象或画布上下文的图像数据传递给渲染引擎时，`ImageFrameGenerator` 会参与解码过程。
    * **示例:**
      ```javascript
      const img = new Image();
      img.onload = function() {
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
      };
      img.src = 'image.webp';
      ```
      在这个例子中，当 `image.webp` 加载完成后，`ImageFrameGenerator` 已经完成了它的解码工作，使得 `ctx.drawImage()` 可以将解码后的图像绘制到画布上。

* **Animated Images (GIF, APNG, WebP):** 对于动画图像，`ImageFrameGenerator` 的多帧处理能力至关重要。它会按顺序解码每一帧，使得浏览器能够播放动画。
    * **示例:** `<img src="animated.gif">`  `ImageFrameGenerator` 会解码 `animated.gif` 的每一帧，并控制动画的播放。

**逻辑推理和假设输入/输出:**

假设我们正在解码一个 JPEG 图像：

* **假设输入:**
    * `data`: 指向 JPEG 图像原始字节数据的指针。
    * `all_data_received`: `true`，表示所有图像数据都已接收。
    * `index`: `0`，表示这是单帧图像或第一帧。
    * `pixmap`: 一个目标 `SkPixmap` 对象，尺寸为 200x100。
    * `client_id`: 一个唯一的客户端 ID。

* **逻辑推理:**
    1. `DecodeAndScale` 方法被调用。
    2. 创建一个 `ImageDecoderWrapper`，它会选择合适的 JPEG 解码器。
    3. JPEG 解码器将原始字节数据解码成像素数据。
    4. 如果原始图像尺寸不是 200x100，解码器会进行缩放操作，将图像缩放到目标尺寸。
    5. 解码后的像素数据被写入到 `pixmap` 对象中。

* **假设输出:**
    * `DecodeAndScale` 方法返回 `true`，表示解码成功。
    * `pixmap` 对象现在包含了 JPEG 图像的解码后且缩放后的像素数据，尺寸为 200x100。

假设我们正在解码一个 YUV 格式的图像：

* **假设输入:**
    * `data`: 指向 YUV 图像原始字节数据的指针。
    * `index`: `0`。
    * `color_type`: `kYUV_888` 等表示 YUV 格式的颜色类型。
    * `component_sizes`: 包含 Y、U、V 平面预期尺寸的数组。
    * `planes`: 包含指向 Y、U、V 平面内存缓冲区的指针数组。
    * `row_bytes`: 包含 Y、U、V 平面每行字节数的数组。
    * `client_id`: 一个唯一的客户端 ID。

* **逻辑推理:**
    1. `DecodeToYUV` 方法被调用。
    2. 创建一个 `ImageDecoder`，它会识别 YUV 格式。
    3. 解码器将原始字节数据解码成 Y、U、V 三个颜色分量平面。
    4. 解码后的数据被分别写入到 `planes` 指向的内存缓冲区中，根据 `row_bytes` 指定的步幅。

* **假设输出:**
    * `DecodeToYUV` 方法返回 `true`，表示解码成功。
    * `planes` 指向的内存缓冲区现在包含了 YUV 图像的颜色分量数据。

**涉及用户或编程常见的使用错误:**

1. **尝试解码不支持的图像格式:** 如果传入 `ImageFrameGenerator` 的数据格式无法被任何已知的 `ImageDecoder` 处理，解码将会失败。
    * **示例:**  尝试将一个纯文本文件作为图像数据传递给 `DecodeAndScale`。

2. **提供的目标 `SkPixmap` 尺寸不兼容:**  虽然 `ImageFrameGenerator` 具有缩放能力，但在某些情况下，如果提供的 `SkPixmap` 尺寸与图像的宽高比差异过大，可能会导致不期望的缩放结果或性能问题。

3. **在多线程环境下不正确地使用 `ImageFrameGenerator` 的实例:**  虽然 `ImageFrameGenerator` 内部使用了锁来保证线程安全，但是如果多个线程以不协调的方式（例如，同时尝试解码同一帧）调用其方法，仍然可能导致问题或性能下降。正确的使用方式是通过 `ClientAutoLock` 来管理对解码器的访问。

4. **YUV 解码时提供的缓冲区大小不足:** 当调用 `DecodeToYUV` 时，如果 `planes` 指向的缓冲区大小不足以容纳解码后的 YUV 数据，会导致内存错误或数据截断。

5. **未接收到完整的图像数据就尝试解码:**  如果 `all_data_received` 设置为 `false`，并且实际数据不完整，解码可能会失败或产生不完整的图像。

总而言之，`image_frame_generator.cc` 是 Blink 渲染引擎中负责将各种图像格式的原始数据转化为可渲染图像帧的关键组件，它连接了 Web 内容中声明的图像资源和浏览器底层的图形处理能力。它的正确性和效率直接影响着网页的加载速度和用户体验。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/image_frame_generator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/graphics/image_frame_generator.h"

#include <array>
#include <memory>
#include <utility>

#include "base/not_fatal_until.h"
#include "base/synchronization/lock.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/graphics/image_decoder_wrapper.h"
#include "third_party/blink/renderer/platform/graphics/image_decoding_store.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/skia/include/core/SkData.h"

namespace blink {

SkYUVAInfo::Subsampling SubsamplingToSkiaSubsampling(
    cc::YUVSubsampling subsampling) {
  switch (subsampling) {
    case cc::YUVSubsampling::k410:
      return SkYUVAInfo::Subsampling::k410;
    case cc::YUVSubsampling::k411:
      return SkYUVAInfo::Subsampling::k411;
    case cc::YUVSubsampling::k420:
      return SkYUVAInfo::Subsampling::k420;
    case cc::YUVSubsampling::k422:
      return SkYUVAInfo::Subsampling::k422;
    case cc::YUVSubsampling::k440:
      return SkYUVAInfo::Subsampling::k440;
    case cc::YUVSubsampling::k444:
      return SkYUVAInfo::Subsampling::k444;
    case cc::YUVSubsampling::kUnknown:
      return SkYUVAInfo::Subsampling::kUnknown;
  }
}

static bool UpdateYUVAInfoSubsamplingAndWidthBytes(
    ImageDecoder* decoder,
    SkYUVAInfo::Subsampling* subsampling,
    base::span<size_t, SkYUVAInfo::kMaxPlanes> component_width_bytes) {
  SkYUVAInfo::Subsampling tempSubsampling =
      SubsamplingToSkiaSubsampling(decoder->GetYUVSubsampling());
  if (tempSubsampling == SkYUVAInfo::Subsampling::kUnknown) {
    return false;
  }
  *subsampling = tempSubsampling;
  component_width_bytes[0] = decoder->DecodedYUVWidthBytes(cc::YUVIndex::kY);
  component_width_bytes[1] = decoder->DecodedYUVWidthBytes(cc::YUVIndex::kU);
  component_width_bytes[2] = decoder->DecodedYUVWidthBytes(cc::YUVIndex::kV);
  // TODO(crbug/910276): Alpha plane is currently unsupported.
  component_width_bytes[3] = 0;
  return true;
}

ImageFrameGenerator::ImageFrameGenerator(const SkISize& full_size,
                                         bool is_multi_frame,
                                         ColorBehavior color_behavior,
                                         cc::AuxImage aux_image,
                                         Vector<SkISize> supported_sizes)
    : full_size_(full_size),
      decoder_color_behavior_(color_behavior),
      aux_image_(aux_image),
      is_multi_frame_(is_multi_frame),
      supported_sizes_(std::move(supported_sizes)) {
#if DCHECK_IS_ON()
  // Verify that sizes are in an increasing order, since
  // GetSupportedDecodeSize() depends on it.
  SkISize last_size = SkISize::MakeEmpty();
  for (auto& size : supported_sizes_) {
    DCHECK_GE(size.width(), last_size.width());
    DCHECK_GE(size.height(), last_size.height());
  }
#endif
}

ImageFrameGenerator::~ImageFrameGenerator() {
  // We expect all image decoders to be unlocked and catch with DCHECKs if not.
  ImageDecodingStore::Instance().RemoveCacheIndexedByGenerator(this);
}

bool ImageFrameGenerator::DecodeAndScale(
    SegmentReader* data,
    bool all_data_received,
    wtf_size_t index,
    const SkPixmap& pixmap,
    cc::PaintImage::GeneratorClientId client_id) {
  {
    base::AutoLock lock(generator_lock_);
    if (decode_failed_)
      return false;
    RecordWhetherMultiDecoded(client_id);
  }

  TRACE_EVENT1("blink", "ImageFrameGenerator::decodeAndScale", "generator",
               static_cast<void*>(this));

  // This implementation does not support arbitrary scaling so check the
  // requested size.
  const SkISize scaled_size = pixmap.dimensions();
  CHECK(GetSupportedDecodeSize(scaled_size) == scaled_size);

  wtf_size_t frame_count = 0u;
  bool has_alpha = true;

  // |decode_failed| indicates a failure due to a corrupt image.
  bool decode_failed = false;
  // |current_decode_succeeded| indicates a failure to decode the current frame.
  // Its possible to have a valid but fail to decode a frame in the case where
  // we don't have enough data to decode this particular frame yet.
  bool current_decode_succeeded = false;
  {
    // Lock the mutex, so only one thread can use the decoder at once.
    ClientAutoLock lock(this, client_id);
    ImageDecoderWrapper decoder_wrapper(this, data, pixmap,
                                        decoder_color_behavior_, aux_image_,
                                        index, all_data_received, client_id);
    current_decode_succeeded = decoder_wrapper.Decode(
        image_decoder_factory_.get(), &frame_count, &has_alpha);
    decode_failed = decoder_wrapper.decode_failed();
  }

  base::AutoLock lock(generator_lock_);
  decode_failed_ = decode_failed;
  if (decode_failed_) {
    DCHECK(!current_decode_succeeded);
    return false;
  }

  if (!current_decode_succeeded)
    return false;

  SetHasAlpha(index, has_alpha);
  if (frame_count != 0u)
    frame_count_ = frame_count;

  return true;
}

bool ImageFrameGenerator::DecodeToYUV(
    SegmentReader* data,
    wtf_size_t index,
    SkColorType color_type,
    base::span<const SkISize, cc::kNumYUVPlanes> component_sizes,
    base::span<void*, cc::kNumYUVPlanes> planes,
    base::span<const wtf_size_t, cc::kNumYUVPlanes> row_bytes,
    cc::PaintImage::GeneratorClientId client_id) {
  base::AutoLock lock(generator_lock_);
  DCHECK_EQ(index, 0u);

  RecordWhetherMultiDecoded(client_id);

  // TODO (scroggo): The only interesting thing this uses from the
  // ImageFrameGenerator is |decode_failed_|. Move this into
  // DecodingImageGenerator, which is the only class that calls it.
  if (decode_failed_ || yuv_decoding_failed_)
    return false;

  if (!planes.data() || !planes[0] || !planes[1] || !planes[2] ||
      !row_bytes.data() || !row_bytes[0] || !row_bytes[1] || !row_bytes[2]) {
    return false;
  }
  const bool all_data_received = true;
  std::unique_ptr<ImageDecoder> decoder = ImageDecoder::Create(
      data, all_data_received, ImageDecoder::kAlphaPremultiplied,
      ImageDecoder::kDefaultBitDepth, decoder_color_behavior_, aux_image_,
      Platform::GetMaxDecodedImageBytes());
  // getYUVComponentSizes was already called and was successful, so
  // ImageDecoder::create must succeed.
  DCHECK(decoder);

  auto image_planes =
      std::make_unique<ImagePlanes>(planes, row_bytes, color_type);
  // TODO(crbug.com/943519): Don't forget to initialize planes to black or
  // transparent for incremental decoding.
  decoder->SetImagePlanes(std::move(image_planes));

  DCHECK(decoder->CanDecodeToYUV());

  {
    // This is the YUV analog of ImageFrameGenerator::decode.
    TRACE_EVENT0("blink,benchmark", "ImageFrameGenerator::decodeToYUV");
    decoder->DecodeToYUV();
  }

  // Display a complete scan if available, even if decoding fails.
  if (decoder->HasDisplayableYUVData()) {
    // TODO(crbug.com/910276): Set this properly for alpha support.
    SetHasAlpha(index, false);
    return true;
  }

  // Currently if there is no displayable data, the decoder always fails.
  // This may not be the case once YUV supports incremental decoding
  // (crbug.com/943519).
  if (decoder->Failed()) {
    yuv_decoding_failed_ = true;
  }

  return false;
}

void ImageFrameGenerator::SetHasAlpha(wtf_size_t index, bool has_alpha) {
  generator_lock_.AssertAcquired();

  if (index >= has_alpha_.size()) {
    const wtf_size_t old_size = has_alpha_.size();
    has_alpha_.resize(index + 1);
    for (wtf_size_t i = old_size; i < has_alpha_.size(); ++i)
      has_alpha_[i] = true;
  }
  has_alpha_[index] = has_alpha;
}

void ImageFrameGenerator::RecordWhetherMultiDecoded(
    cc::PaintImage::GeneratorClientId client_id) {
  generator_lock_.AssertAcquired();

  if (client_id == cc::PaintImage::kDefaultGeneratorClientId)
    return;

  if (last_client_id_ == cc::PaintImage::kDefaultGeneratorClientId) {
    DCHECK(!has_logged_multi_clients_);
    last_client_id_ = client_id;
    UMA_HISTOGRAM_ENUMERATION(
        "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds",
        DecodeTimesType::kRequestByAtLeastOneClient);
  } else if (last_client_id_ != client_id && !has_logged_multi_clients_) {
    has_logged_multi_clients_ = true;
    UMA_HISTOGRAM_ENUMERATION(
        "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds",
        DecodeTimesType::kRequestByMoreThanOneClient);
  }
}

bool ImageFrameGenerator::HasAlpha(wtf_size_t index) {
  base::AutoLock lock(generator_lock_);

  if (index < has_alpha_.size())
    return has_alpha_[index];
  return true;
}

bool ImageFrameGenerator::GetYUVAInfo(
    SegmentReader* data,
    const SkYUVAPixmapInfo::SupportedDataTypes& supported_data_types,
    SkYUVAPixmapInfo* info) {
  TRACE_EVENT2("blink", "ImageFrameGenerator::GetYUVAInfo", "width",
               full_size_.width(), "height", full_size_.height());

  base::AutoLock lock(generator_lock_);

  if (yuv_decoding_failed_)
    return false;
  std::unique_ptr<ImageDecoder> decoder = ImageDecoder::Create(
      data, /*data_complete=*/true, ImageDecoder::kAlphaPremultiplied,
      ImageDecoder::kDefaultBitDepth, decoder_color_behavior_, aux_image_,
      Platform::GetMaxDecodedImageBytes());
  DCHECK(decoder);

  DCHECK(decoder->CanDecodeToYUV())
      << decoder->FilenameExtension() << " image decoder";
  SkYUVAInfo::Subsampling subsampling;
  std::array<size_t, SkYUVAInfo::kMaxPlanes> width_bytes;
  if (!UpdateYUVAInfoSubsamplingAndWidthBytes(decoder.get(), &subsampling,
                                              width_bytes)) {
    return false;
  }
  SkYUVAInfo yuva_info(full_size_, SkYUVAInfo::PlaneConfig::kY_U_V, subsampling,
                       decoder->GetYUVColorSpace());
  SkYUVAPixmapInfo::DataType dataType;
  if (decoder->GetYUVBitDepth() > 8) {
    if (supported_data_types.supported(SkYUVAInfo::PlaneConfig::kY_U_V,
                                       SkYUVAPixmapInfo::DataType::kUnorm16)) {
      dataType = SkYUVAPixmapInfo::DataType::kUnorm16;
    } else if (supported_data_types.supported(
                   SkYUVAInfo::PlaneConfig::kY_U_V,
                   SkYUVAPixmapInfo::DataType::kFloat16)) {
      dataType = SkYUVAPixmapInfo::DataType::kFloat16;
    } else {
      return false;
    }
  } else if (supported_data_types.supported(
                 SkYUVAInfo::PlaneConfig::kY_U_V,
                 SkYUVAPixmapInfo::DataType::kUnorm8)) {
    dataType = SkYUVAPixmapInfo::DataType::kUnorm8;
  } else {
    return false;
  }
  *info = SkYUVAPixmapInfo(yuva_info, dataType, width_bytes.data());
  DCHECK(info->isSupported(supported_data_types));

  return true;
}

SkISize ImageFrameGenerator::GetSupportedDecodeSize(
    const SkISize& requested_size) const {
  for (auto& size : supported_sizes_) {
    if (size.width() >= requested_size.width() &&
        size.height() >= requested_size.height()) {
      return size;
    }
  }
  return full_size_;
}

ImageFrameGenerator::ClientAutoLock::ClientAutoLock(
    ImageFrameGenerator* generator,
    cc::PaintImage::GeneratorClientId client_id)
    : generator_(generator), client_id_(client_id) {
  {
    base::AutoLock lock(generator_->generator_lock_);
    auto it = generator_->lock_map_.find(client_id_);
    ClientLock* client_lock;
    if (it == generator_->lock_map_.end()) {
      auto result = generator_->lock_map_.insert(
          client_id_, std::make_unique<ClientLock>());
      client_lock = result.stored_value->value.get();
    } else {
      client_lock = it->value.get();
    }
    client_lock->ref_count++;
    lock_ = &client_lock->lock;
  }

  lock_->Acquire();
}

ImageFrameGenerator::ClientAutoLock::~ClientAutoLock() {
  lock_->Release();

  base::AutoLock lock(generator_->generator_lock_);
  auto it = generator_->lock_map_.find(client_id_);
  CHECK(it != generator_->lock_map_.end(), base::NotFatalUntil::M130);
  it->value->ref_count--;

  if (it->value->ref_count == 0)
    generator_->lock_map_.erase(it);
}

}  // namespace blink

"""

```