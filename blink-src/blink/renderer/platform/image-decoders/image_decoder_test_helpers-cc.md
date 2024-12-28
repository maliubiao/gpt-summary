Response:
The user wants to understand the functionality of the C++ file `image_decoder_test_helpers.cc`. I need to analyze the code and explain its purpose. The request also specifically asks about connections to web technologies (JavaScript, HTML, CSS), logical reasoning with input/output examples, and common user/programming errors.

Here's a breakdown of the code and how to address the user's request:

1. **File Reading Functions:** The file provides helper functions to read image files from disk into different data structures (`Vector<char>` and `SharedBuffer`). These are fundamental for testing image decoding.

2. **Bitmap Hashing:** The `HashBitmap` function calculates a hash of a `SkBitmap`. This is crucial for comparing decoded image frames to expected baselines.

3. **Baseline Creation:** `CreateDecodingBaseline` decodes an image fully and stores the hashes of each frame. This serves as the "ground truth" for subsequent tests.

4. **Byte-by-Byte Decoding Test:** `TestByteByByteDecode` simulates feeding image data to the decoder byte by byte. It compares the decoded frames at each step with the pre-computed baseline. This tests the robustness of the decoder against incomplete data.

5. **Random Frame Decoding Tests:** `TestRandomFrameDecode` and `TestRandomDecodeAfterClearFrameBufferCache` check the decoder's ability to decode specific frames without sequentially decoding previous ones. The "clear cache" variant tests the impact of memory management.

6. **Data Reallocation Test:** `TestDecodeAfterReallocatingData` ensures the decoder can handle changes in the underlying data buffer after initial parsing.

7. **Size Availability Test:** `TestByteByByteSizeAvailable` verifies that the decoder correctly reports when the image size and other metadata become available during incremental data loading.

8. **Progressive Decoding Test:** `TestProgressiveDecoding` compares the results of decoding an image incrementally with decoding a truncated version of the image at each step. This verifies consistent behavior for progressive loading.

9. **Required Previous Frame Test:** `TestUpdateRequiredPreviousFrameAfterFirstDecode` checks how the decoder tracks dependencies between frames in animated images.

10. **Convenience Overloads:**  There are many overloaded versions of the test functions that take file paths as strings, simplifying test setup.

11. **Frame Comparison:** `VerifyFramesMatch` compares two `ImageFrame` objects pixel by pixel, allowing for a small tolerance due to potential pre-multiplication rounding.

12. **Alpha Blending Test:** `TestAlphaBlending` verifies that decoding with pre-multiplied and non-pre-multiplied alpha produces visually similar results.

13. **BPP Histogram Test:** `TestBppHistogram` checks if the correct bits-per-pixel (BPP) value is recorded in a histogram for image analysis.

**Connections to Web Technologies:**

* **HTML `<img>` tag:**  The core purpose of these decoders is to process image data loaded by the `<img>` tag in HTML.
* **CSS `background-image`:** Similarly, image decoders are used when images are specified as CSS background images.
* **JavaScript `Image()` object and `fetch()` API:** JavaScript code can load images using these APIs, and the loaded data will be processed by the image decoders.
* **Canvas API:**  Decoded image data is often drawn onto a `<canvas>` element using JavaScript.

**Logical Reasoning Examples:**

* **Byte-by-Byte Decoding:**
    * **Input:** Image data received one byte at a time.
    * **Output:**  The decoder should eventually produce the same final set of image frames as if the entire data was available at once. Intermediate states might have incomplete or partially decoded frames.
* **Random Frame Decoding:**
    * **Input:**  Request to decode frame N of an animated image.
    * **Output:** The decoder should be able to decode frame N correctly, potentially needing to decode previous frames if frame N depends on them.

**Common Errors:**

* **Providing incorrect or corrupted image data:** This will cause the decoders to fail. The tests help verify how decoders handle such errors (though this file focuses on successful decoding paths).
* **Assuming all image formats support all decoding features:** For example, not all formats support progressive loading or animation. The tests here help ensure decoders behave correctly for the features they *do* support.
* **Incorrectly handling asynchronous image loading:** While this file doesn't directly address asynchronicity, the byte-by-byte tests simulate a form of incremental loading, which is related to asynchronous behavior in a browser.

By addressing these points, I can create a comprehensive and accurate explanation of the file's functionality for the user.
`image_decoder_test_helpers.cc` 是 Chromium Blink 引擎中用于测试图像解码器的辅助文件。它提供了一系列工具函数，旨在简化和标准化对不同图像解码器进行单元测试的过程。

以下是其主要功能：

**1. 读取测试数据:**

* **`ReadFile(StringView file_name)` 和 `ReadFile(const char* dir, const char* file_name)`:**  这两个函数用于从磁盘读取图像文件内容到 `Vector<char>` 中。它们负责构建完整的文件路径，并使用测试框架提供的工具函数进行读取。
    * **假设输入:**  `ReadFile("test.png")` 或 `ReadFile("web_tests/images", "animated.gif")`
    * **输出:**  包含文件内容的 `Vector<char>`。如果文件不存在或读取失败，则会触发 `CHECK` 宏导致程序终止。
* **`ReadFileToSharedBuffer(StringView file_name)` 和 `ReadFileToSharedBuffer(const char* dir, const char* file_name)`:**  这两个函数与上述函数类似，但它们将读取到的文件内容封装到 `scoped_refptr<SharedBuffer>` 中。`SharedBuffer` 是 Blink 中用于管理共享内存的类，更适合用于传递图像数据。
    * **假设输入:**  `ReadFileToSharedBuffer("test.jpg")`
    * **输出:**  指向包含文件内容的 `SharedBuffer` 的智能指针。

**2. 图像数据处理:**

* **`HashBitmap(const SkBitmap& bitmap)`:**  计算 `SkBitmap` 对象的哈希值。`SkBitmap` 是 Skia 图形库中表示位图的类。这个函数用于生成图像内容的指纹，方便在测试中比较解码后的图像是否与预期一致。
    * **假设输入:**  一个包含解码后图像数据的 `SkBitmap` 对象。
    * **输出:**  一个无符号整数，表示该位图的哈希值。

**3. 基线测试:**

* **`CreateDecodingBaseline(DecoderCreator create_decoder, SharedBuffer* data, Vector<unsigned>* baseline_hashes)`:**  这个函数使用给定的图像解码器 (`create_decoder`) 完全解码提供的图像数据 (`data`)，并计算每一帧的哈希值，存储在 `baseline_hashes` 中。这为后续的测试提供了一个“黄金标准”的结果。
    * **假设输入:**
        * `create_decoder`: 一个函数指针或 lambda 表达式，用于创建待测试的 `ImageDecoder` 对象。
        * `data`: 包含完整图像数据的 `SharedBuffer`。
    * **输出:**  `baseline_hashes` 向量将被填充，其中每个元素是解码后对应帧的位图哈希值。

**4. 各种解码场景测试:**

* **`TestByteByByteDecode(DecoderCreator create_decoder, SharedBuffer* shared_data, size_t expected_frame_count, int expected_repetition_count)`:**  模拟逐字节地将图像数据提供给解码器，测试解码器在接收到不完整数据时的行为。它将解码结果与基线结果进行比较，验证解码的正确性。
    * **与 JavaScript, HTML, CSS 的关系:**  当浏览器逐步下载图片资源时（例如，通过网络加载），图像解码器会收到部分数据。这个测试模拟了这种场景，确保解码器在收到不完整数据时也能正确处理，并最终在数据完整后解码出正确的图像。
    * **假设输入:**
        * `create_decoder`: 用于创建解码器的函数。
        * `shared_data`: 包含完整图像数据的 `SharedBuffer`。
        * `expected_frame_count`: 期望的帧数（对于动画图像）。
        * `expected_repetition_count`: 期望的动画循环次数。
    * **输出:**  通过一系列 `EXPECT_` 宏断言，验证解码过程中的帧数、最终的帧数、循环次数以及每一帧的哈希值是否与预期一致。
* **`TestRandomFrameDecode(DecoderCreator create_decoder, SharedBuffer* full_data, size_t skipping_step)`:** 测试解码器是否能够正确解码任意指定的帧，而无需按顺序解码之前的帧。这对于测试动画图像的随机访问能力很重要。
    * **与 JavaScript, HTML, CSS 的关系:**  某些 JavaScript 动画库或图像处理逻辑可能需要访问动画图像的特定帧，而不是从头到尾播放。这个测试确保解码器能够支持这种随机访问。
    * **假设输入:**
        * `create_decoder`: 用于创建解码器的函数。
        * `full_data`: 包含完整图像数据的 `SharedBuffer`。
        * `skipping_step`:  用于跳过解码的步长，例如，如果为 2，则解码第 0, 2, 4... 帧。
    * **输出:**  通过 `EXPECT_EQ` 宏断言，验证随机解码的帧的哈希值与基线结果一致。
* **`TestRandomDecodeAfterClearFrameBufferCache(...)`:**  在清除解码器的帧缓冲区缓存后，测试随机帧解码。这可以测试解码器的缓存管理和重新解码能力。
* **`TestDecodeAfterReallocatingData(...)`:** 测试在解码过程中重新分配图像数据缓冲区后，解码器是否能继续正确解码。
* **`TestByteByByteSizeAvailable(...)`:** 测试当逐字节提供数据时，解码器何时能够确定图像的尺寸和元数据是否可用。
    * **与 JavaScript, HTML, CSS 的关系:**  在浏览器加载图片时，可能需要先获取图片的尺寸，以便进行布局计算。这个测试确保解码器能在接收到足够的数据后及时提供尺寸信息。
    * **假设输入:**  包含图像数据的 `SharedBuffer`，以及一个偏移量 `frame_offset`。
    * **输出:**  通过 `EXPECT_FALSE` 和 `EXPECT_TRUE` 宏断言，验证在不同数据量下 `IsSizeAvailable()` 方法的返回值是否符合预期。
* **`TestProgressiveDecoding(...)`:** 测试解码器的渐进式解码能力。它比较了逐步解码完整图像和解码部分图像的哈希值。
    * **与 JavaScript, HTML, CSS 的关系:**  对于大型图片，渐进式解码允许浏览器在下载完成之前先显示部分图像，提高用户体验。这个测试确保解码器在逐步接收数据时能够生成正确的中间结果。
* **`TestUpdateRequiredPreviousFrameAfterFirstDecode(...)`:** 测试在首次解码后，解码器是否能正确标记需要依赖前一帧的帧。这对于动画图像的正确渲染至关重要。
* **`TestAlphaBlending(...)`:**  测试当解码具有 Alpha 通道的图像时，解码器在处理预乘 Alpha 和非预乘 Alpha 时的结果是否一致。
    * **与 JavaScript, HTML, CSS 的关系:**  Alpha 通道用于控制图像的透明度。预乘 Alpha 是一种优化技术，可以提高渲染性能。这个测试确保浏览器在处理不同 Alpha 模式的图像时能够得到预期的渲染效果。
    * **假设输入:**  包含具有 Alpha 通道的图像数据的 `SharedBuffer`。
    * **输出:**  通过 `VerifyFramesMatch` 函数比较使用预乘和非预乘 Alpha 解码后的帧，允许一定的像素差异。
* **`TestBppHistogram(...)`:** 测试解码器是否正确记录了图像的每像素比特数 (BPP) 到直方图中。这用于性能分析和监控。

**5. 辅助比较函数:**

* **`VerifyFramesMatch(const char* file, const ImageFrame* const a, const ImageFrame* const b)`:**  比较两个 `ImageFrame` 对象的像素数据是否一致，允许一定的误差范围，因为预乘可能会导致舍入误差。

**与 JavaScript, HTML, CSS 的关系举例:**

* 当 HTML 中包含 `<img src="animated.gif">` 时，浏览器会下载 `animated.gif` 文件。`TestByteByByteDecode` 就模拟了浏览器逐步接收 `animated.gif` 数据并交给图像解码器的过程。
* JavaScript 可以使用 `Image()` 对象创建一个新的图片对象，并设置其 `src` 属性来加载图片。`TestProgressiveDecoding` 模拟了当 JavaScript 加载一个大型 PNG 图片时，解码器如何逐步解码并允许浏览器在下载完成前显示部分图像。
* CSS 中可以使用 `background-image: url("transparent.png")` 来设置元素的背景图片。如果 `transparent.png` 包含透明度信息，`TestAlphaBlending` 就测试了 Blink 的图像解码器在处理这种图片时，是否能正确处理 Alpha 通道，并生成可用于渲染的位图数据。

**逻辑推理举例:**

* **假设输入 (TestByteByByteDecode):** 一个包含完整 PNG 图像数据的 `SharedBuffer`，以及一个 PNG 解码器。
* **输出 (TestByteByByteDecode):**  在逐字节提供数据期间，`decoder->FrameCount()` 的值会逐步增加，直到达到 PNG 图像的实际帧数（通常为 1）。当所有数据都提供后，`decoder->DecodeFrameBufferAtIndex(0)->GetStatus()` 应该返回 `ImageFrame::kFrameComplete`，并且其哈希值应该与基线哈希值一致。

**用户或编程常见的使用错误举例:**

* **忘记处理图像加载错误:**  虽然这个文件主要关注解码器的内部逻辑，但实际使用中，开发者需要处理图像加载失败的情况。例如，如果提供的文件路径不正确，`ReadFile` 或 `ReadFileToSharedBuffer` 会导致程序终止（通过 `CHECK` 宏）。更健壮的代码应该使用 `std::optional` 返回值并检查是否成功读取。
* **假设所有图像格式都支持所有功能:**  例如，尝试对一个静态 PNG 文件调用针对动画 GIF 特有的方法或假设其有多个帧。`image_decoder_test_helpers.cc` 中的测试可以帮助确保针对不同图像格式的解码器不会出现意外行为。
* **在主线程进行耗时的图像解码操作:**  图像解码可能消耗大量 CPU 资源。在主线程执行会导致 UI 卡顿。开发者应该在后台线程或 Web Worker 中进行解码操作。这个文件虽然不直接涉及线程问题，但其测试的解码器最终会被用于浏览器的主线程或其他线程。

总而言之，`image_decoder_test_helpers.cc` 是一个关键的测试基础设施文件，它提供了一套全面的工具，用于验证 Chromium Blink 引擎中图像解码器的正确性和健壮性，确保浏览器能够正确处理各种图像格式和解码场景。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/image_decoder_test_helpers.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"

#include <memory>

#include "base/strings/strcat.h"
#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/image-decoders/image_frame.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hasher.h"

namespace blink {

Vector<char> ReadFile(StringView file_name) {
  StringBuilder file_path;
  file_path.Append(test::BlinkWebTestsDir());
  file_path.Append(file_name);
  std::optional<Vector<char>> data = test::ReadFromFile(file_path.ToString());
  CHECK(data && data->size());
  return *data;
}

Vector<char> ReadFile(const char* dir, const char* file_name) {
  StringBuilder file_path;
  if (strncmp(dir, "web_tests/", 10) == 0) {
    file_path.Append(test::BlinkWebTestsDir());
    file_path.Append('/');
    file_path.Append(dir + 10);
  } else {
    file_path.Append(test::BlinkRootDir());
    file_path.Append('/');
    file_path.Append(dir);
  }
  file_path.Append('/');
  file_path.Append(file_name);
  std::optional<Vector<char>> data = test::ReadFromFile(file_path.ToString());
  CHECK(data && data->size());
  return *data;
}

scoped_refptr<SharedBuffer> ReadFileToSharedBuffer(StringView file_name) {
  return SharedBuffer::Create(ReadFile(file_name));
}

scoped_refptr<SharedBuffer> ReadFileToSharedBuffer(const char* dir,
                                                   const char* file_name) {
  return SharedBuffer::Create(ReadFile(dir, file_name));
}

unsigned HashBitmap(const SkBitmap& bitmap) {
  return StringHasher::HashMemory(
      {static_cast<const uint8_t*>(bitmap.getPixels()),
       bitmap.computeByteSize()});
}

void CreateDecodingBaseline(DecoderCreator create_decoder,
                            SharedBuffer* data,
                            Vector<unsigned>* baseline_hashes) {
  std::unique_ptr<ImageDecoder> decoder = create_decoder();
  decoder->SetData(data, true);
  size_t frame_count = decoder->FrameCount();
  for (size_t i = 0; i < frame_count; ++i) {
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(i);
    baseline_hashes->push_back(HashBitmap(frame->Bitmap()));
  }
}

void TestByteByByteDecode(DecoderCreator create_decoder,
                          SharedBuffer* shared_data,
                          size_t expected_frame_count,
                          int expected_repetition_count) {
  const Vector<char> data = shared_data->CopyAs<Vector<char>>();

  Vector<unsigned> baseline_hashes;
  CreateDecodingBaseline(create_decoder, shared_data, &baseline_hashes);

  std::unique_ptr<ImageDecoder> decoder = create_decoder();

  size_t frame_count = 0;
  size_t frames_decoded = 0;

  // Pass data to decoder byte by byte.
  scoped_refptr<SharedBuffer> source_data[2] = {SharedBuffer::Create(),
                                                SharedBuffer::Create()};
  const char* source = data.data();

  for (size_t length = 1; length <= data.size() && !decoder->Failed();
       ++length) {
    source_data[0]->Append(source, 1u);
    source_data[1]->Append(source++, 1u);
    // Alternate the buffers to cover the JPEGImageDecoder::OnSetData restart
    // code.
    decoder->SetData(source_data[length & 1].get(), length == data.size());

    EXPECT_LE(frame_count, decoder->FrameCount());
    frame_count = decoder->FrameCount();

    if (!decoder->IsSizeAvailable()) {
      continue;
    }

    for (size_t i = frames_decoded; i < frame_count; ++i) {
      // In ICOImageDecoder memory layout could differ from frame order.
      // E.g. memory layout could be |<frame1><frame0>| and frame_count
      // would return 1 until receiving full file.
      // When file is completely received frame_count would return 2 and
      // only then both frames could be completely decoded.
      ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(i);
      if (frame && frame->GetStatus() == ImageFrame::kFrameComplete) {
        EXPECT_EQ(baseline_hashes[i], HashBitmap(frame->Bitmap()));
        ++frames_decoded;
      }
    }
  }

  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(expected_frame_count, decoder->FrameCount());
  EXPECT_EQ(expected_frame_count, frames_decoded);
  EXPECT_EQ(expected_repetition_count, decoder->RepetitionCount());

  ASSERT_EQ(expected_frame_count, baseline_hashes.size());
  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(i);
    EXPECT_EQ(baseline_hashes[i], HashBitmap(frame->Bitmap()));
  }
}

static void TestRandomFrameDecode(DecoderCreator create_decoder,
                                  SharedBuffer* full_data,
                                  size_t skipping_step) {
  Vector<unsigned> baseline_hashes;
  CreateDecodingBaseline(create_decoder, full_data, &baseline_hashes);
  size_t frame_count = baseline_hashes.size();

  // Random decoding should get the same results as sequential decoding.
  std::unique_ptr<ImageDecoder> decoder = create_decoder();
  decoder->SetData(full_data, true);
  for (size_t i = 0; i < skipping_step; ++i) {
    for (size_t j = i; j < frame_count; j += skipping_step) {
      SCOPED_TRACE(testing::Message() << "Random i:" << i << " j:" << j);
      ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(j);
      EXPECT_EQ(baseline_hashes[j], HashBitmap(frame->Bitmap()));
    }
  }

  // Decoding in reverse order.
  decoder = create_decoder();
  decoder->SetData(full_data, true);
  for (size_t i = frame_count; i; --i) {
    SCOPED_TRACE(testing::Message() << "Reverse i:" << i);
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(i - 1);
    EXPECT_EQ(baseline_hashes[i - 1], HashBitmap(frame->Bitmap()));
  }
}

static void TestRandomDecodeAfterClearFrameBufferCache(
    DecoderCreator create_decoder,
    SharedBuffer* data,
    size_t skipping_step) {
  Vector<unsigned> baseline_hashes;
  CreateDecodingBaseline(create_decoder, data, &baseline_hashes);
  size_t frame_count = baseline_hashes.size();

  std::unique_ptr<ImageDecoder> decoder = create_decoder();
  decoder->SetData(data, true);
  for (size_t clear_except_frame = 0; clear_except_frame < frame_count;
       ++clear_except_frame) {
    decoder->ClearCacheExceptFrame(clear_except_frame);
    for (size_t i = 0; i < skipping_step; ++i) {
      for (size_t j = 0; j < frame_count; j += skipping_step) {
        SCOPED_TRACE(testing::Message() << "Random i:" << i << " j:" << j);
        ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(j);
        EXPECT_EQ(baseline_hashes[j], HashBitmap(frame->Bitmap()));
      }
    }
  }
}

static void TestDecodeAfterReallocatingData(DecoderCreator create_decoder,
                                            SharedBuffer* data) {
  std::unique_ptr<ImageDecoder> decoder = create_decoder();

  // Parse from 'data'.
  decoder->SetData(data, true);
  size_t frame_count = decoder->FrameCount();

  // ... and then decode frames from 'reallocated_data'.
  Vector<char> copy = data->CopyAs<Vector<char>>();
  scoped_refptr<SharedBuffer> reallocated_data =
      SharedBuffer::Create(std::move(copy));
  ASSERT_TRUE(reallocated_data.get());
  data->Clear();
  decoder->SetData(reallocated_data.get(), true);

  for (size_t i = 0; i < frame_count; ++i) {
    const ImageFrame* const frame = decoder->DecodeFrameBufferAtIndex(i);
    EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  }
}

static void TestByteByByteSizeAvailable(DecoderCreator create_decoder,
                                        SharedBuffer* data,
                                        size_t frame_offset,
                                        bool has_color_space,
                                        int expected_repetition_count) {
  std::unique_ptr<ImageDecoder> decoder = create_decoder();
  EXPECT_LT(frame_offset, data->size());

  // Send data to the decoder byte-by-byte and use the provided frame offset in
  // the data to check that IsSizeAvailable() changes state only when that
  // offset is reached. Also check other decoder state.
  scoped_refptr<SharedBuffer> temp_data = SharedBuffer::Create();
  const Vector<char> source_buffer = data->CopyAs<Vector<char>>();
  const char* source = source_buffer.data();
  for (size_t length = 1; length <= frame_offset; ++length) {
    temp_data->Append(source++, 1u);
    decoder->SetData(temp_data.get(), false);

    if (length < frame_offset) {
      EXPECT_FALSE(decoder->IsSizeAvailable());
      EXPECT_TRUE(decoder->Size().IsEmpty());
      EXPECT_FALSE(decoder->HasEmbeddedColorProfile());
      EXPECT_EQ(0u, decoder->FrameCount());
      EXPECT_EQ(kAnimationLoopOnce, decoder->RepetitionCount());
      EXPECT_FALSE(decoder->DecodeFrameBufferAtIndex(0));
    } else {
      EXPECT_TRUE(decoder->IsSizeAvailable());
      EXPECT_FALSE(decoder->Size().IsEmpty());
      EXPECT_EQ(decoder->HasEmbeddedColorProfile(), has_color_space);
      EXPECT_EQ(1u, decoder->FrameCount());
      EXPECT_EQ(expected_repetition_count, decoder->RepetitionCount());
    }

    ASSERT_FALSE(decoder->Failed());
  }
}

static void TestProgressiveDecoding(DecoderCreator create_decoder,
                                    SharedBuffer* full_buffer,
                                    size_t increment) {
  const Vector<char> full_data = full_buffer->CopyAs<Vector<char>>();
  const size_t full_length = full_data.size();

  std::unique_ptr<ImageDecoder> decoder;

  Vector<unsigned> truncated_hashes;
  Vector<unsigned> progressive_hashes;

  // Compute hashes when the file is truncated.
  scoped_refptr<SharedBuffer> data = SharedBuffer::Create();
  const char* source = full_data.data();
  for (size_t i = 1; i <= full_length; i += increment) {
    decoder = create_decoder();
    data->Append(source++, 1u);
    decoder->SetData(data.get(), i == full_length);
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
    if (!frame) {
      truncated_hashes.push_back(0);
      continue;
    }
    truncated_hashes.push_back(HashBitmap(frame->Bitmap()));
  }

  // Compute hashes when the file is progressively decoded.
  decoder = create_decoder();
  data = SharedBuffer::Create();
  source = full_data.data();
  for (size_t i = 1; i <= full_length; i += increment) {
    data->Append(source++, 1u);
    decoder->SetData(data.get(), i == full_length);
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
    if (!frame) {
      progressive_hashes.push_back(0);
      continue;
    }
    progressive_hashes.push_back(HashBitmap(frame->Bitmap()));
  }

  for (size_t i = 0; i < truncated_hashes.size(); ++i) {
    ASSERT_EQ(truncated_hashes[i], progressive_hashes[i]);
  }
}

void TestUpdateRequiredPreviousFrameAfterFirstDecode(
    DecoderCreator create_decoder,
    SharedBuffer* full_buffer) {
  const Vector<char> full_data = full_buffer->CopyAs<Vector<char>>();
  std::unique_ptr<ImageDecoder> decoder = create_decoder();

  // Give it data that is enough to parse but not decode in order to check the
  // status of RequiredPreviousFrameIndex before decoding.
  scoped_refptr<SharedBuffer> data = SharedBuffer::Create();
  const char* source = full_data.data();
  do {
    data->Append(source++, 1u);
    decoder->SetData(data.get(), false);
  } while (!decoder->FrameCount() ||
           decoder->DecodeFrameBufferAtIndex(0)->GetStatus() ==
               ImageFrame::kFrameEmpty);

  EXPECT_EQ(kNotFound,
            decoder->DecodeFrameBufferAtIndex(0)->RequiredPreviousFrameIndex());
  unsigned frame_count = decoder->FrameCount();
  for (size_t i = 1; i < frame_count; ++i) {
    EXPECT_EQ(
        i - 1,
        decoder->DecodeFrameBufferAtIndex(i)->RequiredPreviousFrameIndex());
  }

  decoder->SetData(full_buffer, true);
  for (size_t i = 0; i < frame_count; ++i) {
    EXPECT_EQ(
        kNotFound,
        decoder->DecodeFrameBufferAtIndex(i)->RequiredPreviousFrameIndex());
  }
}

void TestByteByByteDecode(DecoderCreator create_decoder,
                          const char* file,
                          size_t expected_frame_count,
                          int expected_repetition_count) {
  SCOPED_TRACE(file);
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());
  TestByteByByteDecode(create_decoder, data.get(), expected_frame_count,
                       expected_repetition_count);
}
void TestByteByByteDecode(DecoderCreator create_decoder,
                          const char* dir,
                          const char* file,
                          size_t expected_frame_count,
                          int expected_repetition_count) {
  SCOPED_TRACE(file);
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  TestByteByByteDecode(create_decoder, data.get(), expected_frame_count,
                       expected_repetition_count);
}

void TestRandomFrameDecode(DecoderCreator create_decoder,
                           const char* file,
                           size_t skipping_step) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());
  SCOPED_TRACE(file);
  TestRandomFrameDecode(create_decoder, data.get(), skipping_step);
}
void TestRandomFrameDecode(DecoderCreator create_decoder,
                           const char* dir,
                           const char* file,
                           size_t skipping_step) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  SCOPED_TRACE(file);
  TestRandomFrameDecode(create_decoder, data.get(), skipping_step);
}

void TestRandomDecodeAfterClearFrameBufferCache(DecoderCreator create_decoder,
                                                const char* file,
                                                size_t skipping_step) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());
  SCOPED_TRACE(file);
  TestRandomDecodeAfterClearFrameBufferCache(create_decoder, data.get(),
                                             skipping_step);
}

void TestRandomDecodeAfterClearFrameBufferCache(DecoderCreator create_decoder,
                                                const char* dir,
                                                const char* file,
                                                size_t skipping_step) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  SCOPED_TRACE(file);
  TestRandomDecodeAfterClearFrameBufferCache(create_decoder, data.get(),
                                             skipping_step);
}

void TestDecodeAfterReallocatingData(DecoderCreator create_decoder,
                                     const char* file) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());
  TestDecodeAfterReallocatingData(create_decoder, data.get());
}

void TestDecodeAfterReallocatingData(DecoderCreator create_decoder,
                                     const char* dir,
                                     const char* file) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  TestDecodeAfterReallocatingData(create_decoder, data.get());
}

void TestByteByByteSizeAvailable(DecoderCreator create_decoder,
                                 const char* file,
                                 size_t frame_offset,
                                 bool has_color_space,
                                 int expected_repetition_count) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());
  TestByteByByteSizeAvailable(create_decoder, data.get(), frame_offset,
                              has_color_space, expected_repetition_count);
}

void TestByteByByteSizeAvailable(DecoderCreator create_decoder,
                                 const char* dir,
                                 const char* file,
                                 size_t frame_offset,
                                 bool has_color_space,
                                 int expected_repetition_count) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  TestByteByByteSizeAvailable(create_decoder, data.get(), frame_offset,
                              has_color_space, expected_repetition_count);
}

void TestProgressiveDecoding(DecoderCreator create_decoder,
                             const char* file,
                             size_t increment) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());
  TestProgressiveDecoding(create_decoder, data.get(), increment);
}

void TestProgressiveDecoding(DecoderCreator create_decoder,
                             const char* dir,
                             const char* file,
                             size_t increment) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  TestProgressiveDecoding(create_decoder, data.get(), increment);
}

void TestUpdateRequiredPreviousFrameAfterFirstDecode(
    DecoderCreator create_decoder,
    const char* dir,
    const char* file) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  TestUpdateRequiredPreviousFrameAfterFirstDecode(create_decoder, data.get());
}

void TestUpdateRequiredPreviousFrameAfterFirstDecode(
    DecoderCreator create_decoder,
    const char* file) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());
  TestUpdateRequiredPreviousFrameAfterFirstDecode(create_decoder, data.get());
}

static uint32_t PremultiplyColor(uint32_t c) {
  return SkPremultiplyARGBInline(SkGetPackedA32(c), SkGetPackedR32(c),
                                 SkGetPackedG32(c), SkGetPackedB32(c));
}

static void VerifyFramesMatch(const char* file,
                              const ImageFrame* const a,
                              const ImageFrame* const b) {
  const SkBitmap& bitmap_a = a->Bitmap();
  const SkBitmap& bitmap_b = b->Bitmap();
  ASSERT_EQ(bitmap_a.width(), bitmap_b.width());
  ASSERT_EQ(bitmap_a.height(), bitmap_b.height());

  int max_difference = 0;
  for (int y = 0; y < bitmap_a.height(); ++y) {
    for (int x = 0; x < bitmap_a.width(); ++x) {
      uint32_t color_a = *bitmap_a.getAddr32(x, y);
      if (!a->PremultiplyAlpha()) {
        color_a = PremultiplyColor(color_a);
      }
      uint32_t color_b = *bitmap_b.getAddr32(x, y);
      if (!b->PremultiplyAlpha()) {
        color_b = PremultiplyColor(color_b);
      }
      uint8_t* pixel_a = reinterpret_cast<uint8_t*>(&color_a);
      uint8_t* pixel_b = reinterpret_cast<uint8_t*>(&color_b);
      for (int channel = 0; channel < 4; ++channel) {
        const int difference = abs(pixel_a[channel] - pixel_b[channel]);
        if (difference > max_difference) {
          max_difference = difference;
        }
      }
    }
  }

  // Pre-multiplication could round the RGBA channel values. So, we declare
  // that the frames match if the RGBA channel values differ by at most 2.
  EXPECT_GE(2, max_difference) << file;
}

// Verifies that result of alpha blending is similar for AlphaPremultiplied and
// AlphaNotPremultiplied cases.
void TestAlphaBlending(DecoderCreatorWithAlpha create_decoder,
                       const char* file) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(file);
  ASSERT_TRUE(data.get());

  std::unique_ptr<ImageDecoder> decoder_a =
      create_decoder(ImageDecoder::kAlphaPremultiplied);
  decoder_a->SetData(data.get(), true);

  std::unique_ptr<ImageDecoder> decoder_b =
      create_decoder(ImageDecoder::kAlphaNotPremultiplied);
  decoder_b->SetData(data.get(), true);

  size_t frame_count = decoder_a->FrameCount();
  ASSERT_EQ(frame_count, decoder_b->FrameCount());

  for (size_t i = 0; i < frame_count; ++i) {
    VerifyFramesMatch(file, decoder_a->DecodeFrameBufferAtIndex(i),
                      decoder_b->DecodeFrameBufferAtIndex(i));
  }
}

void TestBppHistogram(DecoderCreator create_decoder,
                      const char* image_type,
                      const char* image_name,
                      const char* histogram_name,
                      base::HistogramBase::Sample sample) {
  base::HistogramTester histogram_tester;
  std::unique_ptr<ImageDecoder> decoder = create_decoder();
  decoder->SetData(ReadFileToSharedBuffer(image_name), true);
  ASSERT_TRUE(decoder->IsSizeAvailable());
  if (histogram_name) {
    histogram_tester.ExpectTotalCount(histogram_name, 0);
  }
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_FALSE(decoder->Failed());
  base::HistogramTester::CountsMap expected_counts;
  if (histogram_name) {
    histogram_tester.ExpectUniqueSample(histogram_name, sample, 1);
    expected_counts[histogram_name] = 1;
  }
  EXPECT_THAT(histogram_tester.GetTotalCountsForPrefix(base::StrCat(
                  {"Blink.DecodedImage.", image_type, "Density.Count."})),
              testing::ContainerEq(expected_counts));
}

}  // namespace blink

"""

```