Response:
The user wants to understand the functionality of the `gif_image_decoder_test.cc` file in the Chromium Blink engine. I need to analyze the code and provide a summary of its purpose. The request also asks for connections to JavaScript, HTML, and CSS, examples with assumptions and outputs, and common usage errors.

**Plan:**

1. **High-level purpose:** Identify that this is a test file for the `GIFImageDecoder` class. Its main goal is to ensure the decoder functions correctly under various scenarios.
2. **Specific functionalities:** Go through each test case (`TEST`) and describe what it's testing. This will reveal the decoder's capabilities being verified.
3. **Relationship to web technologies:** Determine how the tested functionalities relate to how GIFs are used on the web (JavaScript manipulation, embedding in HTML, CSS styling).
4. **Logical reasoning (if any):** Look for tests that involve specific input data and expected output.
5. **Common usage errors:**  Infer potential errors based on the tested failure scenarios (e.g., broken GIFs, invalid data).
这个文件 `gif_image_decoder_test.cc` 是 Chromium Blink 引擎中用于测试 `GIFImageDecoder` 类的单元测试文件。它的主要功能是：

**1. 测试 GIF 图片解码器的各种功能和边界情况：**

   这个文件包含了大量的测试用例，每个用例都针对 `GIFImageDecoder` 的特定功能或潜在问题进行测试。  通过构造不同的 GIF 图片数据，并调用 `GIFImageDecoder` 的方法，然后断言其行为是否符合预期，来保证 GIF 解码器的正确性。

**以下是根据代码中的测试用例列举的一些主要测试功能：**

*   **基本的帧解码：**
    *   `decodeTwoFrames`: 测试解码包含两帧动画的 GIF 图片。验证解码后的帧数、每一帧的尺寸、以及动画是否循环播放。
    *   `parseAndDecode`: 测试完整解析和解码 GIF 图片，验证帧数和每一帧的尺寸。
    *   `parseByteByByte`:  测试逐字节地向解码器提供数据，模拟网络加载过程，验证在数据逐步加载的情况下，解码器能否正确解析和解码。
    *   `parseAndDecodeByteByByte`:  使用辅助函数 `TestByteByByteDecode` 进行更全面的逐字节解码测试。
*   **处理错误和异常情况：**
    *   `brokenSecondFrame`: 测试解码包含错误帧的 GIF 图片，验证解码器能否正确处理并标记错误。
    *   `badTerminator`: 测试处理带有错误终止符的 GIF 图片。
    *   `badInitialCode`: 测试处理包含无效的 LZW 初始代码的 GIF 图片，验证解码器是否会失败，但不会无限循环或损坏内存。
    *   `badCode`: 测试处理包含超出字典大小的无效 LZW 代码的 GIF 图片，验证解码器是否会失败。
    *   `invalidDisposalMethod`: 测试处理包含无效处置方法的 GIF 图片，验证解码器如何处理这些情况。
    *   `recursiveDecodeFailure`: 测试在解码依赖于前面错误帧的帧时，解码器的行为。
    *   `errorFrame`: 测试处理包含已知错误帧的 GIF 图片。
*   **渐进式解码：**
    *   `progressiveDecode`: 使用辅助函数 `TestProgressiveDecoding` 测试渐进式解码功能，即在数据未完全加载时能否解码出部分图像。
*   **数据截断处理：**
    *   `allDataReceivedTruncation`: 测试当接收到的数据被截断时，解码器的行为。
*   **帧状态检查：**
    *   `frameIsComplete`: 测试在完整数据加载后，解码器是否正确标记所有帧为已接收。
    *   `frameIsCompleteLoading`: 测试在数据加载过程中，解码器是否正确标记已接收和未接收的帧。
*   **帧缓存管理：**
    *   `updateRequiredPreviousFrameAfterFirstDecode`: 使用辅助函数 `TestUpdateRequiredPreviousFrameAfterFirstDecode` 测试首次解码后是否需要更新前一帧。
    *   `randomFrameDecode`: 使用辅助函数 `TestRandomFrameDecode` 测试随机解码特定帧的功能。
    *   `randomDecodeAfterClearFrameBufferCache`: 使用辅助函数 `TestRandomDecodeAfterClearFrameBufferCache` 测试在清除帧缓冲区缓存后随机解码的功能。
*   **动画循环次数：**
    *   `verifyRepetitionCount`: 测试解码器能否正确读取 GIF 图片中的循环次数信息。
    *   `repetitionCountChangesWhenSeen`: 测试当接收到包含循环次数信息的数据时，解码器是否能更新循环次数。
*   **位图属性：**
    *   `bitmapAlphaType`: 测试解码出的位图的 Alpha 类型是否正确，特别是针对部分解码和完全解码的情况。
*   **内存分配：**
    *   `externalAllocator`: 测试使用外部内存分配器是否影响解码器的功能。

**2. 与 JavaScript, HTML, CSS 的关系举例说明：**

   `GIFImageDecoder` 的主要作用是解码 GIF 图片，以便浏览器能够将其渲染到网页上。它直接影响着用户在网页上看到的 GIF 动画效果。

*   **HTML `<img>` 标签：**  当 HTML 中使用 `<img>` 标签加载 GIF 图片时，浏览器会调用 `GIFImageDecoder` 来解析和解码图片数据，最终将解码后的图像数据绘制到屏幕上。例如：

    ```html
    <img src="animated.gif">
    ```
    在这个例子中，`GIFImageDecoder` 负责解码 `animated.gif`，使得浏览器可以显示动画。

*   **CSS `background-image` 属性：**  CSS 可以使用 `background-image` 属性来设置 GIF 图片作为元素的背景。浏览器同样会使用 `GIFImageDecoder` 来解码这些背景 GIF 图片。例如：

    ```css
    .my-element {
      background-image: url("animated.gif");
    }
    ```
    `GIFImageDecoder` 会解码 `animated.gif`，使其能够作为 `.my-element` 的背景动画显示。

*   **JavaScript 操作 `<img>` 元素：** JavaScript 可以动态创建或修改 `<img>` 标签的 `src` 属性，从而加载新的 GIF 图片。浏览器在加载新的 GIF 图片时，会再次调用 `GIFImageDecoder` 进行解码。  此外，JavaScript 还可以通过监听 `load` 和 `error` 事件来处理 GIF 图片加载成功或失败的情况，这与 `GIFImageDecoder` 的解码结果直接相关。例如：

    ```javascript
    const img = new Image();
    img.onload = function() {
      console.log("GIF 图片加载成功");
    };
    img.onerror = function() {
      console.log("GIF 图片加载失败");
    };
    img.src = "animated.gif";
    document.body.appendChild(img);
    ```
    如果 `GIFImageDecoder` 在解码 `animated.gif` 时遇到错误，`onerror` 事件可能会被触发。

**3. 逻辑推理的假设输入与输出举例：**

   以 `decodeTwoFrames` 测试用例为例：

   *   **假设输入：** 一个名为 `animated.gif` 的 GIF 图片文件，该文件包含两个 16x16 像素的帧，并且动画循环播放。
   *   **逻辑推理：**  测试代码首先创建了一个 `GIFImageDecoder` 实例，然后读取 `animated.gif` 的数据并提供给解码器。接着，它分别调用 `DecodeFrameBufferAtIndex(0)` 和 `DecodeFrameBufferAtIndex(1)` 来解码第一帧和第二帧。
   *   **预期输出：**
        *   解码第一帧后，`frame->GetStatus()` 应该等于 `ImageFrame::kFrameComplete`，表示解码成功。
        *   第一帧的宽度 `frame->Bitmap().width()` 应该等于 16。
        *   第一帧的高度 `frame->Bitmap().height()` 应该等于 16。
        *   解码第二帧后，`frame->GetStatus()` 应该等于 `ImageFrame::kFrameComplete`。
        *   第二帧的宽度和高度也应该都是 16。
        *   第一帧和第二帧的 `generation_id` 应该不同，表明它们是不同的位图。
        *   `decoder->FrameCount()` 应该等于 2，表示识别出两帧。
        *   `decoder->RepetitionCount()` 应该等于 `kAnimationLoopInfinite`，表示动画无限循环。

**4. 用户或者编程常见的使用错误举例说明：**

*   **提供不完整的 GIF 数据：**  如果程序在网络传输过程中提前结束，只提供了部分 GIF 数据给 `GIFImageDecoder`，解码器可能会报告错误或者只能解码出部分帧。例如，在 `allDataReceivedTruncation` 测试用例中，故意截断了 GIF 数据，虽然解码器仍然报告了正确的帧数，但实际解码帧可能会有问题。
*   **使用错误的 GIF 文件路径或文件名：**  在读取 GIF 文件时，如果路径或文件名错误，会导致无法读取文件，从而无法进行解码。测试代码中使用了 `ReadFileToSharedBuffer` 函数，如果该函数返回空指针，就会导致 `ASSERT_TRUE(data.get())` 失败，表明文件读取失败。
*   **假设 GIF 图片格式总是正确的：**  在处理用户上传的 GIF 图片时，可能会遇到格式错误或损坏的图片。例如，`brokenSecondFrame`、`badTerminator` 等测试用例模拟了这些错误情况。如果程序没有妥善处理解码错误，可能会导致程序崩溃或显示异常。
*   **没有处理动画循环次数：**  在某些场景下，开发者可能需要知道 GIF 动画的循环次数。如果没有正确调用 `decoder->RepetitionCount()` 获取并处理这个信息，可能会导致动画播放行为不符合预期。
*   **内存管理错误：** 虽然 `GIFImageDecoder` 内部会进行内存管理，但在一些高级用法中（例如使用外部内存分配器），如果开发者对内存管理不当，可能会导致内存泄漏或程序崩溃。`externalAllocator` 测试用例就是为了验证在这种情况下解码器是否仍然正常工作。

总而言之，`gif_image_decoder_test.cc` 是一个至关重要的测试文件，它确保了 Chromium 浏览器能够正确可靠地解码各种 GIF 图片，从而保证用户在浏览网页时能够正常观看 GIF 动画。 这些测试覆盖了 GIF 解码的各种场景，包括正常情况、错误情况和边界情况，对于保证浏览器的稳定性和用户体验至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/gif/gif_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/gif/gif_image_decoder.h"

#include <memory>
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

const char kWebTestsResourcesDir[] = "web_tests/images/resources";

std::unique_ptr<ImageDecoder> CreateDecoder() {
  return std::make_unique<GIFImageDecoder>(
      ImageDecoder::kAlphaNotPremultiplied, ColorBehavior::kTransformToSRGB,
      ImageDecoder::kNoDecodedImageByteLimit);
}

void TestRepetitionCount(const char* dir,
                         const char* file,
                         int expected_repetition_count) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(dir, file);
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);
  EXPECT_EQ(expected_repetition_count, decoder->RepetitionCount());
}

}  // anonymous namespace

TEST(GIFImageDecoderTest, decodeTwoFrames) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer(kWebTestsResourcesDir, "animated.gif");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  uint32_t generation_id0 = frame->Bitmap().getGenerationID();
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_EQ(16, frame->Bitmap().width());
  EXPECT_EQ(16, frame->Bitmap().height());

  frame = decoder->DecodeFrameBufferAtIndex(1);
  uint32_t generation_id1 = frame->Bitmap().getGenerationID();
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_EQ(16, frame->Bitmap().width());
  EXPECT_EQ(16, frame->Bitmap().height());
  EXPECT_TRUE(generation_id0 != generation_id1);

  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(GIFImageDecoderTest, crbug779261) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();
  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer(kWebTestsResourcesDir, "crbug779261.gif");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  for (size_t i = 0; i < decoder->FrameCount(); ++i) {
    // In crbug.com/779261, an independent, transparent frame following an
    // opaque frame failed to decode. This image has an opaque frame 0 with
    // DisposalMethod::kDisposeOverwriteBgcolor, making frame 1, which has
    // transparency, independent and contain alpha.
    const bool has_alpha = 0 == i ? false : true;
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(i);
    EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
    EXPECT_EQ(has_alpha, frame->HasAlpha());
  }

  EXPECT_FALSE(decoder->Failed());
}

TEST(GIFImageDecoderTest, parseAndDecode) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer(kWebTestsResourcesDir, "animated.gif");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  // This call will parse the entire file.
  EXPECT_EQ(2u, decoder->FrameCount());

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_EQ(16, frame->Bitmap().width());
  EXPECT_EQ(16, frame->Bitmap().height());

  frame = decoder->DecodeFrameBufferAtIndex(1);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_EQ(16, frame->Bitmap().width());
  EXPECT_EQ(16, frame->Bitmap().height());
  EXPECT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(GIFImageDecoderTest, parseByteByByte) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  const Vector<char> data = ReadFile(kWebTestsResourcesDir, "animated.gif");

  size_t frame_count = 0;

  // Pass data to decoder byte by byte.
  for (size_t length = 1; length <= data.size(); ++length) {
    scoped_refptr<SharedBuffer> temp_data =
        SharedBuffer::Create(data.data(), length);
    decoder->SetData(temp_data.get(), length == data.size());

    EXPECT_LE(frame_count, decoder->FrameCount());
    frame_count = decoder->FrameCount();
  }

  EXPECT_EQ(2u, decoder->FrameCount());

  decoder->DecodeFrameBufferAtIndex(0);
  decoder->DecodeFrameBufferAtIndex(1);
  EXPECT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(GIFImageDecoderTest, parseAndDecodeByteByByte) {
  TestByteByByteDecode(&CreateDecoder, kWebTestsResourcesDir,
                       "animated-gif-with-offsets.gif", 5u,
                       kAnimationLoopInfinite);
}

TEST(GIFImageDecoderTest, brokenSecondFrame) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "broken.gif");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  // One frame is detected but cannot be decoded.
  EXPECT_EQ(1u, decoder->FrameCount());
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(1);
  EXPECT_FALSE(frame);
}

TEST(GIFImageDecoderTest, progressiveDecode) {
  TestProgressiveDecoding(&CreateDecoder, kDecodersTestingDir, "radient.gif");
}

TEST(GIFImageDecoderTest, allDataReceivedTruncation) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  const Vector<char> data = ReadFile(kWebTestsResourcesDir, "animated.gif");

  ASSERT_GE(data.size(), 10u);
  scoped_refptr<SharedBuffer> temp_data =
      SharedBuffer::Create(data.data(), data.size() - 10);
  decoder->SetData(temp_data.get(), true);

  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());

  decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_FALSE(decoder->Failed());
  decoder->DecodeFrameBufferAtIndex(1);
  EXPECT_FALSE(decoder->Failed());
}

TEST(GIFImageDecoderTest, frameIsComplete) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer(kWebTestsResourcesDir, "animated.gif");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(0));
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(1));
  EXPECT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(GIFImageDecoderTest, frameIsCompleteLoading) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  const Vector<char> data = ReadFile(kWebTestsResourcesDir, "animated.gif");
  scoped_refptr<SharedBuffer> data_buffer = SharedBuffer::Create(data);

  ASSERT_GE(data.size(), 10u);
  scoped_refptr<SharedBuffer> temp_data =
      SharedBuffer::Create(data.data(), data.size() - 10);
  decoder->SetData(temp_data.get(), false);

  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(0));
  EXPECT_FALSE(decoder->FrameIsReceivedAtIndex(1));

  decoder->SetData(data_buffer.get(), true);
  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(0));
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(1));
}

TEST(GIFImageDecoderTest, badTerminator) {
  scoped_refptr<SharedBuffer> reference_data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "radient.gif");
  scoped_refptr<SharedBuffer> test_data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "radient-bad-terminator.gif");
  ASSERT_TRUE(reference_data.get());
  ASSERT_TRUE(test_data.get());

  std::unique_ptr<ImageDecoder> reference_decoder = CreateDecoder();
  reference_decoder->SetData(reference_data.get(), true);
  EXPECT_EQ(1u, reference_decoder->FrameCount());
  ImageFrame* reference_frame = reference_decoder->DecodeFrameBufferAtIndex(0);
  DCHECK(reference_frame);

  std::unique_ptr<ImageDecoder> test_decoder = CreateDecoder();
  test_decoder->SetData(test_data.get(), true);
  EXPECT_EQ(1u, test_decoder->FrameCount());
  ImageFrame* test_frame = test_decoder->DecodeFrameBufferAtIndex(0);
  DCHECK(test_frame);

  EXPECT_EQ(HashBitmap(reference_frame->Bitmap()),
            HashBitmap(test_frame->Bitmap()));
}

TEST(GIFImageDecoderTest, updateRequiredPreviousFrameAfterFirstDecode) {
  TestUpdateRequiredPreviousFrameAfterFirstDecode(
      &CreateDecoder, kWebTestsResourcesDir, "animated-10color.gif");
}

TEST(GIFImageDecoderTest, randomFrameDecode) {
  // Single frame image.
  TestRandomFrameDecode(&CreateDecoder, kDecodersTestingDir, "radient.gif");
  // Multiple frame images.
  TestRandomFrameDecode(&CreateDecoder, kWebTestsResourcesDir,
                        "animated-gif-with-offsets.gif");
  TestRandomFrameDecode(&CreateDecoder, kWebTestsResourcesDir,
                        "animated-10color.gif");
}

TEST(GIFImageDecoderTest, randomDecodeAfterClearFrameBufferCache) {
  // Single frame image.
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreateDecoder, kDecodersTestingDir, "radient.gif");
  // Multiple frame images.
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreateDecoder, kWebTestsResourcesDir, "animated-gif-with-offsets.gif");
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreateDecoder, kWebTestsResourcesDir, "animated-10color.gif");
}

// The first LZW codes in the image are invalid values that try to create a loop
// in the dictionary. Decoding should fail, but not infinitely loop or corrupt
// memory.
TEST(GIFImageDecoderTest, badInitialCode) {
  scoped_refptr<SharedBuffer> test_data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "bad-initial-code.gif");
  ASSERT_TRUE(test_data.get());

  std::unique_ptr<ImageDecoder> test_decoder = CreateDecoder();
  test_decoder->SetData(test_data.get(), true);
  EXPECT_EQ(1u, test_decoder->FrameCount());
  ASSERT_TRUE(test_decoder->DecodeFrameBufferAtIndex(0));
  EXPECT_TRUE(test_decoder->Failed());
}

// The image has an invalid LZW code that exceeds dictionary size. Decoding
// should fail.
TEST(GIFImageDecoderTest, badCode) {
  scoped_refptr<SharedBuffer> test_data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "bad-code.gif");
  ASSERT_TRUE(test_data.get());

  std::unique_ptr<ImageDecoder> test_decoder = CreateDecoder();
  test_decoder->SetData(test_data.get(), true);
  EXPECT_EQ(1u, test_decoder->FrameCount());
  ASSERT_TRUE(test_decoder->DecodeFrameBufferAtIndex(0));
  EXPECT_TRUE(test_decoder->Failed());
}

TEST(GIFImageDecoderTest, invalidDisposalMethod) {
  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();

  // The image has 2 frames, with disposal method 4 and 5, respectively.
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(
      kDecodersTestingDir, "invalid-disposal-method.gif");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  EXPECT_EQ(2u, decoder->FrameCount());
  // Disposal method 4 is converted to ImageFrame::DisposeOverwritePrevious.
  // This is because some specs say method 3 is "overwrite previous", while
  // others say setting the third bit (i.e. method 4) is.
  EXPECT_EQ(ImageFrame::kDisposeOverwritePrevious,
            decoder->DecodeFrameBufferAtIndex(0)->GetDisposalMethod());
  // Unknown disposal methods (5 in this case) are converted to
  // ImageFrame::DisposeKeep.
  EXPECT_EQ(ImageFrame::kDisposeKeep,
            decoder->DecodeFrameBufferAtIndex(1)->GetDisposalMethod());
}

TEST(GIFImageDecoderTest, firstFrameHasGreaterSizeThanScreenSize) {
  const Vector<char> full_data = ReadFile(
      kDecodersTestingDir, "first-frame-has-greater-size-than-screen-size.gif");

  std::unique_ptr<ImageDecoder> decoder;
  gfx::Size frame_size;

  // Compute hashes when the file is truncated.
  for (size_t i = 1; i <= full_data.size(); ++i) {
    decoder = CreateDecoder();
    scoped_refptr<SharedBuffer> data =
        SharedBuffer::Create(full_data.data(), i);
    decoder->SetData(data.get(), i == full_data.size());

    if (decoder->IsSizeAvailable() && !frame_size.width() &&
        !frame_size.height()) {
      frame_size = decoder->DecodedSize();
      continue;
    }

    ASSERT_EQ(frame_size.width(), decoder->DecodedSize().width());
    ASSERT_EQ(frame_size.height(), decoder->DecodedSize().height());
  }
}

TEST(GIFImageDecoderTest, verifyRepetitionCount) {
  // full2loop.gif has 3 frames (it is an animated GIF) and an explicit loop
  // count of 2.
  TestRepetitionCount(kWebTestsResourcesDir, "full2loop.gif", 2);
  // radient.gif has 1 frame (it is a still GIF) and no explicit loop count.
  // For still images, either kAnimationLoopInfinite or kAnimationNone are
  // valid and equivalent, in that the pixels on screen do not change over
  // time. It's arbitrary which one we pick: kAnimationLoopInfinite.
  TestRepetitionCount(kDecodersTestingDir, "radient.gif",
                      kAnimationLoopInfinite);
}

TEST(GIFImageDecoderTest, repetitionCountChangesWhenSeen) {
  const Vector<char> full_data =
      ReadFile(kWebTestsResourcesDir, "animated-10color.gif");
  scoped_refptr<SharedBuffer> full_data_buffer =
      SharedBuffer::Create(full_data);

  // This size must be before the repetition count is encountered in the file.
  const size_t kTruncatedSize = 60;
  ASSERT_TRUE(kTruncatedSize < full_data.size());
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(full_data.data(), kTruncatedSize);

  std::unique_ptr<ImageDecoder> decoder = std::make_unique<GIFImageDecoder>(
      ImageDecoder::kAlphaPremultiplied, ColorBehavior::kTransformToSRGB,
      ImageDecoder::kNoDecodedImageByteLimit);

  decoder->SetData(partial_data.get(), false);
  ASSERT_EQ(kAnimationLoopOnce, decoder->RepetitionCount());
  decoder->SetData(full_data_buffer.get(), true);
  ASSERT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(GIFImageDecoderTest, bitmapAlphaType) {
  const Vector<char> full_data = ReadFile(kDecodersTestingDir, "radient.gif");
  scoped_refptr<SharedBuffer> full_data_buffer =
      SharedBuffer::Create(full_data);

  // Empirically chosen truncation size:
  //   a) large enough to produce a partial frame &&
  //   b) small enough to not fully decode the frame
  const size_t kTruncateSize = 800;
  ASSERT_TRUE(kTruncateSize < full_data.size());
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(full_data.data(), kTruncateSize);

  std::unique_ptr<ImageDecoder> premul_decoder =
      std::make_unique<GIFImageDecoder>(ImageDecoder::kAlphaPremultiplied,
                                        ColorBehavior::kTransformToSRGB,
                                        ImageDecoder::kNoDecodedImageByteLimit);
  std::unique_ptr<ImageDecoder> unpremul_decoder =
      std::make_unique<GIFImageDecoder>(ImageDecoder::kAlphaNotPremultiplied,
                                        ColorBehavior::kTransformToSRGB,
                                        ImageDecoder::kNoDecodedImageByteLimit);

  // Partially decoded frame => the frame alpha type is unknown and should
  // reflect the requested format.
  premul_decoder->SetData(partial_data.get(), false);
  ASSERT_TRUE(premul_decoder->FrameCount());
  unpremul_decoder->SetData(partial_data.get(), false);
  ASSERT_TRUE(unpremul_decoder->FrameCount());
  ImageFrame* premul_frame = premul_decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_TRUE(premul_frame &&
              premul_frame->GetStatus() != ImageFrame::kFrameComplete);
  EXPECT_EQ(kPremul_SkAlphaType, premul_frame->Bitmap().alphaType());
  ImageFrame* unpremul_frame = unpremul_decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_TRUE(unpremul_frame &&
              unpremul_frame->GetStatus() != ImageFrame::kFrameComplete);
  EXPECT_EQ(kUnpremul_SkAlphaType, unpremul_frame->Bitmap().alphaType());

  // Fully decoded frame => the frame alpha type is known (opaque).
  premul_decoder->SetData(full_data_buffer.get(), true);
  ASSERT_TRUE(premul_decoder->FrameCount());
  unpremul_decoder->SetData(full_data_buffer.get(), true);
  ASSERT_TRUE(unpremul_decoder->FrameCount());
  premul_frame = premul_decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_TRUE(premul_frame &&
              premul_frame->GetStatus() == ImageFrame::kFrameComplete);
  EXPECT_EQ(kOpaque_SkAlphaType, premul_frame->Bitmap().alphaType());
  unpremul_frame = unpremul_decoder->DecodeFrameBufferAtIndex(0);
  EXPECT_TRUE(unpremul_frame &&
              unpremul_frame->GetStatus() == ImageFrame::kFrameComplete);
  EXPECT_EQ(kOpaque_SkAlphaType, unpremul_frame->Bitmap().alphaType());
}

namespace {
// Needed to exercise ImageDecoder::SetMemoryAllocator, but still does the
// default allocation.
class Allocator final : public SkBitmap::Allocator {
  bool allocPixelRef(SkBitmap* dst) override { return dst->tryAllocPixels(); }
};
}  // namespace

// Ensure that calling SetMemoryAllocator does not short-circuit
// InitializeNewFrame.
TEST(GIFImageDecoderTest, externalAllocator) {
  auto data = ReadFileToSharedBuffer(kWebTestsResourcesDir, "boston.gif");
  ASSERT_TRUE(data.get());

  auto decoder = CreateDecoder();
  decoder->SetData(data.get(), true);

  Allocator allocator;
  decoder->SetMemoryAllocator(&allocator);
  EXPECT_EQ(1u, decoder->FrameCount());
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  decoder->SetMemoryAllocator(nullptr);

  ASSERT_TRUE(frame);
  EXPECT_EQ(gfx::Rect(decoder->Size()), frame->OriginalFrameRect());
  EXPECT_FALSE(frame->HasAlpha());
}

TEST(GIFImageDecoderTest, recursiveDecodeFailure) {
  const Vector<char> data =
      ReadFile(kWebTestsResourcesDir, "count-down-color-test.gif");
  scoped_refptr<SharedBuffer> data_buffer = SharedBuffer::Create(data);

  {
    auto decoder = CreateDecoder();
    decoder->SetData(data_buffer.get(), true);
    for (size_t i = 0; i <= 3; ++i) {
      ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(i);
      ASSERT_NE(frame, nullptr);
      EXPECT_EQ(frame->GetStatus(), ImageFrame::kFrameComplete);
    }
  }

  // Modify data to have an error in frame 2.
  const size_t kErrorOffset = 15302u;
  scoped_refptr<SharedBuffer> modified_data =
      SharedBuffer::Create(data.data(), kErrorOffset);
  modified_data->Append("A", 1u);
  modified_data->Append(data.data() + kErrorOffset + 1,
                        data.size() - kErrorOffset - 1);
  {
    auto decoder = CreateDecoder();
    decoder->SetData(modified_data.get(), true);
    decoder->DecodeFrameBufferAtIndex(2);
    EXPECT_FALSE(decoder->Failed());
  }

  {
    // Decode frame 3, recursively decoding frame 2, which 3 depends on.
    auto decoder = CreateDecoder();
    decoder->SetData(modified_data.get(), true);
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(3);
    EXPECT_FALSE(decoder->Failed());
    ASSERT_NE(frame, nullptr);
    EXPECT_EQ(frame->RequiredPreviousFrameIndex(), 2u);
  }
}

TEST(GIFImageDecoderTest, errorFrame) {
  scoped_refptr<SharedBuffer> test_data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "error_frame.gif");
  ASSERT_TRUE(test_data.get());

  std::unique_ptr<ImageDecoder> decoder = CreateDecoder();
  decoder->SetData(test_data.get(), true);
  wtf_size_t frame_count = decoder->FrameCount();
  EXPECT_EQ(65u, frame_count);
  for (wtf_size_t i = 0; i < frame_count; ++i) {
    decoder->DecodeFrameBufferAtIndex(i);
  }
  EXPECT_FALSE(decoder->Failed());
}

}  // namespace blink

"""

```