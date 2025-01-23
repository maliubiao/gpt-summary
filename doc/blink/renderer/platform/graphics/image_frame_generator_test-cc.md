Response:
The user wants to understand the functionality of the `image_frame_generator_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relation to web technologies like JavaScript, HTML, and CSS, provide examples of logical reasoning (if any), and highlight common usage errors.

**Plan:**

1. **Identify the core functionality:** The file name suggests it's a test file for `ImageFrameGenerator`. I'll examine the test cases to understand what aspects of `ImageFrameGenerator` are being tested.
2. **Relate to web technologies:** I'll look for connections between the tested functionalities and how they relate to displaying images on web pages, which involves JavaScript, HTML (for the `<img>` tag), and CSS (for styling and layout).
3. **Analyze logical reasoning:** If the tests involve specific inputs and expected outputs for the `ImageFrameGenerator`, I'll document these as logical reasoning examples.
4. **Identify potential usage errors:** By understanding the purpose of the tests, I can infer potential mistakes developers might make when using the `ImageFrameGenerator` or related components.
这个文件 `image_frame_generator_test.cc` 是 Chromium Blink 引擎中 `ImageFrameGenerator` 类的单元测试文件。它的主要功能是验证 `ImageFrameGenerator` 类的各种功能是否按预期工作。

以下是它测试的主要功能以及与 JavaScript, HTML, CSS 的关系：

**核心功能:**

1. **图像解码和缩放 (Decoding and Scaling):**
   - 测试 `ImageFrameGenerator::DecodeAndScale` 方法，该方法负责解码图像数据并将其缩放到目标 `SkPixmap`。
   - **与 Web 技术的关系:** 当浏览器加载网页上的 `<img>` 标签或 CSS 背景图片时，Blink 引擎会使用图像解码器来处理图像数据。`ImageFrameGenerator` 负责管理这个解码过程，并根据需要进行缩放以适应不同的显示尺寸。

2. **支持的尺寸 (Supported Sizes):**
   - 测试 `ImageFrameGenerator::GetSupportedDecodeSize` 方法，该方法用于确定给定目标尺寸的最佳解码尺寸。这对于优化内存使用和解码性能很重要。
   - **与 Web 技术的关系:**  当浏览器需要显示一个缩略图或者响应式的图片时，选择合适的解码尺寸可以避免解码过大的图像，从而提高性能。这与 HTML 中的 `srcset` 属性和 CSS 中的 `image-set()` 函数有关。

3. **处理不完整的解码 (Handling Incomplete Decoding):**
   - 测试当图像数据不完整时 `ImageFrameGenerator` 的行为，例如，当下载尚未完成时。
   - **与 Web 技术的关系:** 这直接关系到用户在网络较慢的情况下加载图片时的体验。浏览器需要能够逐步渲染部分下载的图像，而不是等待整个图像下载完成。

4. **低端设备优化 (Low-End Device Optimizations):**
   - 测试在低端设备上，为了节省内存，`ImageFrameGenerator` 如何处理部分解码的图像，例如可能会销毁解码器。
   - **与 Web 技术的关系:** 这关乎在资源受限的设备上如何提供流畅的网页浏览体验。针对低端设备的优化可以避免因解码大量图像而导致的性能问题。

5. **处理解码完成 (Handling Complete Decoding):**
   - 测试当图像数据完全可用时 `ImageFrameGenerator` 的行为。

6. **多线程解码 (Multi-threaded Decoding):**
   - 测试在多线程环境下 `ImageFrameGenerator` 的解码功能。
   - **与 Web 技术的关系:** 浏览器通常会使用多个线程来执行不同的任务，包括图像解码，以提高整体性能。

7. **Alpha 通道 (Alpha Channel):**
   - 测试 `ImageFrameGenerator::HasAlpha` 方法，用于判断图像是否包含 Alpha 通道（透明度）。
   - **与 Web 技术的关系:**  Alpha 通道对于实现图像的透明效果至关重要，这在 HTML `<img>` 标签和 CSS 背景图片中都有广泛应用。例如，PNG 格式的图像常常包含 Alpha 通道。

8. **多帧图像处理 (Multi-frame Image Handling):**
   - 测试 `ImageFrameGenerator` 如何处理多帧图像，例如 GIF 和 Animated WebP。
   - **与 Web 技术的关系:**  这直接关系到动画图片的显示。浏览器需要正确地解码和渲染每一帧动画。

9. **统计信息 (Metrics):**
   - 测试 `ImageFrameGenerator` 是否正确记录了一些性能指标，例如是否有多个客户端请求解码同一个图像。
   - **与 Web 技术的关系:**  这些统计信息可以帮助 Chromium 团队了解图像解码器的使用情况，并进行性能优化。

**逻辑推理示例:**

**假设输入:**

- **图像数据:** 一个部分下载的 PNG 图像的 `SharedBuffer`。
- **目标 `SkPixmap`:**  尺寸为 100x100 的缓冲区。
- **调用:** `generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap, cc::PaintImage::kDefaultGeneratorClientId);`  ( `false` 表示不强制完成解码)

**预期输出:**

- 如果当前测试环境不是低端设备，则 `decode_request_count_` 增加 1，`decoders_destroyed_` 保持为 0，`memory_allocator_set_count_` 保持为 0。
- 如果当前测试环境是低端设备，则 `decode_request_count_` 增加 1，`decoders_destroyed_` 增加 1， `memory_allocator_set_count_` 增加 2（设置和清除外部内存分配器）。
- 图像解码状态为 `ImageFrame::kFramePartial`。

**用户或编程常见的使用错误示例:**

1. **在低端设备上重复解码未完成的图像:**  开发者可能在图像未完全加载时多次调用解码函数，尤其是在低端设备上，这可能导致不必要的解码器创建和销毁，消耗资源。测试用例 `LowEndDeviceDestroysDecoderOnPartialDecode` 验证了这种情况下解码器的行为。

2. **错误地假设解码总是同步完成:** 开发者可能假设 `DecodeAndScale` 调用会立即返回完整的解码图像。然而，在图像数据不完整的情况下，解码可能是异步或分阶段进行的。测试用例 `incompleteDecode` 和 `incompleteDecodeBecomesComplete` 演示了如何处理不完整的解码状态。

3. **没有考虑不同设备的内存限制:**  开发者可能没有意识到在低端设备上需要更加谨慎地处理图像解码，避免一次性解码大量或过大的图像。测试用例 `LowEndDeviceDestroysDecoderOnPartialDecode` 强调了这一点。

4. **没有正确处理多帧图像的解码:** 开发者可能没有考虑到多帧图像需要按帧解码和渲染。测试用例 `clearMultiFrameDecoder` 验证了多帧图像解码过程中的缓存清理行为。

**与 JavaScript, HTML, CSS 的更具体联系:**

- **JavaScript:**  JavaScript 可以通过 `Image` 对象或 `fetch` API 加载图像。加载完成后，Blink 引擎会使用 `ImageFrameGenerator` 来解码图像数据。JavaScript 还可以通过操作 DOM (例如修改 `<img>` 标签的 `src` 属性) 来触发图像加载和解码。
- **HTML:** `<img>` 标签是展示图像的核心 HTML 元素。`ImageFrameGenerator` 负责解码 `<img>` 标签 `src` 属性指向的图像。`srcset` 属性允许浏览器根据屏幕尺寸和像素密度选择合适的图像，`ImageFrameGenerator` 的 `GetSupportedDecodeSize` 方法与之相关。
- **CSS:** CSS 可以通过 `background-image` 属性来设置元素的背景图像。同样，`ImageFrameGenerator` 会参与解码这些背景图像。CSS 的 `image-set()` 函数也允许浏览器根据条件选择不同的图像资源，这与 `GetSupportedDecodeSize` 的功能类似。

总而言之，`image_frame_generator_test.cc` 文件通过一系列单元测试，确保 `ImageFrameGenerator` 能够正确、高效地处理各种图像解码和缩放场景，这对于在 Chromium 中正确渲染网页上的图像至关重要。这些测试覆盖了各种边缘情况和性能考量，保证了用户在不同设备和网络环境下都能获得良好的图像浏览体验。

### 提示词
```
这是目录为blink/renderer/platform/graphics/image_frame_generator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/graphics/image_frame_generator.h"

#include <memory>
#include "base/features.h"
#include "base/location.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/image_decoding_store.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/segment_reader.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// Helper methods to generate standard sizes.
SkISize FullSize() {
  return SkISize::Make(100, 100);
}

SkImageInfo ImageInfo() {
  return SkImageInfo::Make(100, 100, kBGRA_8888_SkColorType,
                           kOpaque_SkAlphaType);
}

}  // namespace

class ImageFrameGeneratorTest : public testing::Test,
                                public MockImageDecoderClient {
 public:
  void SetUp() override {
    ImageDecodingStore::Instance().SetCacheLimitInBytes(1024 * 1024);
    generator_ = ImageFrameGenerator::Create(
        FullSize(), false, ColorBehavior::kIgnore, cc::AuxImage::kDefault, {});
    data_ = SharedBuffer::Create();
    segment_reader_ = SegmentReader::CreateFromSharedBuffer(data_);
    UseMockImageDecoderFactory();
    decoders_destroyed_ = 0;
    decode_request_count_ = 0;
    memory_allocator_set_count_ = 0;
    status_ = ImageFrame::kFrameEmpty;
    frame_count_ = 1;
    requested_clear_except_frame_ = kNotFound;
  }

  void TearDown() override { ImageDecodingStore::Instance().Clear(); }

  void DecoderBeingDestroyed() override { ++decoders_destroyed_; }

  void DecodeRequested() override { ++decode_request_count_; }

  void MemoryAllocatorSet() override { ++memory_allocator_set_count_; }

  ImageFrame::Status GetStatus(wtf_size_t index) override {
    ImageFrame::Status current_status = status_;
    status_ = next_frame_status_;
    return current_status;
  }

  void ClearCacheExceptFrameRequested(wtf_size_t clear_except_frame) override {
    requested_clear_except_frame_ = clear_except_frame;
  }

  wtf_size_t FrameCount() override { return frame_count_; }
  int RepetitionCount() const override {
    return frame_count_ == 1 ? kAnimationNone : kAnimationLoopOnce;
  }
  base::TimeDelta FrameDuration() const override { return base::TimeDelta(); }

 protected:
  void UseMockImageDecoderFactory() {
    generator_->SetImageDecoderFactory(
        MockImageDecoderFactory::Create(this, FullSize()));
  }

  void AddNewData() { data_->Append("g", 1u); }

  void SetFrameStatus(ImageFrame::Status status) {
    status_ = next_frame_status_ = status;
  }
  void SetNextFrameStatus(ImageFrame::Status status) {
    next_frame_status_ = status;
  }
  void SetFrameCount(wtf_size_t count) {
    frame_count_ = count;
    if (count > 1) {
      generator_ = nullptr;
      generator_ = ImageFrameGenerator::Create(
          FullSize(), true, ColorBehavior::kIgnore, cc::AuxImage::kDefault, {});
      UseMockImageDecoderFactory();
    }
  }
  void SetSupportedSizes(Vector<SkISize> sizes) {
    generator_ = nullptr;
    generator_ =
        ImageFrameGenerator::Create(FullSize(), true, ColorBehavior::kIgnore,
                                    cc::AuxImage::kDefault, std::move(sizes));
    UseMockImageDecoderFactory();
  }

  test::TaskEnvironment task_environment_;
  scoped_refptr<SharedBuffer> data_;
  scoped_refptr<SegmentReader> segment_reader_;
  scoped_refptr<ImageFrameGenerator> generator_;
  int decoders_destroyed_;
  int decode_request_count_;
  int memory_allocator_set_count_;
  ImageFrame::Status status_;
  ImageFrame::Status next_frame_status_;
  wtf_size_t frame_count_;
  wtf_size_t requested_clear_except_frame_;
};

// Test the UMA(ImageHasMultipleGeneratorClientIds) is recorded correctly.
TEST_F(ImageFrameGeneratorTest, DecodeByMultipleClients) {
  SetFrameStatus(ImageFrame::kFrameComplete);
  base::HistogramTester histogram_tester;
  histogram_tester.ExpectTotalCount(
      "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds", 0);

  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  cc::PaintImage::GeneratorClientId client_id_0 =
      cc::PaintImage::GetNextGeneratorClientId();
  generator_->DecodeAndScale(segment_reader_.get(), true, 0, pixmap,
                             client_id_0);
  histogram_tester.ExpectUniqueSample(
      "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds",
      0 /* kRequestByAtLeastOneClient */, 1);

  generator_->DecodeAndScale(segment_reader_.get(), true, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  histogram_tester.ExpectUniqueSample(
      "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds",
      0 /* kRequestByAtLeastOneClient */, 1);

  cc::PaintImage::GeneratorClientId client_id_1 =
      cc::PaintImage::GetNextGeneratorClientId();
  generator_->DecodeAndScale(segment_reader_.get(), true, 0, pixmap,
                             client_id_1);
  histogram_tester.ExpectTotalCount(
      "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds", 2);
  histogram_tester.ExpectBucketCount(
      "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds",
      0 /* kRequestByAtLeastOneClient */, 1);
  histogram_tester.ExpectBucketCount(
      "Blink.ImageDecoders.ImageHasMultipleGeneratorClientIds",
      1 /* kRequestByMoreThanOneClient */, 1);
}

TEST_F(ImageFrameGeneratorTest, GetSupportedSizes) {
  ASSERT_TRUE(FullSize() == SkISize::Make(100, 100));

  Vector<SkISize> supported_sizes = {SkISize::Make(2, 2), SkISize::Make(50, 50),
                                     SkISize::Make(75, 75), FullSize()};
  SetSupportedSizes(supported_sizes);

  struct Test {
    SkISize query_size;
    wtf_size_t supported_size_index;
  } tests[] = {{SkISize::Make(1, 1), 0},     {SkISize::Make(2, 2), 0},
               {SkISize::Make(25, 10), 1},   {SkISize::Make(1, 25), 1},
               {SkISize::Make(50, 51), 2},   {SkISize::Make(80, 80), 3},
               {SkISize::Make(100, 100), 3}, {SkISize::Make(1000, 1000), 3}};
  for (auto& test : tests) {
    EXPECT_TRUE(generator_->GetSupportedDecodeSize(test.query_size) ==
                supported_sizes[test.supported_size_index]);
  }
}

TEST_F(ImageFrameGeneratorTest, incompleteDecode) {
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
  base::test::ScopedFeatureList feature_list;
  // Since PartialLowEndModeOnMidRangeDevices is enabled, image decoders
  // are destroyed because of the incomplete decode for saving memory.
  feature_list.InitAndDisableFeature(
      base::features::kPartialLowEndModeOnMidRangeDevices);
#endif  // BUILDFLAG(IS_ANDROID)

  SetFrameStatus(ImageFrame::kFramePartial);

  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(1, decode_request_count_);
  EXPECT_EQ(0, memory_allocator_set_count_);

  AddNewData();
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(2, decode_request_count_);
  EXPECT_EQ(0, decoders_destroyed_);
  EXPECT_EQ(0, memory_allocator_set_count_);
}

class ImageFrameGeneratorTestPlatform : public TestingPlatformSupport {
 public:
  bool IsLowEndDevice() override { return true; }
};

// This is the same as incompleteData, but with a low-end device set.
TEST_F(ImageFrameGeneratorTest, LowEndDeviceDestroysDecoderOnPartialDecode) {
  ScopedTestingPlatformSupport<ImageFrameGeneratorTestPlatform> platform;

  SetFrameStatus(ImageFrame::kFramePartial);

  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(1, decode_request_count_);
  EXPECT_EQ(1, decoders_destroyed_);
  // The memory allocator is set to the external one, then cleared after decode.
  EXPECT_EQ(2, memory_allocator_set_count_);

  AddNewData();
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(2, decode_request_count_);
  EXPECT_EQ(2, decoders_destroyed_);
  // The memory allocator is set to the external one, then cleared after decode.
  EXPECT_EQ(4, memory_allocator_set_count_);
}

TEST_F(ImageFrameGeneratorTest, incompleteDecodeBecomesComplete) {
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
  base::test::ScopedFeatureList feature_list;
  // Since PartialLowEndModeOnMidRangeDevices is enabled, image decoders
  // are destroyed because of the incomplete decode for saving memory.
  feature_list.InitAndDisableFeature(
      base::features::kPartialLowEndModeOnMidRangeDevices);
#endif  // BUILDFLAG(IS_ANDROID)

  SetFrameStatus(ImageFrame::kFramePartial);

  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(1, decode_request_count_);
  EXPECT_EQ(0, decoders_destroyed_);
  EXPECT_EQ(0, memory_allocator_set_count_);

  SetFrameStatus(ImageFrame::kFrameComplete);
  AddNewData();

  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(2, decode_request_count_);
  EXPECT_EQ(1, decoders_destroyed_);

  // Decoder created again.
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(3, decode_request_count_);
}

static void DecodeThreadMain(ImageFrameGenerator* generator,
                             SegmentReader* segment_reader) {
  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  generator->DecodeAndScale(segment_reader, false, 0, pixmap,
                            cc::PaintImage::kDefaultGeneratorClientId);
}

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
// TODO(crbug.com/948641)
#define MAYBE_incompleteDecodeBecomesCompleteMultiThreaded \
  DISABLED_incompleteDecodeBecomesCompleteMultiThreaded
#else
#define MAYBE_incompleteDecodeBecomesCompleteMultiThreaded \
  incompleteDecodeBecomesCompleteMultiThreaded
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_LINUX) ||
        // BUILDFLAG(IS_CHROMEOS)
TEST_F(ImageFrameGeneratorTest,
       MAYBE_incompleteDecodeBecomesCompleteMultiThreaded) {
  SetFrameStatus(ImageFrame::kFramePartial);

  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(1, decode_request_count_);
  EXPECT_EQ(0, decoders_destroyed_);

  // LocalFrame can now be decoded completely.
  SetFrameStatus(ImageFrame::kFrameComplete);
  AddNewData();
  std::unique_ptr<NonMainThread> thread =
      NonMainThread::CreateThread(ThreadCreationParams(ThreadType::kTestThread)
                                      .SetThreadNameForTest("DecodeThread"));
  PostCrossThreadTask(
      *thread->GetTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(&DecodeThreadMain, WTF::RetainedRef(generator_),
                          WTF::RetainedRef(segment_reader_)));
  thread.reset();
  EXPECT_EQ(2, decode_request_count_);
  EXPECT_EQ(1, decoders_destroyed_);

  // Decoder created again.
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(3, decode_request_count_);

  AddNewData();

  // Delete generator.
  generator_ = nullptr;
}

TEST_F(ImageFrameGeneratorTest, frameHasAlpha) {
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
  base::test::ScopedFeatureList feature_list;
  // Since PartialLowEndModeOnMidRangeDevices is enabled, image decoders
  // are not cached because it makes ShouldDecodeToExternalMemory()
  // return true. The value will be provided for ImageDecoderWrapper::
  // ShouldRemoveDecoder() and ShouldRemoveDecoder() will return true.
  feature_list.InitAndDisableFeature(
      base::features::kPartialLowEndModeOnMidRangeDevices);
#endif

  SetFrameStatus(ImageFrame::kFramePartial);

  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_TRUE(generator_->HasAlpha(0));
  EXPECT_EQ(1, decode_request_count_);

  ImageDecoder* temp_decoder = nullptr;
  EXPECT_TRUE(ImageDecodingStore::Instance().LockDecoder(
      generator_.get(), FullSize(), ImageDecoder::kAlphaPremultiplied,
      cc::PaintImage::kDefaultGeneratorClientId, &temp_decoder));
  ASSERT_TRUE(temp_decoder);
  temp_decoder->DecodeFrameBufferAtIndex(0)->SetHasAlpha(false);
  ImageDecodingStore::Instance().UnlockDecoder(
      generator_.get(), cc::PaintImage::kDefaultGeneratorClientId,
      temp_decoder);
  EXPECT_EQ(2, decode_request_count_);

  SetFrameStatus(ImageFrame::kFrameComplete);
  generator_->DecodeAndScale(segment_reader_.get(), false, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(3, decode_request_count_);
  EXPECT_FALSE(generator_->HasAlpha(0));
}

TEST_F(ImageFrameGeneratorTest, clearMultiFrameDecoder) {
  SetFrameCount(3);
  SetFrameStatus(ImageFrame::kFrameComplete);

  char buffer[100 * 100 * 4];
  SkPixmap pixmap(ImageInfo(), buffer, 100 * 4);
  generator_->DecodeAndScale(segment_reader_.get(), true, 0, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(1, decode_request_count_);
  EXPECT_EQ(0, decoders_destroyed_);
  EXPECT_EQ(0U, requested_clear_except_frame_);

  SetFrameStatus(ImageFrame::kFrameComplete);

  generator_->DecodeAndScale(segment_reader_.get(), true, 1, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(2, decode_request_count_);
  EXPECT_EQ(0, decoders_destroyed_);
  EXPECT_EQ(1U, requested_clear_except_frame_);

  SetFrameStatus(ImageFrame::kFrameComplete);

  // Decoding the last frame of a multi-frame images should trigger clearing
  // all the frame data, but not destroying the decoder.  See comments in
  // ImageFrameGenerator::tryToResumeDecode().
  generator_->DecodeAndScale(segment_reader_.get(), true, 2, pixmap,
                             cc::PaintImage::kDefaultGeneratorClientId);
  EXPECT_EQ(3, decode_request_count_);
  EXPECT_EQ(0, decoders_destroyed_);
  EXPECT_EQ(kNotFound, requested_clear_except_frame_);
}

}  // namespace blink
```