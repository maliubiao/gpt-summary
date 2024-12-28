Response:
The user wants a summary of the functionality of the `bitmap_image_test.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose:** This file contains unit tests for the `BitmapImage` class.
2. **List the functionalities tested:**  I'll go through the test cases and summarize what aspects of `BitmapImage` are being verified.
3. **Explain the relation to web technologies:**  Connect the tested functionalities to how images are used in HTML, CSS, and potentially manipulated by JavaScript.
4. **Provide examples of logic and potential errors:**  For test cases that demonstrate specific behavior or edge cases, I should provide hypothetical inputs and expected outputs, and identify common usage errors that the tests might be preventing.
5. **Summarize the overall functionality:**  Condense the findings into a brief overview.
这是对Chromium Blink引擎中 `blink/renderer/platform/graphics/bitmap_image_test.cc` 文件功能的归纳：

**核心功能：**

这个文件包含了对 `BitmapImage` 类进行单元测试的各种测试用例。 `BitmapImage` 类是 Blink 引擎中用于处理位图图像的核心类。 这些测试旨在验证 `BitmapImage` 类的各种功能和行为是否符合预期。

**测试涵盖的功能点：**

* **解码和渲染:**
    * 测试不同图像格式（GIF, PNG, JPEG, WebP, ICO, BMP, AVIF）的解码能力和渲染结果的正确性。
    * 验证多帧图像（动画 GIF, APNG）的帧解码和显示顺序。
    * 测试在多线程环境下解码图像的正确性。
    * 验证解码后的图像尺寸和颜色数据的正确性。
    * 检查是否正确处理图像的颜色配置文件 (ICC profile)。
    * 测试在数据部分加载完成时的行为。
    * 测试图像解码后缓存数据的销毁和释放。
* **动画处理:**
    * 验证动画图像的循环次数 (`RepetitionCount`) 的解析和处理。
    * 测试动画策略 (`AnimationPolicy`) 对动画播放的影响（例如，只播放一次，不播放，无限循环）。
    * 测试动画的重置功能 (`ResetAnimation`).
    * 区分静态图像和动画图像，并验证 `ImageForDefaultFrame` 方法的行为。
* **内存管理和性能:**
    * 测试控制最大解码图像大小 (`MaxDecodedImageBytes`) 对解码过程的影响，例如强制 JPEG 解码器使用缩放。
    * 验证解码后图像占用的内存大小 (`DecodedSize`) 的计算和更新。
* **图像元数据:**
    * 测试对图像帧元数据（例如，帧持续时间，是否完成）的跟踪和管理。
    * 验证在数据更新时，图像缓存的更新机制。
* **图像标识:**
    * 验证部分加载和完整加载图像的 `PaintImage` 对象标识的一致性。
* **错误处理和边界情况:**
    * 测试处理帧尺寸错误的 ICO 图像。

**与 JavaScript, HTML, CSS 的关系：**

`BitmapImage` 类是浏览器渲染图像的基础，它直接影响着 HTML `<img>` 标签和 CSS `background-image` 属性中使用的图像的显示。

* **HTML `<img>` 标签：** 当浏览器解析到 `<img>` 标签时，会根据 `src` 属性下载图像数据，并使用 `BitmapImage` 类来解码和渲染图像。 这个测试文件验证了 `BitmapImage` 正确解码各种格式的图像，这意味着浏览器可以正确显示不同格式的图片。

    * **举例说明：** 如果 `BitmapImage` 中 GIF 解码器存在问题，那么网页上的 GIF 动画可能无法正常播放或者显示错误。 `GifDecoderFrame0` 等测试用例就是为了确保 GIF 解码的正确性。

* **CSS `background-image` 属性：** CSS 可以使用 `background-image` 属性来设置元素的背景图片，这同样依赖于 `BitmapImage` 来加载和渲染图像。

    * **举例说明：** 如果 `BitmapImage` 对带有 ICC 配置文件的 JPEG 图片处理有误，那么使用这类图片作为背景的元素可能会显示出错误的颜色。 `jpegHasColorProfile` 测试用例确保了对带颜色配置文件的 JPEG 图像的正确处理。

* **JavaScript 操作图像：** JavaScript 可以通过 DOM API 获取 `<img>` 元素，并可能通过 Canvas API 等进行图像处理。 `BitmapImage` 提供的解码能力是这些操作的基础。

    * **举例说明：**  JavaScript 可以使用 Canvas API 将 `<img>` 元素绘制到画布上。 如果 `BitmapImage` 解码出的图像数据不正确，那么 Canvas 上绘制的结果也会出错。  例如， `APNGDecoder00` 测试确保了 APNG 格式的正确解码，这对于 JavaScript 操作 APNG 图像至关重要。

**逻辑推理与假设输入输出：**

* **测试用例：`destroyDecodedData`**
    * **假设输入：** 加载一个动画 GIF 图像。
    * **操作：** 调用 `DestroyDecodedData()` 方法。
    * **预期输出：** 解码后的数据大小变为 0，并且 `LastDecodedSizeChange()` 返回负的原始解码大小。
    * **逻辑推理：**  这个测试验证了显式释放解码后图像数据的机制是否有效，可以帮助节省内存。

* **测试用例：`ConstantImageIdForPartiallyLoadedImages`**
    * **假设输入：**  一个 JPEG 图像的完整数据。
    * **操作：**  先加载部分数据，然后加载完整数据，期间多次获取 `PaintImage` 对象。
    * **预期输出：** 在数据未发生变化时，即使是部分加载，多次获取的 `PaintImage` 对象应该是相同的（使用 `IsSameForTesting` 检查）。 当数据更新或解码数据被销毁后，`PaintImage` 对象会发生变化。
    * **逻辑推理：** 这个测试验证了在图像数据加载过程中，Blink 如何管理 `PaintImage` 的缓存和标识，避免不必要的重新解码和渲染。

**用户或编程常见的使用错误：**

* **忘记释放解码后的数据：** 如果开发者在某些场景下创建了 `BitmapImage` 对象并解码了图像，但忘记在不再使用时调用 `DestroyDecodedData()` 或让 `BitmapImage` 对象被回收，可能会导致内存泄漏。 `destroyDecodedData` 测试就覆盖了这种情况。

* **假设部分加载的图像可以立即使用全部功能：**  开发者可能会在图像数据尚未完全加载完成时就尝试获取图像的完整尺寸或者进行像素级别的操作，这可能导致程序错误。  `isAllDataReceived` 和 `ConstantImageIdForPartiallyLoadedImages`  相关的测试体现了 Blink 对部分加载图像的处理方式，提醒开发者需要考虑这种情况。

* **错误地处理动画图像的循环次数：**  开发者可能错误地假设所有动画都会无限循环，或者没有正确读取和处理图像元数据中的循环次数，导致动画播放行为不符合预期。 `GIFRepetitionCount`  等测试确保了对循环次数的正确解析。

**总结 `bitmap_image_test.cc` 的功能 (第 1 部分)：**

`bitmap_image_test.cc` 文件主要用于对 Blink 引擎中的 `BitmapImage` 类进行全面的单元测试。 它涵盖了图像解码、渲染、动画处理、内存管理、图像元数据处理以及对各种图像格式和边界情况的处理。 这些测试确保了 `BitmapImage` 类的正确性和稳定性，从而保证了网页上图像的正常显示和 JavaScript 对图像的正确操作。  这些测试对于防止因图像处理错误而导致的网页显示问题和潜在的内存泄漏至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/bitmap_image_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/numerics/safe_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "cc/paint/image_provider.h"
#include "cc/paint/skia_paint_canvas.h"
#include "cc/tiles/mipmap_util.h"
#include "media/media_buildflags.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image_metrics.h"
#include "third_party/blink/renderer/platform/graphics/deferred_image_decoder.h"
#include "third_party/blink/renderer/platform/graphics/image_observer.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_image_decoder.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkImage.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {
namespace {

class FrameSettingImageProvider : public cc::ImageProvider {
 public:
  FrameSettingImageProvider(size_t frame_index,
                            cc::PaintImage::GeneratorClientId client_id)
      : frame_index_(frame_index), client_id_(client_id) {}
  ~FrameSettingImageProvider() override = default;

  ImageProvider::ScopedResult GetRasterContent(
      const cc::DrawImage& draw_image) override {
    DCHECK(!draw_image.paint_image().IsPaintWorklet());
    auto sk_image =
        draw_image.paint_image().GetSkImageForFrame(frame_index_, client_id_);
    return ScopedResult(cc::DecodedDrawImage(
        sk_image, nullptr, SkSize::MakeEmpty(), SkSize::Make(1, 1),
        draw_image.filter_quality(), true));
  }

 private:
  size_t frame_index_;
  cc::PaintImage::GeneratorClientId client_id_;
};

void GenerateBitmapForPaintImage(cc::PaintImage paint_image,
                                 size_t frame_index,
                                 cc::PaintImage::GeneratorClientId client_id,
                                 SkBitmap* bitmap) {
  CHECK(paint_image);
  CHECK_GE(paint_image.FrameCount(), frame_index);

  SkImageInfo info =
      SkImageInfo::MakeN32Premul(paint_image.width(), paint_image.height());
  bitmap->allocPixels(info, paint_image.width() * 4);
  bitmap->eraseColor(SK_AlphaTRANSPARENT);
  FrameSettingImageProvider image_provider(frame_index, client_id);
  cc::SkiaPaintCanvas canvas(*bitmap, &image_provider);
  canvas.drawImage(paint_image, 0u, 0u);
}

}  // namespace

// Extends TestingPlatformSupportWithMockScheduler to add the ability to set the
// return value of MaxDecodedImageBytes().
class TestingPlatformSupportWithMaxDecodedBytes
    : public TestingPlatformSupportWithMockScheduler {
 public:
  TestingPlatformSupportWithMaxDecodedBytes() {}
  TestingPlatformSupportWithMaxDecodedBytes(
      const TestingPlatformSupportWithMaxDecodedBytes&) = delete;
  TestingPlatformSupportWithMaxDecodedBytes& operator=(
      const TestingPlatformSupportWithMaxDecodedBytes&) = delete;
  ~TestingPlatformSupportWithMaxDecodedBytes() override {}

  void SetMaxDecodedImageBytes(size_t max_decoded_image_bytes) {
    max_decoded_image_bytes_ = max_decoded_image_bytes;
  }

  size_t MaxDecodedImageBytes() override { return max_decoded_image_bytes_; }

 private:
  size_t max_decoded_image_bytes_ = Platform::kNoDecodedImageByteLimit;
};

class BitmapImageTest : public testing::Test {
 public:
  class FakeImageObserver : public GarbageCollected<FakeImageObserver>,
                            public ImageObserver {
   public:
    FakeImageObserver()
        : last_decoded_size_(0), last_decoded_size_changed_delta_(0) {}

    void DecodedSizeChangedTo(const Image*, size_t new_size) override {
      last_decoded_size_changed_delta_ =
          base::checked_cast<int>(new_size) -
          base::checked_cast<int>(last_decoded_size_);
      last_decoded_size_ = new_size;
    }
    bool ShouldPauseAnimation(const Image*) override { return false; }
    void AsyncLoadCompleted(const Image*) override { NOTREACHED(); }

    void Changed(const Image*) override {}

    size_t last_decoded_size_;
    int last_decoded_size_changed_delta_;
  };

  void TearDown() override { image_.reset(); }

  static Vector<char> ReadFile(const char* file_name) {
    String file_path = test::PlatformTestDataPath(file_name);
    std::optional<Vector<char>> data = test::ReadFromFile(file_path);
    CHECK(data && data->size());
    return std::move(*data);
  }

  // Accessors to BitmapImage's protected methods.
  void DestroyDecodedData() { image_->DestroyDecodedData(); }
  size_t FrameCount() { return image_->FrameCount(); }

  void CreateImage() {
    image_observer_ = MakeGarbageCollected<FakeImageObserver>();
    image_ = BitmapImage::Create(image_observer_.Get());
  }

  void LoadImage(const char* file_name) {
    CreateImage();

    scoped_refptr<SharedBuffer> image_data =
        SharedBuffer::Create(ReadFile(file_name));
    ASSERT_TRUE(image_data.get());

    image_->SetData(image_data, true);
  }

  void LoadBlinkWebTestsImage(const char* relative_path) {
    CreateImage();

    String file_path = test::BlinkWebTestsImagesTestDataPath(relative_path);
    std::optional<Vector<char>> data = test::ReadFromFile(file_path);
    ASSERT_TRUE(data && data->size());
    scoped_refptr<SharedBuffer> image_data =
        SharedBuffer::Create(std::move(*data));
    image_->SetData(image_data, true);
  }

  SkBitmap GenerateBitmap(size_t frame_index) {
    SkBitmap bitmap;
    GenerateBitmapForPaintImage(image_->PaintImageForTesting(), frame_index,
                                cc::PaintImage::kDefaultGeneratorClientId,
                                &bitmap);
    return bitmap;
  }

  SkBitmap GenerateBitmapForImage(const char* file_name) {
    scoped_refptr<SharedBuffer> image_data =
        SharedBuffer::Create(ReadFile(file_name));
    EXPECT_TRUE(image_data.get());
    if (!image_data)
      return SkBitmap();

    auto image = BitmapImage::Create();
    image->SetData(image_data, true);
    auto paint_image = image->PaintImageForCurrentFrame();
    CHECK(paint_image);

    SkBitmap bitmap;
    SkImageInfo info = SkImageInfo::MakeN32Premul(image->Size().width(),
                                                  image->Size().height());
    bitmap.allocPixels(info, image->Size().width() * 4);
    bitmap.eraseColor(SK_AlphaTRANSPARENT);
    cc::SkiaPaintCanvas canvas(bitmap);
    canvas.drawImage(paint_image, 0u, 0u);
    return bitmap;
  }

  void VerifyBitmap(const SkBitmap& bitmap, SkColor color) {
    ASSERT_GT(bitmap.width(), 0);
    ASSERT_GT(bitmap.height(), 0);

    for (int i = 0; i < bitmap.width(); ++i) {
      for (int j = 0; j < bitmap.height(); ++j) {
        auto bitmap_color = bitmap.getColor(i, j);
        EXPECT_EQ(bitmap_color, color)
            << "Bitmap: " << SkColorGetA(bitmap_color) << ","
            << SkColorGetR(bitmap_color) << "," << SkColorGetG(bitmap_color)
            << "," << SkColorGetB(bitmap_color)
            << "Expected: " << SkColorGetA(color) << "," << SkColorGetR(color)
            << "," << SkColorGetG(color) << "," << SkColorGetB(color);
      }
    }
  }

  void VerifyBitmap(const SkBitmap& bitmap, const SkBitmap& expected) {
    ASSERT_GT(bitmap.width(), 0);
    ASSERT_GT(bitmap.height(), 0);
    ASSERT_EQ(bitmap.info(), expected.info());

    for (int i = 0; i < bitmap.width(); ++i) {
      for (int j = 0; j < bitmap.height(); ++j) {
        auto bitmap_color = bitmap.getColor(i, j);
        auto expected_color = expected.getColor(i, j);
        EXPECT_EQ(bitmap_color, expected_color)
            << "Bitmap: " << SkColorGetA(bitmap_color) << ","
            << SkColorGetR(bitmap_color) << "," << SkColorGetG(bitmap_color)
            << "," << SkColorGetB(bitmap_color)
            << "Expected: " << SkColorGetA(expected_color) << ","
            << SkColorGetR(expected_color) << "," << SkColorGetG(expected_color)
            << "," << SkColorGetB(expected_color);
      }
    }
  }

  size_t DecodedSize() { return image_->TotalFrameBytes(); }

  int RepetitionCount() { return image_->RepetitionCount(); }

  scoped_refptr<Image> ImageForDefaultFrame() {
    return image_->ImageForDefaultFrame();
  }

  int LastDecodedSizeChange() {
    return image_observer_->last_decoded_size_changed_delta_;
  }

  scoped_refptr<SharedBuffer> Data() { return image_->Data(); }

 protected:
  Persistent<FakeImageObserver> image_observer_;
  scoped_refptr<BitmapImage> image_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMaxDecodedBytes>
      platform_;
};

TEST_F(BitmapImageTest, destroyDecodedData) {
  LoadImage("animated-10color.gif");
  image_->PaintImageForCurrentFrame();
  size_t total_size = DecodedSize();
  EXPECT_GT(total_size, 0u);
  DestroyDecodedData();
  EXPECT_EQ(-static_cast<int>(total_size), LastDecodedSizeChange());
  EXPECT_EQ(0u, DecodedSize());
}

TEST_F(BitmapImageTest, maybeAnimated) {
  LoadImage("gif-loop-count.gif");
  EXPECT_TRUE(image_->MaybeAnimated());
}

TEST_F(BitmapImageTest, isAllDataReceived) {
  scoped_refptr<SharedBuffer> image_data =
      SharedBuffer::Create(ReadFile("green.jpg"));
  ASSERT_TRUE(image_data.get());

  scoped_refptr<BitmapImage> image = BitmapImage::Create();
  EXPECT_FALSE(image->IsAllDataReceived());

  image->SetData(image_data, false);
  EXPECT_FALSE(image->IsAllDataReceived());

  image->SetData(image_data, true);
  EXPECT_TRUE(image->IsAllDataReceived());
}

TEST_F(BitmapImageTest, noColorProfile) {
  LoadImage("green.jpg");
  image_->PaintImageForCurrentFrame();
  EXPECT_EQ(1024u, DecodedSize());
  EXPECT_FALSE(image_->HasColorProfile());
}

TEST_F(BitmapImageTest, jpegHasColorProfile) {
  LoadImage("icc-v2-gbr.jpg");
  image_->PaintImageForCurrentFrame();
  EXPECT_EQ(227700u, DecodedSize());
  EXPECT_TRUE(image_->HasColorProfile());
}

TEST_F(BitmapImageTest, pngHasColorProfile) {
  LoadImage("palatted-color-png-gamma-one-color-profile.png");
  image_->PaintImageForCurrentFrame();
  EXPECT_EQ(65536u, DecodedSize());
  EXPECT_TRUE(image_->HasColorProfile());
}

TEST_F(BitmapImageTest, webpHasColorProfile) {
  LoadImage("webp-color-profile-lossy.webp");
  image_->PaintImageForCurrentFrame();
  EXPECT_EQ(2560000u, DecodedSize());
  EXPECT_TRUE(image_->HasColorProfile());
}

TEST_F(BitmapImageTest, icoHasWrongFrameDimensions) {
  LoadImage("wrong-frame-dimensions.ico");
  // This call would cause crash without fix for 408026
  ImageForDefaultFrame();
}

TEST_F(BitmapImageTest, correctDecodedDataSize) {
  // Requesting any one frame shouldn't result in decoding any other frames.
  LoadImage("anim_none.gif");
  image_->PaintImageForCurrentFrame();
  int frame_size =
      static_cast<int>(image_->Size().Area64() * sizeof(ImageFrame::PixelData));
  EXPECT_EQ(frame_size, LastDecodedSizeChange());
}

TEST_F(BitmapImageTest, recachingFrameAfterDataChanged) {
  LoadImage("green.jpg");
  image_->PaintImageForCurrentFrame();
  EXPECT_GT(LastDecodedSizeChange(), 0);
  image_observer_->last_decoded_size_changed_delta_ = 0;

  // Calling dataChanged causes the cache to flush, but doesn't affect the
  // source's decoded frames. It shouldn't affect decoded size.
  image_->DataChanged(true);
  EXPECT_EQ(0, LastDecodedSizeChange());
  // Recaching the first frame also shouldn't affect decoded size.
  image_->PaintImageForCurrentFrame();
  EXPECT_EQ(0, LastDecodedSizeChange());
}

TEST_F(BitmapImageTest, ConstantImageIdForPartiallyLoadedImages) {
  Vector<char> image_data_binary = ReadFile("green.jpg");

  // Create a new buffer to partially supply the data.
  scoped_refptr<SharedBuffer> partial_buffer = SharedBuffer::Create();
  partial_buffer->Append(image_data_binary.data(),
                         image_data_binary.size() - 4);

  // First partial load. Repeated calls for a PaintImage should have the same
  // image until the data changes or the decoded data is destroyed.
  CreateImage();
  ASSERT_EQ(image_->SetData(partial_buffer, false), Image::kSizeAvailable);
  auto image1 = image_->PaintImageForCurrentFrame();
  auto image2 = image_->PaintImageForCurrentFrame();
  EXPECT_TRUE(image1.IsSameForTesting(image2));
  auto sk_image1 = image1.GetSwSkImage();
  auto sk_image2 = image2.GetSwSkImage();
  EXPECT_EQ(sk_image1->uniqueID(), sk_image2->uniqueID());

  // Frame keys should be the same for these PaintImages.
  EXPECT_EQ(image1.GetKeyForFrame(PaintImage::kDefaultFrameIndex),
            image2.GetKeyForFrame(PaintImage::kDefaultFrameIndex));

  // Destroy the decoded data. This generates a new id since we don't cache
  // image ids for partial decodes.
  DestroyDecodedData();
  auto image3 = image_->PaintImageForCurrentFrame();
  auto sk_image3 = image3.GetSwSkImage();
  EXPECT_NE(sk_image1, sk_image3);
  EXPECT_NE(sk_image1->uniqueID(), sk_image3->uniqueID());

  // Since the cached generator is discarded on destroying the cached decode,
  // the new content id is generated resulting in an updated frame key.
  EXPECT_NE(image1.GetKeyForFrame(PaintImage::kDefaultFrameIndex),
            image3.GetKeyForFrame(PaintImage::kDefaultFrameIndex));

  // Load complete. This should generate a new image id.
  scoped_refptr<SharedBuffer> image_data =
      SharedBuffer::Create(image_data_binary);
  image_->SetData(image_data, true);
  auto complete_image = image_->PaintImageForCurrentFrame();
  auto complete_sk_image = complete_image.GetSwSkImage();
  EXPECT_NE(sk_image3, complete_sk_image);
  EXPECT_NE(sk_image3->uniqueID(), complete_sk_image->uniqueID());
  EXPECT_NE(complete_image.GetKeyForFrame(PaintImage::kDefaultFrameIndex),
            image3.GetKeyForFrame(PaintImage::kDefaultFrameIndex));

  // Destroy the decoded data and re-create the PaintImage. The frame key
  // remains constant but the SkImage id will change since we don't cache skia
  // uniqueIDs.
  DestroyDecodedData();
  auto new_complete_image = image_->PaintImageForCurrentFrame();
  auto new_complete_sk_image = new_complete_image.GetSwSkImage();
  EXPECT_NE(new_complete_sk_image, complete_sk_image);
  EXPECT_EQ(new_complete_image.GetKeyForFrame(PaintImage::kDefaultFrameIndex),
            complete_image.GetKeyForFrame(PaintImage::kDefaultFrameIndex));
}

TEST_F(BitmapImageTest, ImageForDefaultFrame_MultiFrame) {
  LoadImage("anim_none.gif");

  // Multi-frame images create new StaticBitmapImages for each call.
  auto default_image1 = image_->ImageForDefaultFrame();
  auto default_image2 = image_->ImageForDefaultFrame();
  EXPECT_NE(default_image1, default_image2);

  // But the PaintImage should be the same.
  auto paint_image1 = default_image1->PaintImageForCurrentFrame();
  auto paint_image2 = default_image2->PaintImageForCurrentFrame();
  EXPECT_TRUE(paint_image1.IsSameForTesting(paint_image2));
  EXPECT_EQ(paint_image1.GetSwSkImage()->uniqueID(),
            paint_image2.GetSwSkImage()->uniqueID());
}

TEST_F(BitmapImageTest, ImageForDefaultFrame_SingleFrame) {
  LoadImage("green.jpg");

  // Default frame images for single-frame cases is the image itself.
  EXPECT_EQ(image_->ImageForDefaultFrame(), image_);
}

TEST_F(BitmapImageTest, GifDecoderFrame0) {
  LoadImage("green-red-blue-yellow-animated.gif");
  auto bitmap = GenerateBitmap(0u);
  SkColor color = SkColorSetARGB(255, 0, 128, 0);
  VerifyBitmap(bitmap, color);
}

TEST_F(BitmapImageTest, GifDecoderFrame1) {
  LoadImage("green-red-blue-yellow-animated.gif");
  auto bitmap = GenerateBitmap(1u);
  VerifyBitmap(bitmap, SK_ColorRED);
}

TEST_F(BitmapImageTest, GifDecoderFrame2) {
  LoadImage("green-red-blue-yellow-animated.gif");
  auto bitmap = GenerateBitmap(2u);
  VerifyBitmap(bitmap, SK_ColorBLUE);
}

TEST_F(BitmapImageTest, GifDecoderFrame3) {
  LoadImage("green-red-blue-yellow-animated.gif");
  auto bitmap = GenerateBitmap(3u);
  VerifyBitmap(bitmap, SK_ColorYELLOW);
}

TEST_F(BitmapImageTest, GifDecoderMultiThreaded) {
  LoadImage("green-red-blue-yellow-animated.gif");
  auto paint_image = image_->PaintImageForTesting();
  ASSERT_EQ(paint_image.FrameCount(), 4u);

  struct Decode {
    SkBitmap bitmap;
    std::unique_ptr<base::Thread> thread;
    cc::PaintImage::GeneratorClientId client_id;
  };

  Decode decodes[4];
  SkColor expected_color[4] = {SkColorSetARGB(255, 0, 128, 0), SK_ColorRED,
                               SK_ColorBLUE, SK_ColorYELLOW};
  for (int i = 0; i < 4; ++i) {
    decodes[i].thread =
        std::make_unique<base::Thread>("Decode" + std::to_string(i));
    decodes[i].client_id = cc::PaintImage::GetNextGeneratorClientId();

    decodes[i].thread->StartAndWaitForTesting();
    decodes[i].thread->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&GenerateBitmapForPaintImage, paint_image, i,
                                  decodes[i].client_id, &decodes[i].bitmap));
  }

  for (int i = 0; i < 4; ++i) {
    decodes[i].thread->FlushForTesting();
    VerifyBitmap(decodes[i].bitmap, expected_color[i]);
  }
}

TEST_F(BitmapImageTest, APNGDecoder00) {
  LoadImage("apng00.png");
  auto actual_bitmap = GenerateBitmap(0u);
  auto expected_bitmap = GenerateBitmapForImage("apng00-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

// Jump to the final frame of each image.
TEST_F(BitmapImageTest, APNGDecoder01) {
  LoadImage("apng01.png");
  auto actual_bitmap = GenerateBitmap(9u);
  auto expected_bitmap = GenerateBitmapForImage("apng01-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder02) {
  LoadImage("apng02.png");
  auto actual_bitmap = GenerateBitmap(9u);
  auto expected_bitmap = GenerateBitmapForImage("apng02-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder04) {
  LoadImage("apng04.png");
  auto actual_bitmap = GenerateBitmap(12u);
  auto expected_bitmap = GenerateBitmapForImage("apng04-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder08) {
  LoadImage("apng08.png");
  auto actual_bitmap = GenerateBitmap(12u);
  auto expected_bitmap = GenerateBitmapForImage("apng08-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder10) {
  LoadImage("apng10.png");
  auto actual_bitmap = GenerateBitmap(3u);
  auto expected_bitmap = GenerateBitmapForImage("apng10-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder11) {
  LoadImage("apng11.png");
  auto actual_bitmap = GenerateBitmap(9u);
  auto expected_bitmap = GenerateBitmapForImage("apng11-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder12) {
  LoadImage("apng12.png");
  auto actual_bitmap = GenerateBitmap(9u);
  auto expected_bitmap = GenerateBitmapForImage("apng12-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder14) {
  LoadImage("apng14.png");
  auto actual_bitmap = GenerateBitmap(12u);
  auto expected_bitmap = GenerateBitmapForImage("apng14-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder18) {
  LoadImage("apng18.png");
  auto actual_bitmap = GenerateBitmap(12u);
  auto expected_bitmap = GenerateBitmapForImage("apng18-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoder19) {
  LoadImage("apng19.png");
  auto actual_bitmap = GenerateBitmap(12u);
  auto expected_bitmap = GenerateBitmapForImage("apng19-ref.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, APNGDecoderDisposePrevious) {
  LoadImage("crbug722072.png");
  auto actual_bitmap = GenerateBitmap(3u);
  auto expected_bitmap = GenerateBitmapForImage("green.png");
  VerifyBitmap(actual_bitmap, expected_bitmap);
}

TEST_F(BitmapImageTest, GIFRepetitionCount) {
  LoadImage("three-frames_loop-three-times.gif");
  auto paint_image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(paint_image.repetition_count(), 3);
  EXPECT_EQ(paint_image.FrameCount(), 3u);
}

TEST_F(BitmapImageTest, DecoderAndCacheMipLevels) {
  // Here, we want to test that the mip level calculated by the cc matches
  // exactly a size supported by the decoder. This is to make sure that the
  // rounding used in cc matches the rounding in the decoder. The image in this
  // test is 629x473 and uses 4:2:0 sampling. This means that the MCU is 16x16.
  // Under no memory limits, this image would not be eligible for downscaling by
  // the JPEG decoder because neither dimension is a multiple of 16 (see
  // https://crbug.com/890745). However, we can force the JPEG decoder to
  // support downscaling by limiting the maximum bytes allowed for decoding. If
  // we limit to 315 * 237 * 4 bytes, we'll be forcing the maximum scale factor
  // numerator to be 4 (assuming a denominator of 8).
  platform_->SetMaxDecodedImageBytes(315 * 237 * 4);
  LoadImage("original-cat-420-629x473.jpg");
  auto paint_image = image_->PaintImageForCurrentFrame();

  // The size of the PaintImage is based on the maximum bytes allowed for
  // decoding.
  ASSERT_EQ(315, paint_image.width());
  ASSERT_EQ(237, paint_image.height());

  // Level 0 should match the decoder supported size for scale factor 4/8.
  // Level 1 should match the decoder supported size for scale factor 2/8.
  // Level 2 should match the decoder supported size for scale factor 1/8.
  // Higher levels (smaller sizes) are not supported by the JPEG decoder.
  for (int mip_level = 0; mip_level < 3; ++mip_level) {
    SCOPED_TRACE(mip_level);
    SkISize scaled_size = gfx::SizeToSkISize(cc::MipMapUtil::GetSizeForLevel(
        gfx::Size(paint_image.width(), paint_image.height()), mip_level));
    SkISize supported_size = paint_image.GetSupportedDecodeSize(scaled_size);
    EXPECT_EQ(gfx::SkISizeToSize(supported_size),
              gfx::SkISizeToSize(scaled_size));
  }
}

class BitmapImageTestWithMockDecoder : public BitmapImageTest,
                                       public MockImageDecoderClient {
 public:
  void SetUp() override {
    auto decoder = std::make_unique<MockImageDecoder>(this);
    decoder->SetSize(10u, 10u);
    CreateImage();
    image_->SetDecoderForTesting(
        DeferredImageDecoder::CreateForTesting(std::move(decoder)));
  }

  void DecoderBeingDestroyed() override {}
  void DecodeRequested() override {}
  ImageFrame::Status GetStatus(wtf_size_t index) override {
    if (index < frame_count_ - 1 || last_frame_complete_)
      return ImageFrame::Status::kFrameComplete;
    return ImageFrame::Status::kFramePartial;
  }
  wtf_size_t FrameCount() override { return frame_count_; }
  int RepetitionCount() const override { return repetition_count_; }
  base::TimeDelta FrameDuration() const override { return duration_; }

 protected:
  base::TimeDelta duration_;
  int repetition_count_;
  wtf_size_t frame_count_;
  bool last_frame_complete_;
};

TEST_F(BitmapImageTestWithMockDecoder, ImageMetadataTracking) {
  // For a zero duration, we should make it non-zero when creating a PaintImage.
  repetition_count_ = kAnimationLoopOnce;
  frame_count_ = 4u;
  last_frame_complete_ = false;
  image_->SetData(SharedBuffer::Create("data", sizeof("data")), false);

  PaintImage image = image_->PaintImageForCurrentFrame();
  ASSERT_TRUE(image);
  EXPECT_EQ(image.FrameCount(), frame_count_);
  EXPECT_EQ(image.completion_state(),
            PaintImage::CompletionState::kPartiallyDone);
  EXPECT_EQ(image.repetition_count(), repetition_count_);
  for (size_t i = 0; i < image.GetFrameMetadata().size(); ++i) {
    const auto& data = image.GetFrameMetadata()[i];
    EXPECT_EQ(data.duration, base::Milliseconds(100));
    if (i == frame_count_ - 1 && !last_frame_complete_)
      EXPECT_FALSE(data.complete);
    else
      EXPECT_TRUE(data.complete);
  }

  // Now the load is finished.
  duration_ = base::Seconds(1);
  repetition_count_ = kAnimationLoopInfinite;
  frame_count_ = 6u;
  last_frame_complete_ = true;
  image_->SetData(SharedBuffer::Create("data", sizeof("data")), true);

  image = image_->PaintImageForCurrentFrame();
  ASSERT_TRUE(image);
  EXPECT_EQ(image.FrameCount(), frame_count_);
  EXPECT_EQ(image.completion_state(), PaintImage::CompletionState::kDone);
  EXPECT_EQ(image.repetition_count(), repetition_count_);
  for (size_t i = 0; i < image.GetFrameMetadata().size(); ++i) {
    const auto& data = image.GetFrameMetadata()[i];
    if (i < 4u)
      EXPECT_EQ(data.duration, base::Milliseconds(100));
    else
      EXPECT_EQ(data.duration, base::Seconds(1));
    EXPECT_TRUE(data.complete);
  }
}

TEST_F(BitmapImageTestWithMockDecoder,
       AnimationPolicyOverrideOriginalRepetitionNone) {
  repetition_count_ = kAnimationNone;
  frame_count_ = 4u;
  last_frame_complete_ = true;
  image_->SetData(SharedBuffer::Create("data", sizeof("data")), false);

  PaintImage image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), repetition_count_);

  // In all cases, the image shouldn't animate.

  // Only one loop allowed.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAnimateOnce);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationNone);

  // No animation allowed.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyNoAnimation);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationNone);

  // Default policy.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAllowed);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationNone);
}

TEST_F(BitmapImageTestWithMockDecoder,
       AnimationPolicyOverrideOriginalRepetitionOnce) {
  repetition_count_ = kAnimationLoopOnce;
  frame_count_ = 4u;
  last_frame_complete_ = true;
  image_->SetData(SharedBuffer::Create("data", sizeof("data")), false);

  PaintImage image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), repetition_count_);

  // If the policy is no animation, then the repetition count is none. In all
  // other cases, it remains loop once.

  // Only one loop allowed.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAnimateOnce);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationLoopOnce);

  // No animation allowed.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyNoAnimation);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationNone);

  // Default policy.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAllowed);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationLoopOnce);
}

TEST_F(BitmapImageTestWithMockDecoder,
       AnimationPolicyOverrideOriginalRepetitionInfinite) {
  repetition_count_ = kAnimationLoopInfinite;
  frame_count_ = 4u;
  last_frame_complete_ = true;
  image_->SetData(SharedBuffer::Create("data", sizeof("data")), false);

  PaintImage image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), repetition_count_);

  // The repetition count is determined by the animation policy.

  // Only one loop allowed.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAnimateOnce);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationLoopOnce);

  // No animation allowed.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyNoAnimation);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), kAnimationNone);

  // Default policy.
  image_->SetAnimationPolicy(
      mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAllowed);
  image = image_->PaintImageForCurrentFrame();
  EXPECT_EQ(image.repetition_count(), repetition_count_);
}

TEST_F(BitmapImageTestWithMockDecoder, ResetAnimation) {
  repetition_count_ = kAnimationLoopInfinite;
  frame_count_ = 4u;
  last_frame_complete_ = true;
  image_->SetData(SharedBuffer::Create("data", sizeof("data")), false);

  PaintImage image = image_->PaintImageForCurrentFrame();
  image_->ResetAnimation();
  PaintImage image2 = image_->PaintImageForCurrentFrame();
  EXPECT_GT(image2.reset_animation_sequence_id(),
            image.reset_animation_sequence_id());
}

TEST_F(BitmapImageTestWithMockDecoder, PaintImageForStaticBitmapImage) {
  repetition_count_ = kAnimationLoopInfinite;
  frame_count_ = 5;
  last_frame_complete_ = true;
  image_->SetData(SharedBuffer::Create("data", sizeof("data")), false);

  // PaintImage for the original image is animated.
  EXPECT_TRUE(image_->PaintImageForCurrentFrame().ShouldAnimate());

  // But the StaticBitmapImage is not.
  EXPECT_FALSE(image_->ImageForDefaultFrame()
                   ->PaintImageForCurrentFrame()
                   .ShouldAnimate());
}

class BitmapHistogramTest : public BitmapImageTest {
 protected:
  template <typename MetricType>
  void ExpectImageRecordsSample(const char* filename,
                                const char* name,
                                MetricType bucket,
                                int count = 1) {
    base::HistogramTester histogram_tester;
    LoadImage(filename);
    histogram_tester.ExpectUniqueSample(name, bucket, count);
  }
};

TEST_F(BitmapHistogramTest, DecodedImageType) {
  ExpectImageRecordsSample("green.jpg", "Blink.DecodedImageType",
                           BitmapImageMetrics::DecodedImageType::kJPEG);
  ExpectImageRecordsSample("palatted-color-png-gamma-one-color-profile.png",
                           "Blink.DecodedImageType",
                           BitmapImageMetrics::DecodedImageType::kPNG);
  ExpectImageRecordsSample("animated-10color.gif", "Blink.DecodedImageType",
                           BitmapImageMetrics::DecodedImageType::kGIF);
  ExpectImageRecordsSample("webp-color-profile-lossy.webp",
                           "Blink.DecodedImageType",
                           BitmapImageMetrics::DecodedImageType::kWebP);
  ExpectImageRecordsSample("wrong-frame-dimensions.ico",
                           "Blink.DecodedImageType",
                           BitmapImageMetrics::DecodedImageType::kICO);
  ExpectImageRecordsSample("gracehopper.bmp", "Blink.DecodedImageType",
                           BitmapImageMetrics::DecodedImageType::kBMP);
#if BUILDFLAG(ENABLE_AV1_DECODER)
  ExpectImageRecordsSample("red-full-ranged-8bpc.avif",
                           "Blink.DecodedImageType",
                           Bitmap
"""


```