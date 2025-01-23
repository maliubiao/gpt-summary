Response:
Let's break down the thought process for analyzing the C++ test file and generating the response.

1. **Understand the Core Task:** The request asks for an analysis of the `deferred_image_decoder_test.cc` file, focusing on its functionality, relationship to web technologies (JS, HTML, CSS), logic/reasoning with examples, and common user/programming errors.

2. **Initial Code Scan and High-Level Understanding:**  The first step is to quickly scan the `#include` directives and the overall structure of the file. This immediately reveals:
    * It's a C++ test file (`.cc`).
    * It uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`).
    * It's testing something related to image decoding (`deferred_image_decoder.h`, `image_decoding_store.h`, `image_frame_generator.h`, `mock_image_decoder.h`).
    * It involves painting and graphics (`paint/paint_canvas.h`, `paint/paint_image.h`, `paint/paint_record.h`, `paint/paint_recorder.h`).
    * It mentions threading (`scheduler/public/non_main_thread.h`, `scheduler/public/post_cross_thread_task.h`).
    * It uses Skia (`third_party/skia/include/...`).

3. **Identify the Target Class:** The file name `deferred_image_decoder_test.cc` strongly suggests the primary target of the tests is the `DeferredImageDecoder` class.

4. **Analyze the Test Fixture:** The `DeferredImageDecoderTest` class inherits from `testing::Test` and `MockImageDecoderClient`. This provides crucial information:
    * It's setting up and tearing down test environments (`SetUp`, `TearDown`).
    * It's using a mock object (`MockImageDecoder`) to simulate the behavior of a real image decoder.
    * It's implementing the `MockImageDecoderClient` interface, indicating it needs to respond to events from the mock decoder.

5. **Examine Individual Test Cases:**  Go through each `TEST_F` function to understand what specific aspect of `DeferredImageDecoder` is being tested. For each test case, try to answer:
    * What is the *input* to the `DeferredImageDecoder` (e.g., image data, flags)?
    * What *actions* are being performed (e.g., setting data, creating `PaintImage`, drawing)?
    * What are the *expected outcomes* (assertions using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`)?

    *Examples from the file and the thinking process:*

    * **`drawIntoPaintRecord`:** Sets image data, creates a `PaintImage`, draws it into a `PaintRecord`, and then renders the record. The key assertion is that no decoding happens *until* the record is drawn. This points to the "deferred" nature.
    * **`drawIntoPaintRecordProgressive`:** Tests handling of partial image data, drawing, then completing the data and drawing again. This highlights how the decoder handles progressive loading.
    * **`allDataReceivedPriorToDecodeNonIncrementally` and `allDataReceivedPriorToDecodeIncrementally`:** Focus on the `all_data_received_prior_to_decode` flag in the `ImageHeaderMetadata`. These tests differentiate between loading all data at once vs. in parts *before* creating the `PaintImageGenerator`.
    * **`notAllDataReceivedPriorToDecode`:**  Similar to the previous tests but examines the case where a `PaintImageGenerator` is created *before* all data is received.
    * **`decodeOnOtherThread`:**  Demonstrates that image decoding can happen on a separate thread. This is a performance optimization.
    * **`singleFrameImageLoading` and `multiFrameImageLoading`:** Test the handling of single and multi-frame images (like GIFs), checking if frames are received and duration is correctly handled.
    * **`decodedSize`:** Verifies that the decoded image size is correctly reported.
    * **`smallerFrameCount`:**  Tests how the decoder handles changes in the reported frame count.
    * **`frameOpacity`:**  Checks if the decoder correctly determines the opacity of an image frame after decoding.
    * **`data`:** Tests the ability to retrieve the image data from the decoder.
    * **`PaintImage` (in `MultiFrameDeferredImageDecoderTest`):** Focuses on the `PaintImage` object itself, specifically the `FrameMetadata` (completeness, duration) and how keys for frames are generated and updated.
    * **`FrameDurationOverride` (in `MultiFrameDeferredImageDecoderTest`):** Checks the logic for overriding very short frame durations.

6. **Identify Connections to Web Technologies:** Consider how the functionality of `DeferredImageDecoder` relates to JavaScript, HTML, and CSS.
    * **HTML `<img>` tag:** The most obvious connection. The decoder is responsible for processing the image data fetched by the browser when it encounters an `<img>` tag.
    * **CSS `background-image`:** Similar to `<img>`, CSS can specify images.
    * **JavaScript `Image()` constructor:**  JavaScript can create `Image` objects, which will also use the image decoding pipeline.
    * **Progressive loading:** This is a key feature visible to users and developers. The decoder's ability to handle partial data directly relates to this.
    * **Animation (GIFs, APNG):** The handling of multiple frames is directly related to animated images.

7. **Infer Logic and Reasoning:** For each test, think about *why* the test is written the way it is. What underlying logic of the `DeferredImageDecoder` is being verified?  Formulate "assumptions" and "outputs" based on the test's setup and assertions.

8. **Identify Potential User/Programming Errors:** Based on the functionality and the tests, consider common mistakes developers might make:
    * Assuming synchronous decoding.
    * Incorrectly handling partial image data.
    * Not considering the implications of decoding on different threads.
    * Misunderstanding how frame durations are handled for animations.

9. **Structure the Response:** Organize the information logically, using headings and bullet points for clarity. Address each part of the original request: functionality, relationship to web technologies, logic/reasoning, and common errors.

10. **Refine and Elaborate:** Review the generated response for accuracy, completeness, and clarity. Add more detail and examples where needed. For instance, when explaining the relationship to HTML, give concrete examples of the HTML code.

This step-by-step approach allows for a comprehensive understanding of the test file and its implications, leading to a well-structured and informative response. The key is to move from the general structure to the specific test cases and then connect the technical details back to the broader context of web development.
这个文件 `deferred_image_decoder_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `DeferredImageDecoder` 类的单元测试文件。它的主要功能是验证 `DeferredImageDecoder` 类的各种行为和功能是否符合预期。

以下是该文件的功能分解：

**1. 测试 `DeferredImageDecoder` 的核心功能:**

* **延迟解码:**  `DeferredImageDecoder` 的核心思想是延迟图像的解码，直到真正需要图像数据时才进行。这个测试文件验证了这种延迟行为。例如，在 `drawIntoPaintRecord` 测试中，图像数据被设置，但是直到 `canvas_->drawPicture()` 被调用时才可能触发实际的解码。
* **处理完整的和部分接收的图像数据:**  测试了 `DeferredImageDecoder` 如何处理完整接收的图像数据 (`drawIntoPaintRecord`) 和部分接收的图像数据 (`drawIntoPaintRecordProgressive`). 这对于网络加载的图片非常重要，因为数据是逐步到达的。
* **图像元数据:** 测试了图像的元数据信息，例如 `all_data_received_prior_to_decode`，这指示了图像解码器是否在接收到所有数据后才开始解码。这关系到性能优化。
* **多线程解码:**  `decodeOnOtherThread` 测试验证了图像解码是否可以在非主线程上进行，这有助于避免阻塞渲染主线程，提高用户体验。
* **单帧和多帧图像 (动画):**  `singleFrameImageLoading` 和 `multiFrameImageLoading` 测试分别验证了 `DeferredImageDecoder` 对静态图片和动画图片（例如 GIF）的处理，包括帧的接收状态、帧时长和循环次数。
* **解码后的大小:** `decodedSize` 测试验证了 `DeferredImageDecoder` 能否正确报告解码后的图像尺寸。
* **帧的透明度:** `frameOpacity` 测试验证了 `DeferredImageDecoder` 能否正确处理和报告图像帧的透明度信息。
* **获取原始数据:** `data` 测试验证了可以从 `DeferredImageDecoder` 中获取原始的图像数据。
* **`PaintImage` 集成:**  测试了 `DeferredImageDecoder` 如何与 `PaintImage` 类协同工作，`PaintImage` 是 Blink 中用于表示可绘制图像的类。这包括测试帧元数据 (`PaintImage` 测试用例) 和帧时长覆盖 (`FrameDurationOverride` 测试用例)。

**2. 使用 Mock 对象进行隔离测试:**

* 文件中使用了 `MockImageDecoder` 类来模拟真实的图像解码器。这样做的好处是可以隔离被测试的 `DeferredImageDecoder`，并精确控制模拟解码器的行为（例如，设置解码后的尺寸，返回帧状态等）。这使得测试更加可靠和可预测。

**3. 使用 Google Test 框架进行断言:**

* 文件使用了 `testing::Test` 作为测试基类，并使用 `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE` 等宏进行断言，验证实际结果是否与预期一致。

**与 JavaScript, HTML, CSS 的关系:**

`DeferredImageDecoder` 直接服务于在网页上显示图像的需求，因此与 JavaScript, HTML, CSS 都有密切关系：

* **HTML `<img>` 标签:** 当浏览器解析 HTML 遇到 `<img>` 标签时，会发起图像资源的请求。下载的图像数据会传递给 `DeferredImageDecoder` 进行处理和解码，最终渲染到页面上。
    * **举例:**  HTML 中有 `<img src="image.png">`，浏览器下载 `image.png` 的数据后，`DeferredImageDecoder` 会负责解码这个图像，以便在页面上显示。
* **CSS `background-image` 属性:** CSS 可以使用 `background-image` 属性来设置元素的背景图像。类似地，下载的背景图像数据也会由 `DeferredImageDecoder` 处理。
    * **举例:** CSS 中有 `body { background-image: url("background.jpg"); }`，`DeferredImageDecoder` 负责解码 `background.jpg`。
* **JavaScript `Image()` 对象:** JavaScript 可以通过 `Image()` 构造函数动态创建图像对象。当设置 `Image` 对象的 `src` 属性时，浏览器会下载图像，并使用 `DeferredImageDecoder` 进行处理。
    * **举例:**  JavaScript 代码 `const img = new Image(); img.src = 'dynamic.gif'; document.body.appendChild(img);`。`DeferredImageDecoder` 会处理 `dynamic.gif` 的解码。

**逻辑推理 (假设输入与输出):**

**假设输入 (以 `drawIntoPaintRecord` 为例):**

* **输入数据:**  `kWhitePNG` 数组表示的 PNG 图像数据。
* **操作:**
    1. 调用 `lazy_decoder_->SetData(data_, true /* all_data_received */)`，将完整的 PNG 数据设置到 `DeferredImageDecoder` 中。
    2. 创建一个 `PaintImage` 对象。
    3. 创建一个 `PaintRecorder` 和一个临时的 `PaintCanvas`。
    4. 在临时画布上绘制 `PaintImage`。
    5. 完成录制，得到 `PaintRecord`。
    6. 在主画布上绘制 `PaintRecord`。

**预期输出:**

* 在调用 `canvas_->drawPicture()` 之前，`decode_request_count_` 应该为 0，表示尚未触发解码。
* 在调用 `canvas_->drawPicture()` 之后，图像会被解码并绘制到 `bitmap_` 上。
* `bitmap_.getColor(0, 0)` 应该返回白色 (SkColorSetARGB(255, 255, 255, 255))，因为 `kWhitePNG` 代表一个白色的像素。

**涉及用户或者编程常见的使用错误 (举例说明):**

1. **假设图像数据已经完全加载:** 开发者可能会假设图像数据已经完全加载，并尝试立即使用解码后的数据，而忽略了 `DeferredImageDecoder` 的延迟特性。在网络不佳的情况下，这可能导致错误或不完整的渲染。
    * **错误示例 (JavaScript):**
      ```javascript
      const img = new Image();
      img.src = 'large_image.jpg';
      // 错误地假设图像已经加载完成
      const width = img.naturalWidth;
      const height = img.naturalHeight;
      console.log(`Image dimensions: ${width}x${height}`); // 可能为 0
      ```
      **正确做法:** 应该监听 `img.onload` 事件，确保图像加载完成后再访问其属性。

2. **在主线程上进行耗时的解码操作:**  虽然 `DeferredImageDecoder` 支持多线程解码，但如果开发者直接调用同步的解码方法，或者没有正确配置，仍然可能在主线程上进行耗时的解码操作，导致页面卡顿。
    * **错误示例 (假设 `DeferredImageDecoder` 有同步解码接口):**
      ```cpp
      // 假设存在同步解码接口 (实际上 Blink 中通常是异步的)
      SkBitmap bitmap = decoder->decodeSynchronously();
      // 如果图像很大，这会阻塞主线程
      canvas->drawBitmap(bitmap, 0, 0);
      ```
      **正确做法:** 利用 `DeferredImageDecoder` 的异步特性，或者将解码任务放到后台线程执行。

3. **不正确处理部分加载的图像:** 开发者可能没有考虑到图像是逐步加载的，只处理了完全加载的情况，导致在加载过程中页面显示不正常。
    * **错误示例 (假设有直接访问解码进度的接口):**
      ```javascript
      const img = new Image();
      img.src = 'very_large_image.png';
      // 尝试在加载过程中访问部分解码的数据 (可能不存在这样的直接接口)
      // 这样做可能会导致错误或不完整的图像
      // ...
      ```
      **正确做法:**  利用浏览器提供的图像加载事件（如 `progress`），或者依赖渲染引擎的机制来逐步渲染部分加载的图像。`DeferredImageDecoder` 就在幕后处理了这部分逻辑。

4. **混淆了 `PaintImage` 的状态:**  `PaintImage` 可能处于不同的完成状态（例如 `kPartiallyDone`, `kDone`）。开发者需要根据 `PaintImage` 的状态来判断图像是否已经完全解码可用。
    * **错误示例 (假设 `PaintImage` 有直接的解码完成标志):**
      ```cpp
      PaintImage image = decoder->createPaintImage();
      if (image->isDecoded()) { // 假设有这样的方法，但实际上可能需要检查 CompletionState
          // 使用解码后的图像
      }
      ```
      **正确做法:**  检查 `PaintImage::CompletionState()` 的返回值。

总而言之，`deferred_image_decoder_test.cc` 通过大量的单元测试用例，细致地验证了 `DeferredImageDecoder` 类的各种功能和边界情况，确保其在 Blink 渲染引擎中能够正确高效地处理图像解码任务，从而为用户提供流畅的网页浏览体验。

### 提示词
```
这是目录为blink/renderer/platform/graphics/deferred_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/graphics/deferred_image_decoder.h"

#include <memory>
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/image_decoding_store.h"
#include "third_party/blink/renderer/platform/graphics/image_frame_generator.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_image.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_image_decoder.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_skia.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkPixmap.h"
#include "third_party/skia/include/core/SkSurface.h"

namespace blink {

namespace {

// Raw data for a PNG file with 1x1 white pixels.
const unsigned char kWhitePNG[] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xde, 0x00, 0x00, 0x00,
    0x01, 0x73, 0x52, 0x47, 0x42, 0x00, 0xae, 0xce, 0x1c, 0xe9, 0x00, 0x00,
    0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0b, 0x13, 0x00, 0x00,
    0x0b, 0x13, 0x01, 0x00, 0x9a, 0x9c, 0x18, 0x00, 0x00, 0x00, 0x0c, 0x49,
    0x44, 0x41, 0x54, 0x08, 0xd7, 0x63, 0xf8, 0xff, 0xff, 0x3f, 0x00, 0x05,
    0xfe, 0x02, 0xfe, 0xdc, 0xcc, 0x59, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
};

// Raw data for a GIF file with 1x1 white pixels. Modified from animatedGIF.
const unsigned char kWhiteGIF[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0xf0, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xff, 0x0b, 0x4e, 0x45,
    0x54, 0x53, 0x43, 0x41, 0x50, 0x45, 0x32, 0x2e, 0x30, 0x03, 0x01, 0x00,
    0x00, 0x00, 0x21, 0xff, 0x0b, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x4d, 0x61,
    0x67, 0x69, 0x63, 0x6b, 0x0d, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x3d, 0x30,
    0x2e, 0x34, 0x35, 0x34, 0x35, 0x35, 0x00, 0x21, 0xff, 0x0b, 0x49, 0x6d,
    0x61, 0x67, 0x65, 0x4d, 0x61, 0x67, 0x69, 0x63, 0x6b, 0x0d, 0x67, 0x61,
    0x6d, 0x6d, 0x61, 0x3d, 0x30, 0x2e, 0x34, 0x35, 0x34, 0x35, 0x35, 0x00,
    0x21, 0xf9, 0x04, 0x00, 0x00, 0x00, 0xff, 0x00, 0x2c, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x4c, 0x01, 0x00, 0x3b};

}  // namespace

class DeferredImageDecoderTest : public testing::Test,
                                 public MockImageDecoderClient {
 public:
  void SetUp() override {
    paint_image_id_ = PaintImage::GetNextId();
    ImageDecodingStore::Instance().SetCacheLimitInBytes(1024 * 1024);
    data_ = SharedBuffer::Create(kWhitePNG, sizeof(kWhitePNG));
    original_data_ = data_->CopyAs<Vector<char>>();
    frame_count_ = 1;
    auto decoder = std::make_unique<MockImageDecoder>(this);
    actual_decoder_ = decoder.get();
    actual_decoder_->SetSize(1, 1);
    lazy_decoder_ = DeferredImageDecoder::CreateForTesting(std::move(decoder));
    bitmap_.allocPixels(SkImageInfo::MakeN32Premul(100, 100));
    canvas_ = std::make_unique<cc::SkiaPaintCanvas>(bitmap_);
    decode_request_count_ = 0;
    repetition_count_ = kAnimationNone;
    status_ = ImageFrame::kFrameComplete;
    frame_duration_ = base::TimeDelta();
    decoded_size_ = actual_decoder_->Size();
  }

  void TearDown() override { ImageDecodingStore::Instance().Clear(); }

  void DecoderBeingDestroyed() override { actual_decoder_ = nullptr; }

  void DecodeRequested() override { ++decode_request_count_; }

  wtf_size_t FrameCount() override { return frame_count_; }

  int RepetitionCount() const override { return repetition_count_; }

  ImageFrame::Status GetStatus(wtf_size_t index) override { return status_; }

  base::TimeDelta FrameDuration() const override { return frame_duration_; }

  gfx::Size DecodedSize() const override { return decoded_size_; }

  PaintImage CreatePaintImage(
      PaintImage::CompletionState state = PaintImage::CompletionState::kDone) {
    return CreatePaintImage(lazy_decoder_.get(), state);
  }

  PaintImage CreatePaintImage(
      DeferredImageDecoder* decoder,
      PaintImage::CompletionState state = PaintImage::CompletionState::kDone) {
    PaintImage::AnimationType type = FrameCount() > 1
                                         ? PaintImage::AnimationType::kAnimated
                                         : PaintImage::AnimationType::kStatic;

    return PaintImageBuilder::WithDefault()
        .set_id(paint_image_id_)
        .set_animation_type(type)
        .set_completion_state(state)
        .set_paint_image_generator(decoder->CreateGenerator())
        .TakePaintImage();
  }

 protected:
  void UseMockImageDecoderFactory() {
    lazy_decoder_->FrameGenerator()->SetImageDecoderFactory(
        MockImageDecoderFactory::Create(this, decoded_size_));
  }

  test::TaskEnvironment task_environment_;
  // Don't own this but saves the pointer to query states.
  PaintImage::Id paint_image_id_;
  raw_ptr<MockImageDecoder> actual_decoder_;
  std::unique_ptr<DeferredImageDecoder> lazy_decoder_;
  SkBitmap bitmap_;
  std::unique_ptr<cc::PaintCanvas> canvas_;
  int decode_request_count_;
  scoped_refptr<SharedBuffer> data_;
  Vector<char> original_data_;
  wtf_size_t frame_count_;
  int repetition_count_;
  ImageFrame::Status status_;
  base::TimeDelta frame_duration_;
  gfx::Size decoded_size_;
};

TEST_F(DeferredImageDecoderTest, drawIntoPaintRecord) {
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_EQ(1, image.width());
  EXPECT_EQ(1, image.height());

  PaintRecorder recorder;
  cc::PaintCanvas* temp_canvas = recorder.beginRecording();
  temp_canvas->drawImage(image, 0, 0);
  PaintRecord record = recorder.finishRecordingAsPicture();
  EXPECT_EQ(0, decode_request_count_);

  canvas_->drawPicture(std::move(record));
  EXPECT_EQ(0, decode_request_count_);
  EXPECT_EQ(SkColorSetARGB(255, 255, 255, 255), bitmap_.getColor(0, 0));
}

TEST_F(DeferredImageDecoderTest, drawIntoPaintRecordProgressive) {
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(original_data_.data(), original_data_.size() - 10);

  // Received only half the file.
  lazy_decoder_->SetData(partial_data, false /* all_data_received */);
  PaintRecorder recorder;
  cc::PaintCanvas* temp_canvas = recorder.beginRecording();
  PaintImage image =
      CreatePaintImage(PaintImage::CompletionState::kPartiallyDone);
  ASSERT_TRUE(image);
  temp_canvas->drawImage(image, 0, 0);
  canvas_->drawPicture(recorder.finishRecordingAsPicture());

  // Fully received the file and draw the PaintRecord again.
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  image = CreatePaintImage();
  ASSERT_TRUE(image);
  temp_canvas = recorder.beginRecording();
  temp_canvas->drawImage(image, 0, 0);
  canvas_->drawPicture(recorder.finishRecordingAsPicture());
  EXPECT_EQ(SkColorSetARGB(255, 255, 255, 255), bitmap_.getColor(0, 0));
}

TEST_F(DeferredImageDecoderTest, allDataReceivedPriorToDecodeNonIncrementally) {
  // The image is received completely at once.
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  ASSERT_TRUE(image.GetImageHeaderMetadata());
  EXPECT_TRUE(
      image.GetImageHeaderMetadata()->all_data_received_prior_to_decode);
}

TEST_F(DeferredImageDecoderTest, allDataReceivedPriorToDecodeIncrementally) {
  // The image is received in two parts, but a PaintImageGenerator is created
  // only after all the data is received.
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(original_data_.data(), original_data_.size() - 10);
  lazy_decoder_->SetData(partial_data, false /* all_data_received */);
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  ASSERT_TRUE(image.GetImageHeaderMetadata());
  EXPECT_TRUE(
      image.GetImageHeaderMetadata()->all_data_received_prior_to_decode);
}

TEST_F(DeferredImageDecoderTest, notAllDataReceivedPriorToDecode) {
  // The image is received in two parts, and a PaintImageGenerator is created
  // for each one. In real usage, it's likely that the software image decoder
  // will start working with partial data.
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(original_data_.data(), original_data_.size() - 10);
  lazy_decoder_->SetData(partial_data, false /* all_data_received */);
  PaintImage image =
      CreatePaintImage(PaintImage::CompletionState::kPartiallyDone);
  ASSERT_TRUE(image);
  ASSERT_TRUE(image.GetImageHeaderMetadata());
  EXPECT_FALSE(
      image.GetImageHeaderMetadata()->all_data_received_prior_to_decode);

  lazy_decoder_->SetData(data_, true /* all_data_received */);
  image = CreatePaintImage();
  ASSERT_TRUE(image);
  ASSERT_TRUE(image.GetImageHeaderMetadata());
  EXPECT_FALSE(
      image.GetImageHeaderMetadata()->all_data_received_prior_to_decode);
}

static void RasterizeMain(cc::PaintCanvas* canvas, PaintRecord record) {
  canvas->drawPicture(std::move(record));
}

// Flaky on Mac. crbug.com/792540.
#if BUILDFLAG(IS_MAC)
#define MAYBE_decodeOnOtherThread DISABLED_decodeOnOtherThread
#else
#define MAYBE_decodeOnOtherThread decodeOnOtherThread
#endif
TEST_F(DeferredImageDecoderTest, MAYBE_decodeOnOtherThread) {
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_EQ(1, image.width());
  EXPECT_EQ(1, image.height());

  PaintRecorder recorder;
  cc::PaintCanvas* temp_canvas = recorder.beginRecording();
  temp_canvas->drawImage(image, 0, 0);
  PaintRecord record = recorder.finishRecordingAsPicture();
  EXPECT_EQ(0, decode_request_count_);

  // Create a thread to rasterize PaintRecord.
  std::unique_ptr<NonMainThread> thread =
      NonMainThread::CreateThread(ThreadCreationParams(ThreadType::kTestThread)
                                      .SetThreadNameForTest("RasterThread"));
  PostCrossThreadTask(
      *thread->GetTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(&RasterizeMain, CrossThreadUnretained(canvas_.get()),
                          record));
  thread.reset();
  EXPECT_EQ(0, decode_request_count_);
  EXPECT_EQ(SkColorSetARGB(255, 255, 255, 255), bitmap_.getColor(0, 0));
}

TEST_F(DeferredImageDecoderTest, singleFrameImageLoading) {
  status_ = ImageFrame::kFramePartial;
  lazy_decoder_->SetData(data_, false /* all_data_received */);
  EXPECT_FALSE(lazy_decoder_->FrameIsReceivedAtIndex(0));
  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_FALSE(lazy_decoder_->FrameIsReceivedAtIndex(0));
  EXPECT_TRUE(actual_decoder_);

  status_ = ImageFrame::kFrameComplete;
  data_->Append(" ", 1u);
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  EXPECT_FALSE(actual_decoder_);
  EXPECT_TRUE(lazy_decoder_->FrameIsReceivedAtIndex(0));

  image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_FALSE(decode_request_count_);
}

TEST_F(DeferredImageDecoderTest, multiFrameImageLoading) {
  repetition_count_ = 10;
  frame_count_ = 1;
  frame_duration_ = base::Milliseconds(10);
  status_ = ImageFrame::kFramePartial;
  lazy_decoder_->SetData(data_, false /* all_data_received */);

  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_FALSE(lazy_decoder_->FrameIsReceivedAtIndex(0));
  // Anything <= 10ms is clamped to 100ms. See the implementation for details.
  EXPECT_EQ(base::Milliseconds(100), lazy_decoder_->FrameDurationAtIndex(0));

  frame_count_ = 2;
  frame_duration_ = base::Milliseconds(20);
  status_ = ImageFrame::kFrameComplete;
  data_->Append(" ", 1u);
  lazy_decoder_->SetData(data_, false /* all_data_received */);

  image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_TRUE(lazy_decoder_->FrameIsReceivedAtIndex(0));
  EXPECT_TRUE(lazy_decoder_->FrameIsReceivedAtIndex(1));
  EXPECT_EQ(base::Milliseconds(20), lazy_decoder_->FrameDurationAtIndex(1));
  EXPECT_TRUE(actual_decoder_);

  frame_count_ = 3;
  frame_duration_ = base::Milliseconds(30);
  status_ = ImageFrame::kFrameComplete;
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  EXPECT_FALSE(actual_decoder_);
  EXPECT_TRUE(lazy_decoder_->FrameIsReceivedAtIndex(0));
  EXPECT_TRUE(lazy_decoder_->FrameIsReceivedAtIndex(1));
  EXPECT_TRUE(lazy_decoder_->FrameIsReceivedAtIndex(2));
  EXPECT_EQ(base::Milliseconds(100), lazy_decoder_->FrameDurationAtIndex(0));
  EXPECT_EQ(base::Milliseconds(20), lazy_decoder_->FrameDurationAtIndex(1));
  EXPECT_EQ(base::Milliseconds(30), lazy_decoder_->FrameDurationAtIndex(2));
  EXPECT_EQ(10, lazy_decoder_->RepetitionCount());
}

TEST_F(DeferredImageDecoderTest, decodedSize) {
  decoded_size_ = gfx::Size(22, 33);
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_EQ(decoded_size_.width(), image.width());
  EXPECT_EQ(decoded_size_.height(), image.height());

  UseMockImageDecoderFactory();

  // The following code should not fail any assert.
  PaintRecorder recorder;
  cc::PaintCanvas* temp_canvas = recorder.beginRecording();
  temp_canvas->drawImage(image, 0, 0);
  PaintRecord record = recorder.finishRecordingAsPicture();
  EXPECT_EQ(0, decode_request_count_);
  canvas_->drawPicture(std::move(record));
  EXPECT_EQ(1, decode_request_count_);
}

TEST_F(DeferredImageDecoderTest, smallerFrameCount) {
  frame_count_ = 1;
  lazy_decoder_->SetData(data_, false /* all_data_received */);
  EXPECT_EQ(frame_count_, lazy_decoder_->FrameCount());
  frame_count_ = 2;
  lazy_decoder_->SetData(data_, false /* all_data_received */);
  EXPECT_EQ(frame_count_, lazy_decoder_->FrameCount());
  frame_count_ = 0;
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  EXPECT_EQ(frame_count_, lazy_decoder_->FrameCount());
}

TEST_F(DeferredImageDecoderTest, frameOpacity) {
  for (bool test_gif : {false, true}) {
    if (test_gif)
      data_ = SharedBuffer::Create(kWhiteGIF, sizeof(kWhiteGIF));

    std::unique_ptr<DeferredImageDecoder> decoder =
        DeferredImageDecoder::Create(data_, true,
                                     ImageDecoder::kAlphaPremultiplied,
                                     ColorBehavior::kTransformToSRGB);

    SkImageInfo pix_info = SkImageInfo::MakeN32Premul(1, 1);

    size_t row_bytes = pix_info.minRowBytes();
    size_t size = pix_info.computeByteSize(row_bytes);

    Vector<char> storage(base::checked_cast<wtf_size_t>(size));
    SkPixmap pixmap(pix_info, storage.data(), row_bytes);

    // Before decoding, the frame is not known to be opaque.
    sk_sp<SkImage> frame = CreatePaintImage(decoder.get()).GetSwSkImage();
    ASSERT_TRUE(frame);
    EXPECT_FALSE(frame->isOpaque());
    EXPECT_EQ(decoder->AlphaType(), kPremul_SkAlphaType);

    // Force a lazy decode by reading pixels.
    EXPECT_TRUE(frame->readPixels(pixmap, 0, 0));

    // After decoding, the frame is known to be opaque.
    EXPECT_EQ(decoder->AlphaType(), kOpaque_SkAlphaType);
    frame = CreatePaintImage(decoder.get()).GetSwSkImage();
    ASSERT_TRUE(frame);
    EXPECT_TRUE(frame->isOpaque());

    // Re-generating the opaque-marked frame should not fail.
    EXPECT_TRUE(frame->readPixels(pixmap, 0, 0));
  }
}

TEST_F(DeferredImageDecoderTest, data) {
  Vector<char> data_binary = data_->CopyAs<Vector<char>>();
  scoped_refptr<SharedBuffer> original_buffer =
      SharedBuffer::Create(data_binary.data(), data_binary.size());
  EXPECT_EQ(original_buffer->size(), data_binary.size());
  lazy_decoder_->SetData(original_buffer, false /* all_data_received */);
  scoped_refptr<SharedBuffer> new_buffer = lazy_decoder_->Data();
  EXPECT_EQ(original_buffer->size(), new_buffer->size());
  const Vector<char> original_data = original_buffer->CopyAs<Vector<char>>();
  const Vector<char> new_data = new_buffer->CopyAs<Vector<char>>();
  EXPECT_EQ(0, std::memcmp(original_data.data(), new_data.data(),
                           new_buffer->size()));
}

class MultiFrameDeferredImageDecoderTest : public DeferredImageDecoderTest {
 public:
  ImageFrame::Status GetStatus(wtf_size_t index) override {
    return index > last_complete_frame_ ? ImageFrame::Status::kFramePartial
                                        : ImageFrame::Status::kFrameComplete;
  }

  wtf_size_t last_complete_frame_ = 0u;
};

TEST_F(MultiFrameDeferredImageDecoderTest, PaintImage) {
  frame_count_ = 2;
  frame_duration_ = base::Milliseconds(20);
  last_complete_frame_ = 0u;
  lazy_decoder_->SetData(data_, false /* all_data_received */);

  // Only the first frame is complete.
  PaintImage image = CreatePaintImage();
  ASSERT_TRUE(image);
  EXPECT_EQ(image.GetFrameMetadata().size(), 2u);
  EXPECT_TRUE(image.GetFrameMetadata()[0].complete);
  EXPECT_FALSE(image.GetFrameMetadata()[1].complete);
  EXPECT_EQ(image.GetFrameMetadata()[0].duration, frame_duration_);
  EXPECT_EQ(image.GetFrameMetadata()[1].duration, frame_duration_);

  auto frame0_key = image.GetKeyForFrame(0);
  auto frame1_key = image.GetKeyForFrame(1);
  EXPECT_NE(frame0_key, frame1_key);

  // Send some more data but the frame status remains the same.
  last_complete_frame_ = 0u;
  lazy_decoder_->SetData(data_, false /* all_data_received */);
  PaintImage updated_image = CreatePaintImage();
  ASSERT_TRUE(updated_image);
  EXPECT_EQ(updated_image.GetFrameMetadata().size(), 2u);
  EXPECT_TRUE(updated_image.GetFrameMetadata()[0].complete);
  EXPECT_FALSE(updated_image.GetFrameMetadata()[1].complete);

  // Since the first frame was complete, the key remains constant. While the
  // second frame generates a new key after it is updated.
  auto updated_frame0_key = updated_image.GetKeyForFrame(0);
  auto updated_frame1_key = updated_image.GetKeyForFrame(1);
  EXPECT_NE(updated_frame0_key, updated_frame1_key);
  EXPECT_EQ(updated_frame0_key, frame0_key);
  EXPECT_NE(updated_frame1_key, frame1_key);

  // Mark all frames complete.
  last_complete_frame_ = 1u;
  lazy_decoder_->SetData(data_, true /* all_data_received */);
  PaintImage complete_image = CreatePaintImage();
  ASSERT_TRUE(complete_image);
  EXPECT_EQ(complete_image.GetFrameMetadata().size(), 2u);
  EXPECT_TRUE(complete_image.GetFrameMetadata()[0].complete);
  EXPECT_TRUE(complete_image.GetFrameMetadata()[1].complete);

  auto complete_frame0_key = complete_image.GetKeyForFrame(0);
  auto complete_frame1_key = complete_image.GetKeyForFrame(1);
  EXPECT_NE(complete_frame0_key, complete_frame1_key);
  EXPECT_EQ(updated_frame0_key, complete_frame0_key);
  EXPECT_NE(updated_frame1_key, complete_frame1_key);
}

TEST_F(MultiFrameDeferredImageDecoderTest, FrameDurationOverride) {
  frame_count_ = 2;
  frame_duration_ = base::Milliseconds(5);
  last_complete_frame_ = 1u;
  lazy_decoder_->SetData(data_, true /* all_data_received */);

  // If the frame duration is below a threshold, we override it to a constant
  // value of 100 ms.
  PaintImage image = CreatePaintImage();
  EXPECT_EQ(image.GetFrameMetadata()[0].duration, base::Milliseconds(100));
  EXPECT_EQ(image.GetFrameMetadata()[1].duration, base::Milliseconds(100));
}

}  // namespace blink
```