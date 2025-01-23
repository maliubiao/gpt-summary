Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The request is to understand the purpose of the `image_decoding_store_test.cc` file. This immediately tells me it's a test file for something called `ImageDecodingStore`.

2. **Identify the Core Subject:**  The name of the file and the included header `#include "third_party/blink/renderer/platform/graphics/image_decoding_store.h"`  clearly point to `ImageDecodingStore` as the central component being tested.

3. **Scan for Key Actions/Methods:** Look for verbs and nouns related to the likely functionality of an image decoding store. I expect actions like "insert," "evict," "remove," "lock," "unlock," and concepts like "cache," "memory usage," and "decoder."  A quick scan of the test methods confirms these expectations: `insertDecoder`, `evictDecoder`, `removeDecoder`, `LockDecoder`, `UnlockDecoder`, `OnMemoryPressure`.

4. **Analyze Individual Test Cases:**  Go through each `TEST_F` function and determine what it's testing. For each test:
    * **Setup:** What is being initialized?  Look for `SetUp()` and local variable initializations.
    * **Action:** What operation is being performed on the `image_decoding_store_`?
    * **Assertion:** What is the expected outcome, verified using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`?

5. **Infer Functionality of `ImageDecodingStore`:** Based on the test cases, build a mental model of what `ImageDecodingStore` does.
    * **Caching:** It stores decoded image data (represented by `MockImageDecoder`).
    * **Insertion:**  It allows adding decoders with associated information (generator, client ID).
    * **Retrieval (Lock/Unlock):** It provides a way to retrieve (lock) a decoder based on certain criteria (generator, size, alpha type, client ID) and release it (unlock). The lock mechanism suggests it handles concurrency or prevents premature eviction.
    * **Eviction:** It manages memory by evicting decoders when the cache limit is reached or under memory pressure. The "in use not evicted" test is crucial here.
    * **Removal:** It allows explicit removal of decoders.
    * **Multiple Clients:** It supports multiple clients potentially requesting the same image data.
    * **Memory Pressure Handling:** It reacts to system memory pressure signals.

6. **Consider Connections to Web Technologies (JavaScript, HTML, CSS):**  Think about how image decoding fits into a web browser.
    * **HTML `<img>` tag:**  The most direct connection. The browser needs to decode the image data to display it.
    * **CSS `background-image`:** Similar to `<img>`, CSS can use images.
    * **JavaScript `Image()` object:** JavaScript can programmatically load and manipulate images.
    * **Canvas API:** Drawing images onto a canvas requires decoding.

7. **Provide Examples:**  Illustrate the connections with concrete examples. Think about a scenario where the store's behavior would be relevant. For instance, rapidly switching between images or having multiple elements use the same image.

8. **Identify Potential User/Programming Errors:**  Think about how someone using or relying on a system like this might make mistakes.
    * **Assuming Immediate Availability:**  The locking mechanism suggests that a decoder might not always be available immediately.
    * **Memory Leaks (less relevant here but a general consideration):** While the store manages memory, incorrect usage *around* the store could lead to leaks (although the tests seem designed to prevent leaks *within* the store).
    * **Incorrect Keys:**  Providing the wrong generator, size, or alpha type when trying to retrieve a decoder would be an error.

9. **Hypothesize Input and Output (Logical Reasoning):**  Choose a test case that demonstrates a key behavior and describe the input (the setup and actions) and the expected output (the assertions). This makes the test's logic clearer.

10. **Structure and Refine:** Organize the information logically. Start with the main purpose, then delve into details, connections to web tech, potential errors, and examples. Use clear and concise language. Use formatting (like bullet points) to improve readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe it just stores the raw image bytes. **Correction:** The tests talk about *decoders*, which are objects that *process* image data, not just the raw bytes.
* **Focusing too much on implementation details:** While the C++ code is there, the goal is to explain the *functionality*. Avoid getting bogged down in the specifics of `SkISize` or `cc::PaintImage`. Focus on the *what* and *why*.
* **Vague connections to web tech:**  Initially, I might just say "it's used for displaying images." **Refinement:** Provide specific examples like the `<img>` tag and CSS `background-image`.

By following these steps and engaging in some self-correction, we can arrive at a comprehensive and accurate explanation of the test file's purpose and its relationship to the broader context of web browser functionality.
这个文件 `image_decoding_store_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件。它的主要功能是 **测试 `ImageDecodingStore` 类的功能和行为**。

`ImageDecodingStore` 的作用是作为一个缓存，存储已经解码的图像数据（更准确地说，是 `ImageDecoder` 对象）。这样做是为了提高性能，避免重复解码相同的图像。

下面我们来详细列举一下它测试的功能，并分析它与 JavaScript、HTML 和 CSS 的关系，以及可能的用户或编程错误。

**`image_decoding_store_test.cc` 测试的功能：**

1. **插入解码器 (`insertDecoder` 测试):**
   - 验证 `ImageDecodingStore::InsertDecoder` 方法是否能正确地将一个 `ImageDecoder` 对象添加到缓存中。
   - **假设输入:**  一个 `ImageFrameGenerator` 对象和一个 `MockImageDecoder` 对象。
   - **预期输出:** 缓存中条目数量增加，内存使用量相应增加。

2. **驱逐解码器 (`evictDecoder` 测试):**
   - 验证当缓存达到容量限制时，`ImageDecodingStore` 是否能正确地移除（驱逐）缓存中的解码器。
   - `EvictOneCache()` 方法模拟触发缓存驱逐。
   - **假设输入:**  缓存中已存在多个解码器，并设置较低的缓存限制。
   - **预期输出:** 缓存中条目数量减少，内存使用量相应减少。

3. **正在使用的解码器不会被驱逐 (`decoderInUseNotEvicted` 测试):**
   - 验证当一个解码器正在被使用（通过 `LockDecoder` 获取）时，即使触发缓存驱逐，它也不会被移除。
   - **假设输入:**  缓存中存在多个解码器，其中一个通过 `LockDecoder` 被锁定。触发多次驱逐操作。
   - **预期输出:**  被锁定的解码器仍然存在于缓存中，直到被 `UnlockDecoder` 释放。

4. **移除解码器 (`removeDecoder` 测试):**
   - 验证 `ImageDecodingStore::RemoveDecoder` 方法是否能显式地从缓存中移除指定的解码器。
   - **假设输入:**  一个 `ImageFrameGenerator` 对象和一个已添加到缓存的 `MockImageDecoder` 对象。
   - **预期输出:**  缓存中条目数量减少，内存使用量相应减少。

5. **同一生成器的多个客户端 (`MultipleClientsForSameGenerator` 测试):**
   - 验证 `ImageDecodingStore` 是否能为同一个 `ImageFrameGenerator` 存储来自不同客户端的解码器。
   - 这涉及到使用不同的 `cc::PaintImage::GeneratorClientId`。
   - **假设输入:**  相同的 `ImageFrameGenerator`，但使用不同的客户端 ID 插入多个解码器。
   - **预期输出:**  缓存中存在与不同客户端 ID 关联的多个解码器实例。可以通过客户端 ID 锁定和移除特定的解码器。

6. **内存压力下的行为 (`OnMemoryPressure` 测试):**
   - 验证当系统发出内存压力通知时，`ImageDecodingStore` 是否能释放缓存中的解码器以降低内存使用。
   - 使用 `base::MemoryPressureListener::SimulatePressureNotification` 模拟内存压力。
   - **假设输入:**  缓存中已存在解码器。模拟中度和临界内存压力。
   - **预期输出:**  在中度内存压力下可能没有变化（具体行为取决于实现细节），但在临界内存压力下，缓存中的条目会被清除。

**与 JavaScript, HTML, CSS 的关系：**

`ImageDecodingStore` 本身是一个底层的 C++ 组件，JavaScript、HTML 和 CSS 无法直接操作它。但是，它的功能直接影响到这些 Web 技术中图像的渲染性能。

* **HTML `<img>` 标签:** 当浏览器解析到 `<img>` 标签并需要显示图像时，Blink 引擎会加载图像数据并解码。`ImageDecodingStore` 可以缓存这些解码后的图像数据。如果页面上多次使用相同的图片，或者用户返回浏览之前看过的包含相同图片的页面，`ImageDecodingStore` 可以避免重复解码，提高页面加载速度。

   **举例说明:** 假设一个 HTML 页面包含多个 `<img>` 标签，它们都指向同一个图片 URL。如果没有 `ImageDecodingStore`，浏览器可能需要多次解码这张图片。有了 `ImageDecodingStore`，第一次解码后，后续的 `<img>` 标签可以直接从缓存中获取已解码的数据，无需再次解码。

* **CSS `background-image` 属性:** 与 `<img>` 标签类似，CSS 的 `background-image` 也会触发图像的加载和解码。`ImageDecodingStore` 同样可以缓存这些解码后的背景图像数据。

   **举例说明:** 一个网站的导航栏使用了相同的背景图片。`ImageDecodingStore` 可以确保该背景图片只被解码一次，提高页面渲染效率。

* **JavaScript 操作图像:** JavaScript 可以通过 `Image()` 对象或者 Canvas API 加载和操作图像。Blink 引擎在处理这些操作时，也会使用底层的图像解码机制，因此 `ImageDecodingStore` 的缓存功能对 JavaScript 操作图像的性能也有影响。

   **举例说明:** 一个 JavaScript 编写的图片轮播功能，如果连续展示相同的图片，`ImageDecodingStore` 可以避免重复解码，使轮播动画更加流畅。

**逻辑推理的假设输入与输出：**

以 `insertDecoder` 测试为例：

* **假设输入:**
    * `image_decoding_store_`: 一个空的 `ImageDecodingStore` 对象。
    * `generator_`: 一个 `ImageFrameGenerator` 对象，代表图像的来源。
    * `decoder`: 一个 `MockImageDecoder` 对象，模拟已解码的图像数据。
    * `client_id`: `cc::PaintImage::kDefaultGeneratorClientId`。
* **预期输出:**
    * 调用 `image_decoding_store_.InsertDecoder(generator_.get(), client_id, std::move(decoder))` 后，`image_decoding_store_.CacheEntries()` 返回 1，表示缓存中有一个条目。
    * `image_decoding_store_.MemoryUsageInBytes()` 返回一个非零值（在本例中是 `4u`），表示缓存占用的内存。
    * 后续使用相同的 `generator_` 和尺寸等信息调用 `image_decoding_store_.LockDecoder` 应该能成功获取到之前插入的解码器。

**涉及用户或者编程常见的使用错误：**

尽管用户和程序员不直接与 `ImageDecodingStore` 交互，但其背后的逻辑可能会导致一些间接的使用错误或需要注意的地方：

1. **过度依赖缓存的即时性:**  开发者不能假设解码后的图像总是立即存在于缓存中。例如，在内存压力大的情况下，缓存可能会被清理。因此，在需要图像数据时，总是需要考虑图像可能需要重新解码的情况。

2. **内存管理不当 (与 `ImageDecodingStore` 相关的间接错误):** 虽然 `ImageDecodingStore` 负责管理其自身的缓存，但在 Blink 引擎的其他部分，如果对图像资源的管理不当，仍然可能导致内存泄漏。例如，如果 `ImageFrameGenerator` 对象被意外地释放，那么与它关联的缓存条目可能无法正确清理。

3. **错误的缓存键 (内部错误):**  `ImageDecodingStore` 使用 `ImageFrameGenerator` 和其他信息作为缓存的键。如果这些键的生成逻辑出现错误，可能会导致相同的图像被错误地缓存多次，或者无法正确地命中缓存。这通常是 Blink 引擎内部的 bug，而不是用户直接操作导致的。

4. **假设缓存无限大:**  开发者不应该假设 `ImageDecodingStore` 的缓存是无限大的。当加载大量不同的图像时，缓存可能会被填满，导致旧的图像被驱逐。这可能会影响性能，特别是对于频繁切换不同图片的场景。

总而言之，`image_decoding_store_test.cc` 这个文件通过一系列单元测试，确保了 `ImageDecodingStore` 作为一个高效的图像解码缓存，能够正确地存储、检索和管理解码后的图像数据，从而提升 Chromium 浏览器的渲染性能，最终惠及用户浏览网页的体验。

### 提示词
```
这是目录为blink/renderer/platform/graphics/image_decoding_store_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/graphics/image_decoding_store.h"

#include <memory>
#include "base/memory/memory_pressure_listener.h"
#include "base/run_loop.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/image_frame_generator.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_image_decoder.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

class ImageDecodingStoreTest : public testing::Test,
                               public MockImageDecoderClient {
 public:
  void SetUp() override {
    image_decoding_store_.SetCacheLimitInBytes(1024 * 1024);
    generator_ = ImageFrameGenerator::Create(SkISize::Make(100, 100), true,
                                             ColorBehavior::kIgnore,
                                             cc::AuxImage::kDefault, {});
    decoders_destroyed_ = 0;
  }

  void TearDown() override { image_decoding_store_.Clear(); }

  void DecoderBeingDestroyed() override { ++decoders_destroyed_; }

  void DecodeRequested() override {
    // Decoder is never used by ImageDecodingStore.
    ASSERT_TRUE(false);
  }

  ImageFrame::Status GetStatus(wtf_size_t index) override {
    return ImageFrame::kFramePartial;
  }

  wtf_size_t FrameCount() override { return 1; }
  int RepetitionCount() const override { return kAnimationNone; }
  base::TimeDelta FrameDuration() const override { return base::TimeDelta(); }

 protected:
  void EvictOneCache() {
    size_t memory_usage_in_bytes = image_decoding_store_.MemoryUsageInBytes();
    if (memory_usage_in_bytes)
      image_decoding_store_.SetCacheLimitInBytes(memory_usage_in_bytes - 1);
    else
      image_decoding_store_.SetCacheLimitInBytes(0);
  }

  test::TaskEnvironment task_environment_;
  ImageDecodingStore image_decoding_store_;
  scoped_refptr<ImageFrameGenerator> generator_;
  int decoders_destroyed_;
};

TEST_F(ImageDecodingStoreTest, insertDecoder) {
  const SkISize size = SkISize::Make(1, 1);
  auto decoder = std::make_unique<MockImageDecoder>(this);
  decoder->SetSize(1, 1);
  const ImageDecoder* ref_decoder = decoder.get();
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder));
  EXPECT_EQ(1, image_decoding_store_.CacheEntries());
  EXPECT_EQ(4u, image_decoding_store_.MemoryUsageInBytes());

  ImageDecoder* test_decoder;
  EXPECT_TRUE(image_decoding_store_.LockDecoder(
      generator_.get(), size, ImageDecoder::kAlphaPremultiplied,
      cc::PaintImage::kDefaultGeneratorClientId, &test_decoder));
  EXPECT_TRUE(test_decoder);
  EXPECT_EQ(ref_decoder, test_decoder);
  image_decoding_store_.UnlockDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      test_decoder);
  EXPECT_EQ(1, image_decoding_store_.CacheEntries());
}

TEST_F(ImageDecodingStoreTest, evictDecoder) {
  auto decoder1 = std::make_unique<MockImageDecoder>(this);
  auto decoder2 = std::make_unique<MockImageDecoder>(this);
  auto decoder3 = std::make_unique<MockImageDecoder>(this);
  decoder1->SetSize(1, 1);
  decoder2->SetSize(2, 2);
  decoder3->SetSize(3, 3);
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder1));
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder2));
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder3));
  EXPECT_EQ(3, image_decoding_store_.CacheEntries());
  EXPECT_EQ(56u, image_decoding_store_.MemoryUsageInBytes());

  EvictOneCache();
  EXPECT_EQ(2, image_decoding_store_.CacheEntries());
  EXPECT_EQ(52u, image_decoding_store_.MemoryUsageInBytes());

  EvictOneCache();
  EXPECT_EQ(1, image_decoding_store_.CacheEntries());
  EXPECT_EQ(36u, image_decoding_store_.MemoryUsageInBytes());

  EvictOneCache();
  EXPECT_FALSE(image_decoding_store_.CacheEntries());
  EXPECT_FALSE(image_decoding_store_.MemoryUsageInBytes());
}

TEST_F(ImageDecodingStoreTest, decoderInUseNotEvicted) {
  auto decoder1 = std::make_unique<MockImageDecoder>(this);
  auto decoder2 = std::make_unique<MockImageDecoder>(this);
  auto decoder3 = std::make_unique<MockImageDecoder>(this);
  decoder1->SetSize(1, 1);
  decoder2->SetSize(2, 2);
  decoder3->SetSize(3, 3);
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder1));
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder2));
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder3));
  EXPECT_EQ(3, image_decoding_store_.CacheEntries());

  ImageDecoder* test_decoder;
  EXPECT_TRUE(image_decoding_store_.LockDecoder(
      generator_.get(), SkISize::Make(2, 2), ImageDecoder::kAlphaPremultiplied,
      cc::PaintImage::kDefaultGeneratorClientId, &test_decoder));

  EvictOneCache();
  EvictOneCache();
  EvictOneCache();
  EXPECT_EQ(1, image_decoding_store_.CacheEntries());
  EXPECT_EQ(16u, image_decoding_store_.MemoryUsageInBytes());

  image_decoding_store_.UnlockDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      test_decoder);
  EvictOneCache();
  EXPECT_FALSE(image_decoding_store_.CacheEntries());
  EXPECT_FALSE(image_decoding_store_.MemoryUsageInBytes());
}

TEST_F(ImageDecodingStoreTest, removeDecoder) {
  const SkISize size = SkISize::Make(1, 1);
  auto decoder = std::make_unique<MockImageDecoder>(this);
  decoder->SetSize(1, 1);
  const ImageDecoder* ref_decoder = decoder.get();
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder));
  EXPECT_EQ(1, image_decoding_store_.CacheEntries());
  EXPECT_EQ(4u, image_decoding_store_.MemoryUsageInBytes());

  ImageDecoder* test_decoder;
  EXPECT_TRUE(image_decoding_store_.LockDecoder(
      generator_.get(), size, ImageDecoder::kAlphaPremultiplied,
      cc::PaintImage::kDefaultGeneratorClientId, &test_decoder));
  EXPECT_TRUE(test_decoder);
  EXPECT_EQ(ref_decoder, test_decoder);
  image_decoding_store_.RemoveDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      test_decoder);
  EXPECT_FALSE(image_decoding_store_.CacheEntries());

  EXPECT_FALSE(image_decoding_store_.LockDecoder(
      generator_.get(), size, ImageDecoder::kAlphaPremultiplied,
      cc::PaintImage::kDefaultGeneratorClientId, &test_decoder));
}

TEST_F(ImageDecodingStoreTest, MultipleClientsForSameGenerator) {
  image_decoding_store_.Clear();
  ASSERT_EQ(image_decoding_store_.CacheEntries(), 0);

  const SkISize size = SkISize::Make(1, 1);

  auto decoder = std::make_unique<MockImageDecoder>(this);
  ImageDecoder* decoder_1 = decoder.get();
  decoder_1->SetSize(1, 1);
  auto client_id_1 = cc::PaintImage::GetNextGeneratorClientId();
  image_decoding_store_.InsertDecoder(generator_.get(), client_id_1,
                                      std::move(decoder));
  EXPECT_EQ(image_decoding_store_.CacheEntries(), 1);

  decoder = std::make_unique<MockImageDecoder>(this);
  ImageDecoder* decoder_2 = decoder.get();
  decoder_2->SetSize(1, 1);
  auto client_id_2 = cc::PaintImage::GetNextGeneratorClientId();
  image_decoding_store_.InsertDecoder(generator_.get(), client_id_2,
                                      std::move(decoder));
  EXPECT_EQ(image_decoding_store_.CacheEntries(), 2);

  ImageDecoder* cached_decoder = nullptr;
  image_decoding_store_.LockDecoder(generator_.get(), size,
                                    ImageDecoder::kAlphaPremultiplied,
                                    client_id_1, &cached_decoder);
  EXPECT_EQ(decoder_1, cached_decoder);

  image_decoding_store_.LockDecoder(generator_.get(), size,
                                    ImageDecoder::kAlphaPremultiplied,
                                    client_id_2, &cached_decoder);
  EXPECT_EQ(decoder_2, cached_decoder);

  image_decoding_store_.RemoveDecoder(generator_.get(), client_id_1, decoder_1);
  image_decoding_store_.RemoveDecoder(generator_.get(), client_id_2, decoder_2);
  EXPECT_EQ(image_decoding_store_.CacheEntries(), 0);
}

TEST_F(ImageDecodingStoreTest, OnMemoryPressure) {
  auto decoder = std::make_unique<MockImageDecoder>(this);
  decoder->SetSize(1, 1);
  image_decoding_store_.InsertDecoder(generator_.get(),
                                      cc::PaintImage::kDefaultGeneratorClientId,
                                      std::move(decoder));
  EXPECT_EQ(1, image_decoding_store_.CacheEntries());
  EXPECT_EQ(4u, image_decoding_store_.MemoryUsageInBytes());

  base::MemoryPressureListener::SimulatePressureNotification(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, image_decoding_store_.CacheEntries());
  EXPECT_EQ(4u, image_decoding_store_.MemoryUsageInBytes());

  base::MemoryPressureListener::SimulatePressureNotification(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, image_decoding_store_.CacheEntries());
  EXPECT_EQ(0u, image_decoding_store_.MemoryUsageInBytes());
}

}  // namespace blink
```