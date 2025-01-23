Response:
My thinking process to analyze the C++ test file and generate the explanation went through these stages:

1. **Understand the Core Purpose:** The filename `image_bitmap_test.cc` immediately suggests this is a test file for the `ImageBitmap` functionality within the Blink rendering engine. The `_test.cc` convention is a strong indicator of unit or integration tests.

2. **Identify Key Classes and Concepts:** I scanned the included headers (`#include`) to understand the primary classes involved. Key ones that stood out were:
    * `ImageBitmap`: The central class being tested.
    * `HTMLImageElement`, `HTMLCanvasElement`, `HTMLVideoElement`: Potential sources for creating `ImageBitmap` objects.
    * `ImageData`: Another potential source for `ImageBitmap`.
    * `StaticBitmapImage`, `AcceleratedStaticBitmapImage`, `UnacceleratedStaticBitmapImage`: Different implementations of images, potentially impacting `ImageBitmap` behavior.
    * `MemoryCache`:  Relevant for resource management and how `ImageBitmap` interacts with cached images.
    * `SkImage`, `SkSurface`, `SkCanvas`:  Skia graphics library components, indicating low-level image manipulation.
    * Testing frameworks (`gtest`, `gmock`):  Confirming this is a test file.

3. **Analyze Test Cases (Functions starting with `TEST_F`)**: I examined each `TEST_F` function to understand the specific aspects of `ImageBitmap` being tested:
    * `ImageResourceConsistency`: Focuses on whether `ImageBitmap` created with different cropping regions maintains (or doesn't maintain) a reference to the original `HTMLImageElement`'s image data.
    * `ImageBitmapSourceChanged`: Tests the behavior when the source of the `HTMLImageElement` changes *after* an `ImageBitmap` has been created from it. It checks if the `ImageBitmap` still references the original image.
    * `AvoidGPUReadback`: Investigates whether creating `ImageBitmap` from GPU-backed resources avoids unnecessary readback to CPU memory under various options (resizing, orientation, etc.). This is a performance-related test.
    * `CreateImageBitmapFromTooBigImageDataDoesNotCrash`: A stability test to ensure that creating an `ImageBitmap` from very large `ImageData` doesn't lead to a crash.
    * `ImageAlphaState`: Checks the alpha channel handling of `ImageBitmap` when created from a transparent image with specific options.

4. **Infer Functionality based on Tests:** By understanding the individual test cases, I could infer the overall functionality of the `ImageBitmap` class. It's responsible for:
    * Creating bitmap images from various sources (HTML image elements, canvas elements, video elements, raw image data).
    * Handling cropping of the source image.
    * Applying transformations (like `flipY`).
    * Performing resizing with different quality settings.
    * Managing color space conversion.
    * Handling alpha channel premultiplication.
    * Potentially using GPU resources for efficiency.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** I considered how `ImageBitmap` is exposed and used in web development:
    * **JavaScript:**  The `createImageBitmap()` function in JavaScript directly relates to the C++ `ImageBitmap` class. JavaScript code passing image sources to this function would ultimately interact with this C++ code.
    * **HTML:**  `<canvas>`, `<img>`, and `<video>` elements are the most direct HTML elements that serve as sources for `createImageBitmap()`.
    * **CSS:** While CSS doesn't directly create `ImageBitmap` objects, CSS properties like `background-image` can use canvas elements where `ImageBitmap` might be involved in rendering. CSS transformations could conceptually relate to some of the `ImageBitmap` options (like orientation).

6. **Identify Potential User/Programming Errors:**  Based on the tests and the functionality, I identified common errors:
    * Incorrectly specifying the crop rectangle (going out of bounds).
    * Assuming an `ImageBitmap` will always update when the source image changes (the `ImageBitmapSourceChanged` test highlights this nuanced behavior).
    * Performance issues if GPU readback isn't avoided.
    * Trying to create `ImageBitmap` from overly large image data.
    * Misunderstanding alpha premultiplication and its impact on pixel data.

7. **Simulate User Steps for Debugging:**  I imagined a user interacting with a web page and how they might trigger the creation and use of `ImageBitmap`, leading to a potential bug. This involved actions like loading images, drawing on canvases, and manipulating video.

8. **Structure the Explanation:** I organized the information into logical sections:
    * Core Functionality
    * Relationship to Web Technologies (with examples)
    * Logical Inferences (with input/output examples)
    * Common User/Programming Errors (with examples)
    * Debugging Scenarios (user steps).

9. **Refine and Elaborate:**  I reviewed the generated explanation, ensuring clarity, accuracy, and sufficient detail. I tried to provide concrete examples where possible. For example, instead of just saying "handles cropping," I explained different cropping scenarios (interior, exterior, outside).

By following these steps, I could effectively analyze the C++ test file and provide a comprehensive explanation of the functionality of the `ImageBitmap` class and its relevance to web technologies. The process involves understanding the code's purpose, identifying key components, analyzing test cases, making logical connections, and considering the user's perspective.
这是目录为 `blink/renderer/core/imagebitmap/image_bitmap_test.cc` 的 Chromium Blink 引擎源代码文件。正如文件名所示，这是一个 **测试文件**，专门用于测试 `ImageBitmap` 相关的核心功能。

以下是它主要的功能和涉及的方面：

**核心功能：测试 `ImageBitmap` 类的各种功能和行为**

* **创建 `ImageBitmap` 对象:** 测试从不同来源创建 `ImageBitmap` 对象的能力，包括：
    * `HTMLImageElement` (图像元素)
    * `HTMLCanvasElement` (画布元素)
    * `HTMLVideoElement` (视频元素)
    * `ImageData` (图像数据)
    * 其他 `ImageBitmap` 对象 (通过裁剪等操作)
    * `StaticBitmapImage` (静态位图图像)

* **裁剪 (Cropping):** 测试从源图像中裁剪特定区域来创建 `ImageBitmap` 的功能，包括：
    * 正常裁剪
    * 裁剪区域超出源图像边界
    * 裁剪区域完全在源图像外部

* **图像资源一致性 (Image Resource Consistency):**  测试当从 `HTMLImageElement` 创建 `ImageBitmap` 时，即使裁剪了图像，`ImageBitmap` 是否能正确访问和使用原始图像资源。

* **图像来源改变 (ImageBitmapSourceChanged):** 测试当 `HTMLImageElement` 的 `src` 属性改变后，之前基于该元素创建的 `ImageBitmap` 的行为。它会验证 `ImageBitmap` 是否仍然持有对原始图像的引用。

* **避免 GPU 回读 (Avoid GPU Readback):**  这是一个性能测试，旨在验证当从 GPU 纹理支持的图像源（例如，在 Canvas 上渲染的内容）创建 `ImageBitmap` 时，是否能避免不必要的 GPU 数据回读到 CPU 内存，从而提高性能。测试涵盖了不同的 `ImageBitmapOptions` 设置（如图像方向、Alpha 预乘、颜色空间转换、调整大小和质量）。

* **处理过大的 `ImageData` (CreateImageBitmapFromTooBigImageDataDoesNotCrash):**  这是一个稳定性测试，验证当尝试从非常大的 `ImageData` 对象创建 `ImageBitmap` 时，不会导致程序崩溃。

* **图像 Alpha 状态 (ImageAlphaState):** 测试创建 `ImageBitmap` 时，如何处理源图像的 Alpha 通道，特别是当指定不进行 Alpha 预乘 (premultiplyAlpha: 'none') 时，像素数据的正确性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`ImageBitmap` API 是在 JavaScript 中暴露的，允许开发者异步地从各种图像源创建位图图像。这个测试文件直接关联到 JavaScript 中的 `createImageBitmap()` 函数。

* **JavaScript:**
    * **示例:**  JavaScript 代码可以使用 `createImageBitmap()` 从一个 `<img>` 元素创建一个 `ImageBitmap`：
      ```javascript
      const imageElement = document.getElementById('myImage');
      createImageBitmap(imageElement).then(imageBitmap => {
        // 使用 imageBitmap 进行后续操作，例如在 canvas 上绘制
        console.log(imageBitmap.width, imageBitmap.height);
      });
      ```
      这个测试文件中的 `ImageBitmapTest` 类和其子测试，就是在模拟 Blink 引擎内部处理 `createImageBitmap()` 调用的过程，并验证其正确性。

* **HTML:**
    * **示例:**  `<img>`、`<canvas>` 和 `<video>` 元素都是 `createImageBitmap()` 的有效输入源。
      ```html
      <img id="myImage" src="image.png">
      <canvas id="myCanvas" width="100" height="100"></canvas>
      <video id="myVideo" src="video.mp4"></video>
      <script>
        const imageElement = document.getElementById('myImage');
        const canvasElement = document.getElementById('myCanvas');
        const videoElement = document.getElementById('myVideo');

        createImageBitmap(imageElement).then(/* ... */);
        createImageBitmap(canvasElement).then(/* ... */);
        createImageBitmap(videoElement).then(/* ... */);
      </script>
      ```
      测试文件中创建了 `HTMLImageElement`、`HTMLCanvasElement` 等对象，并用它们来创建 `ImageBitmap`，以模拟 JavaScript 中使用这些 HTML 元素作为源的情况。

* **CSS:**
    * 虽然 CSS 本身不直接创建 `ImageBitmap` 对象，但 CSS 中使用的图像资源（例如，`background-image`）可能会间接地涉及到 `ImageBitmap` 的使用。例如，一个 `<canvas>` 元素上绘制的内容可以被 CSS 使用，而 `ImageBitmap` 可能参与了 `<canvas>` 内容的生成。
    * **示例 (间接关系):**
      ```html
      <canvas id="myCanvas" width="100" height="100"></canvas>
      <div style="background-image: url('#myCanvas');"></div>
      <script>
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        const image = new Image();
        image.src = 'another_image.png';
        image.onload = function() {
          createImageBitmap(image).then(bitmap => {
            ctx.drawImage(bitmap, 0, 0);
          });
        };
      </script>
      ```
      在这个例子中，CSS 使用了 Canvas 的内容作为背景图。而 `createImageBitmap` 被用来处理加载的图像，并在 Canvas 上绘制。虽然 CSS 没有直接操作 `ImageBitmap`，但 `ImageBitmap` 参与了最终呈现的内容生成。

**逻辑推理、假设输入与输出:**

* **假设输入 (以 `ImageResourceConsistency` 测试为例):**
    * 一个 `HTMLImageElement` 加载了一个 10x10 像素的图像。
    * 使用不同的裁剪矩形创建多个 `ImageBitmap` 对象：
        * `crop_rect = (0, 0, 10, 10)` (完整图像)
        * `crop_rect = (5, 5, 5, 5)` (内部裁剪)
        * `crop_rect = (-5, -5, 10, 10)` (部分超出边界)
        * `crop_rect = (-10, -10, 10, 10)` (完全超出边界)

* **输出:**
    * 对于完整裁剪，`ImageBitmap` 的底层图像数据应该与原始 `HTMLImageElement` 的图像数据相同。
    * 对于内部裁剪和部分超出边界的裁剪，`ImageBitmap` 的底层图像数据应该与原始图像数据不同（因为进行了裁剪或填充）。
    * 对于完全超出边界的裁剪，`ImageBitmap` 应该得到一个空的图像。

* **假设输入 (以 `AvoidGPUReadback` 测试为例):**
    * 创建一个 GPU 纹理支持的 `StaticBitmapImage` (例如，来自 Canvas)。
    * 使用不同的 `ImageBitmapOptions` 创建 `ImageBitmap` 对象，例如：
        * `imageOrientation: "flipY"`
        * `premultiplyAlpha: "none"`
        * `resizeWidth: 50, resizeHeight: 50`

* **输出:**
    * 当选项允许时（例如，不进行需要 CPU 操作的转换），创建的 `ImageBitmap` 应该仍然是 GPU 纹理支持的，从而避免 GPU 回读。
    * 例如，如果 `premultiplyAlpha` 设置为 `"none"`，通常需要从 GPU 纹理读取数据到 CPU 进行处理，那么 `ImageBitmap` 可能就不是纹理支持的了。

**用户或编程常见的使用错误及举例说明:**

* **错误的裁剪参数:** 用户可能传递超出源图像尺寸的裁剪参数，导致意外的结果或错误。
    * **示例 (JavaScript):**
      ```javascript
      const imageElement = document.getElementById('myImage');
      createImageBitmap(imageElement, { x: -10, y: -10, width: 50, height: 50 })
        .then(imageBitmap => {
          // 开发者可能期望得到部分图像，但实际结果可能是一个空图像或经过填充的图像
        });
      ```
      测试文件中的相关测试会验证 Blink 引擎如何处理这种情况。

* **误解 `ImageBitmap` 的更新行为:**  用户可能期望当原始 `HTMLImageElement` 的 `src` 改变时，之前创建的 `ImageBitmap` 会自动更新。但实际上，`ImageBitmap` 在创建时会捕获图像的状态，后续的源更改不会影响已创建的 `ImageBitmap`。
    * **示例 (JavaScript):**
      ```javascript
      const imageElement = document.getElementById('myImage');
      const bitmapPromise = createImageBitmap(imageElement);
      imageElement.src = 'new_image.png';
      bitmapPromise.then(imageBitmap => {
        // imageBitmap 仍然是基于 'image.png' 创建的，而不是 'new_image.png'
      });
      ```
      `ImageBitmapSourceChanged` 测试验证了这种行为。

* **性能问题：未考虑 GPU 回读:** 在需要高性能的场景中，用户可能没有意识到某些 `ImageBitmapOptions` 会导致 GPU 回读，从而降低性能。
    * **示例 (JavaScript):**  在高性能渲染循环中，不必要地设置 `premultiplyAlpha: 'none'` 可能会导致性能瓶颈。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载包含图像、画布或视频的网页。**
2. **JavaScript 代码执行，调用 `createImageBitmap()` 函数。**
3. **`createImageBitmap()` 函数接收 HTML 元素或 `ImageData` 作为输入。**
4. **Blink 引擎接收到 `createImageBitmap()` 的调用。**
5. **Blink 引擎内部会创建 `ImageBitmap` 类的实例，并根据传入的参数（源、裁剪区域、选项等）进行初始化。**
6. **在 `image_bitmap_test.cc` 文件中编写的测试用例模拟了上述步骤，通过不同的输入和选项来测试 `ImageBitmap` 对象的创建和行为。**

**调试线索:**

当开发者在使用 `createImageBitmap()` 遇到问题时，例如：

* **图像显示不正确 (裁剪错误，颜色错误等):** 可以检查传递给 `createImageBitmap()` 的参数，特别是裁剪矩形和各种选项。测试文件中的裁剪和 Alpha 相关的测试可以提供参考。
* **性能问题:**  可以检查是否因为某些选项导致了 GPU 回读。`AvoidGPUReadback` 测试覆盖了这方面。
* **意外的资源占用或内存泄漏:**  Blink 引擎的开发者可能会使用测试文件来确保 `ImageBitmap` 的资源管理是正确的。

总而言之，`blink/renderer/core/imagebitmap/image_bitmap_test.cc` 是一个至关重要的测试文件，它确保了 `ImageBitmap` 这一 Web 平台核心功能的正确性、稳定性和性能。它通过模拟各种使用场景和参数组合，验证了 `ImageBitmap` 类的行为是否符合预期，并帮助开发者避免常见的错误用法。

### 提示词
```
这是目录为blink/renderer/core/imagebitmap/image_bitmap_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
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

#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"

#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/color_correction_test_utils.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/test/fake_gles2_interface.h"
#include "third_party/blink/renderer/platform/graphics/test/fake_web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_test_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkPixelRef.h"
#include "third_party/skia/include/core/SkSurface.h"

namespace blink {

class ExceptionState;

class ImageBitmapTest : public testing::Test {
 protected:
  void SetUp() override {
    sk_sp<SkSurface> surface =
        SkSurfaces::Raster(SkImageInfo::MakeN32Premul(10, 10));
    surface->getCanvas()->clear(0xFFFFFFFF);
    image_ = surface->makeImageSnapshot();

    sk_sp<SkSurface> surface2 =
        SkSurfaces::Raster(SkImageInfo::MakeN32Premul(5, 5));
    surface2->getCanvas()->clear(0xAAAAAAAA);
    image2_ = surface2->makeImageSnapshot();

    // Save the global memory cache to restore it upon teardown.
    global_memory_cache_ =
        ReplaceMemoryCacheForTesting(MakeGarbageCollected<MemoryCache>(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()));

    test_context_provider_ = viz::TestContextProvider::Create();
    InitializeSharedGpuContextGLES2(test_context_provider_.get());
  }

  void TearDown() override {
    // Garbage collection is required prior to switching out the
    // test's memory cache; image resources are released, evicting
    // them from the cache.
    ThreadState::Current()->CollectAllGarbageForTesting(
        ThreadState::StackState::kNoHeapPointers);

    ReplaceMemoryCacheForTesting(global_memory_cache_.Release());
    SharedGpuContext::Reset();
  }

 protected:
  test::TaskEnvironment task_environment_;
  scoped_refptr<viz::TestContextProvider> test_context_provider_;
  sk_sp<SkImage> image_, image2_;
  Persistent<MemoryCache> global_memory_cache_;
};

TEST_F(ImageBitmapTest, ImageResourceConsistency) {
  const ImageBitmapOptions* default_options = ImageBitmapOptions::Create();
  auto dummy = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  auto* image_element =
      MakeGarbageCollected<HTMLImageElement>(dummy->GetDocument());
  sk_sp<SkColorSpace> src_rgb_color_space = SkColorSpace::MakeSRGB();
  SkImageInfo raster_image_info =
      SkImageInfo::MakeN32Premul(5, 5, src_rgb_color_space);
  sk_sp<SkSurface> surface(SkSurfaces::Raster(raster_image_info));
  sk_sp<SkImage> image = surface->makeImageSnapshot();
  ImageResourceContent* original_image_content =
      ImageResourceContent::CreateLoaded(
          UnacceleratedStaticBitmapImage::Create(image).get());
  image_element->SetImageForTest(original_image_content);

  std::optional<gfx::Rect> crop_rect =
      gfx::Rect(0, 0, image_element->width(), image_element->height());
  auto* image_bitmap_no_crop = MakeGarbageCollected<ImageBitmap>(
      image_element, crop_rect, default_options);
  ASSERT_TRUE(image_bitmap_no_crop);
  crop_rect =
      gfx::Rect(image_element->width() / 2, image_element->height() / 2,
                image_element->width() / 2, image_element->height() / 2);
  auto* image_bitmap_interior_crop = MakeGarbageCollected<ImageBitmap>(
      image_element, crop_rect, default_options);
  ASSERT_TRUE(image_bitmap_interior_crop);
  crop_rect =
      gfx::Rect(-image_element->width() / 2, -image_element->height() / 2,
                image_element->width(), image_element->height());
  auto* image_bitmap_exterior_crop = MakeGarbageCollected<ImageBitmap>(
      image_element, crop_rect, default_options);
  ASSERT_TRUE(image_bitmap_exterior_crop);
  crop_rect = gfx::Rect(-image_element->width(), -image_element->height(),
                        image_element->width(), image_element->height());
  auto* image_bitmap_outside_crop = MakeGarbageCollected<ImageBitmap>(
      image_element, crop_rect, default_options);
  ASSERT_TRUE(image_bitmap_outside_crop);

  ASSERT_EQ(image_bitmap_no_crop->BitmapImage()
                ->PaintImageForCurrentFrame()
                .GetSwSkImage(),
            image_element->CachedImage()
                ->GetImage()
                ->PaintImageForCurrentFrame()
                .GetSwSkImage());
  ASSERT_NE(image_bitmap_interior_crop->BitmapImage()
                ->PaintImageForCurrentFrame()
                .GetSwSkImage(),
            image_element->CachedImage()
                ->GetImage()
                ->PaintImageForCurrentFrame()
                .GetSwSkImage());
  ASSERT_NE(image_bitmap_exterior_crop->BitmapImage()
                ->PaintImageForCurrentFrame()
                .GetSwSkImage(),
            image_element->CachedImage()
                ->GetImage()
                ->PaintImageForCurrentFrame()
                .GetSwSkImage());

  scoped_refptr<StaticBitmapImage> empty_image =
      image_bitmap_outside_crop->BitmapImage();
  ASSERT_NE(empty_image->PaintImageForCurrentFrame().GetSwSkImage(),
            image_element->CachedImage()
                ->GetImage()
                ->PaintImageForCurrentFrame()
                .GetSwSkImage());
}

// Verifies that ImageBitmaps constructed from HTMLImageElements hold a
// reference to the original Image if the HTMLImageElement src is changed.
TEST_F(ImageBitmapTest, ImageBitmapSourceChanged) {
  auto dummy = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  auto* image = MakeGarbageCollected<HTMLImageElement>(dummy->GetDocument());
  sk_sp<SkColorSpace> src_rgb_color_space = SkColorSpace::MakeSRGB();
  SkImageInfo raster_image_info =
      SkImageInfo::MakeN32Premul(5, 5, src_rgb_color_space);
  sk_sp<SkSurface> raster_surface(SkSurfaces::Raster(raster_image_info));
  sk_sp<SkImage> raster_image = raster_surface->makeImageSnapshot();
  ImageResourceContent* original_image_content =
      ImageResourceContent::CreateLoaded(
          UnacceleratedStaticBitmapImage::Create(raster_image).get());
  image->SetImageForTest(original_image_content);

  const ImageBitmapOptions* default_options = ImageBitmapOptions::Create();
  std::optional<gfx::Rect> crop_rect =
      gfx::Rect(0, 0, image->width(), image->height());
  auto* image_bitmap =
      MakeGarbageCollected<ImageBitmap>(image, crop_rect, default_options);
  ASSERT_TRUE(image_bitmap);
  ASSERT_EQ(
      image_bitmap->BitmapImage()->PaintImageForCurrentFrame().GetSwSkImage(),
      original_image_content->GetImage()
          ->PaintImageForCurrentFrame()
          .GetSwSkImage());

  ImageResourceContent* new_image_content = ImageResourceContent::CreateLoaded(
      UnacceleratedStaticBitmapImage::Create(image2_).get());
  image->SetImageForTest(new_image_content);

  {
    ASSERT_EQ(
        image_bitmap->BitmapImage()->PaintImageForCurrentFrame().GetSwSkImage(),
        original_image_content->GetImage()
            ->PaintImageForCurrentFrame()
            .GetSwSkImage());
    SkImage* image1 = image_bitmap->BitmapImage()
                          ->PaintImageForCurrentFrame()
                          .GetSwSkImage()
                          .get();
    ASSERT_NE(image1, nullptr);
    SkImage* image2 = original_image_content->GetImage()
                          ->PaintImageForCurrentFrame()
                          .GetSwSkImage()
                          .get();
    ASSERT_NE(image2, nullptr);
    ASSERT_EQ(image1, image2);
  }

  {
    ASSERT_NE(
        image_bitmap->BitmapImage()->PaintImageForCurrentFrame().GetSwSkImage(),
        new_image_content->GetImage()
            ->PaintImageForCurrentFrame()
            .GetSwSkImage());
    SkImage* image1 = image_bitmap->BitmapImage()
                          ->PaintImageForCurrentFrame()
                          .GetSwSkImage()
                          .get();
    ASSERT_NE(image1, nullptr);
    SkImage* image2 = new_image_content->GetImage()
                          ->PaintImageForCurrentFrame()
                          .GetSwSkImage()
                          .get();
    ASSERT_NE(image2, nullptr);
    ASSERT_NE(image1, image2);
  }
}

static void TestImageBitmapTextureBacked(
    scoped_refptr<StaticBitmapImage> bitmap,
    gfx::Rect& rect,
    ImageBitmapOptions* options,
    bool is_texture_backed) {
  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(bitmap, rect, options);
  EXPECT_TRUE(image_bitmap);
  EXPECT_EQ(image_bitmap->BitmapImage()->IsTextureBacked(), is_texture_backed);
}

TEST_F(ImageBitmapTest, AvoidGPUReadback) {
  base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper =
      SharedGpuContext::ContextProviderWrapper();
  auto resource_provider = CanvasResourceProvider::CreateSharedImageProvider(
      SkImageInfo::MakeN32Premul(100, 100), cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kNo, context_provider_wrapper,
      RasterMode::kGPU, gpu::SharedImageUsageSet());

  scoped_refptr<StaticBitmapImage> bitmap =
      resource_provider->Snapshot(FlushReason::kTesting);
  ASSERT_TRUE(bitmap->IsTextureBacked());

  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(bitmap);
  EXPECT_TRUE(image_bitmap);
  EXPECT_TRUE(image_bitmap->BitmapImage()->IsTextureBacked());

  gfx::Rect image_bitmap_rect(25, 25, 50, 50);
  {
    ImageBitmapOptions* image_bitmap_options = ImageBitmapOptions::Create();
    TestImageBitmapTextureBacked(bitmap, image_bitmap_rect,
                                 image_bitmap_options, true);
  }

  std::list<String> image_orientations = {"none", "flipY"};
  std::list<String> premultiply_alphas = {"none", "premultiply", "default"};
  std::list<String> color_space_conversions = {"none", "default"};
  std::list<int> resize_widths = {25, 50, 75};
  std::list<int> resize_heights = {25, 50, 75};
  std::list<String> resize_qualities = {"pixelated", "low", "medium", "high"};

  for (auto image_orientation : image_orientations) {
    for (auto premultiply_alpha : premultiply_alphas) {
      for (auto color_space_conversion : color_space_conversions) {
        for (auto resize_width : resize_widths) {
          for (auto resize_height : resize_heights) {
            for (auto resize_quality : resize_qualities) {
              ImageBitmapOptions* image_bitmap_options =
                  ImageBitmapOptions::Create();
              image_bitmap_options->setImageOrientation(image_orientation);
              image_bitmap_options->setPremultiplyAlpha(premultiply_alpha);
              image_bitmap_options->setColorSpaceConversion(
                  color_space_conversion);
              image_bitmap_options->setResizeWidth(resize_width);
              image_bitmap_options->setResizeHeight(resize_height);
              image_bitmap_options->setResizeQuality(resize_quality);
              // Setting premuliply_alpha to none will cause a read back.
              // Otherwise, we expect to avoid GPU readback when creaing an
              // ImageBitmap from a texture-backed source.
              TestImageBitmapTextureBacked(bitmap, image_bitmap_rect,
                                           image_bitmap_options,
                                           premultiply_alpha != "none");
            }
          }
        }
      }
    }
  }
}

// This test is failing on asan-clang-phone because memory allocation is
// declined. See <http://crbug.com/782286>.
// This test is failing on fuchsia because memory allocation is
// declined.  <http://crbug.com/1090252>.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_FUCHSIA)
#define MAYBE_CreateImageBitmapFromTooBigImageDataDoesNotCrash \
  DISABLED_CreateImageBitmapFromTooBigImageDataDoesNotCrash
#else
#define MAYBE_CreateImageBitmapFromTooBigImageDataDoesNotCrash \
  CreateImageBitmapFromTooBigImageDataDoesNotCrash
#endif

// This test verifies if requesting a large ImageData and creating an
// ImageBitmap from that does not crash. crbug.com/780358
TEST_F(ImageBitmapTest,
       MAYBE_CreateImageBitmapFromTooBigImageDataDoesNotCrash) {
  constexpr int kWidth = 1 << 28;  // 256M pixels width, resulting in 1GB data.
  ImageData* image_data = ImageData::CreateForTest(gfx::Size(kWidth, 1));
  DCHECK(image_data);
  ImageBitmapOptions* options = ImageBitmapOptions::Create();
  options->setColorSpaceConversion("default");
  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      image_data, gfx::Rect(image_data->Size()), options);
  DCHECK(image_bitmap);
}

TEST_F(ImageBitmapTest, ImageAlphaState) {
  auto dummy = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  auto* image_element =
      MakeGarbageCollected<HTMLImageElement>(dummy->GetDocument());

  // Load a 2x2 png file which has pixels (255, 102, 153, 0). It is a fully
  // transparent image.
  ResourceRequest resource_request(
      "data:image/"
      "png;base64,"
      "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAEUlEQVR42mP8nzaTAQQYYQwA"
      "LssD/5ca+r8AAAAASUVORK5CYII=");

  FetchParameters params =
      FetchParameters::CreateForTest(std::move(resource_request));

  ImageResourceContent* resource_content =
      ImageResourceContent::Fetch(params, dummy->GetDocument().Fetcher());

  image_element->SetImageForTest(resource_content);

  ImageBitmapOptions* options = ImageBitmapOptions::Create();
  // ImageBitmap created from unpremul source image result.
  options->setPremultiplyAlpha("none");

  // Additional operation shouldn't affect alpha op.
  options->setImageOrientation("flipY");

  std::optional<gfx::Rect> crop_rect =
      gfx::Rect(0, 0, image_element->width(), image_element->height());
  auto* image_bitmap =
      MakeGarbageCollected<ImageBitmap>(image_element, crop_rect, options);
  ASSERT_TRUE(image_bitmap);

  // Read 1 pixel
  sk_sp<SkImage> result =
      image_bitmap->BitmapImage()->PaintImageForCurrentFrame().GetSwSkImage();
  SkPixmap pixmap;
  ASSERT_TRUE(result->peekPixels(&pixmap));
  const uint32_t* pixels = pixmap.addr32();

  SkColorType result_color_type = result->colorType();
  SkColor expected = SkColorSetARGB(0, 0, 0, 0);

  switch (result_color_type) {
    case SkColorType::kRGBA_8888_SkColorType:
      // Set ABGR value as reverse of RGBA
      expected =
          SkColorSetARGB(/* a */ 0, /* b */ 153, /* g */ 102, /* r */ 255);
      break;
    case SkColorType::kBGRA_8888_SkColorType:
      // Set ARGB value as reverse of BGRA
      expected =
          SkColorSetARGB(/* a */ 0, /* r */ 255, /* g */ 102, /* b */ 153);
      break;
    default:
      NOTREACHED();
  }

  ASSERT_EQ(pixels[0], expected);
}

}  // namespace blink
```