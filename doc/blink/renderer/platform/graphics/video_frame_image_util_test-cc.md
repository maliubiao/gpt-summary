Response:
Let's break down the thought process to analyze the provided C++ test file.

1. **Understand the Goal:** The primary goal is to understand the purpose of `video_frame_image_util_test.cc` within the Chromium Blink rendering engine. Specifically, we need to identify what functionality it tests and how it relates to broader web technologies like JavaScript, HTML, and CSS.

2. **Identify Key Components:**  Scan the file for important keywords, class names, and function names. This immediately highlights:
    * `#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"`:  This is the header file for the code being tested. It suggests the tests are about utility functions related to converting video frames into images.
    * `TEST(...)`: This is the Google Test macro, indicating individual test cases.
    * Class names like `AcceleratedCompositingTestPlatform`, `ScopedFakeGpuContext`. These suggest testing scenarios involving GPU acceleration.
    * Function names like `CreateImageFromVideoFrame`, `WillCreateAcceleratedImagesFromVideoFrame`, `CreateResourceProviderForVideoFrame`. These are the core functions being tested.
    * Mentions of `media::VideoFrame`, `SkImage`, `gpu::Mailbox`, `viz::RasterContextProvider`. These indicate dependencies on media, graphics, and GPU-related components.

3. **Infer Functionality from Test Names:** The names of the `TEST` cases provide direct clues about the functionality being tested:
    * `VideoTransformationToFromImageOrientation`: Testing the conversion between video transformations and image orientations.
    * `WillCreateAcceleratedImagesFromVideoFrame`: Testing whether a video frame can be used to create accelerated images.
    * `CreateImageFromVideoFrameZeroCopy`, `CreateImageFromVideoFrameSoftwareFrame`, `CreateImageFromVideoFrameGpuMemoryBufferFrame`, `CreateImageFromVideoFrameTextureFrame`: Testing different paths for creating images from various video frame types.
    * `CreateAcceleratedImageFromVideoFrame...`: Specifically testing the creation of *accelerated* images.
    * `FlushedAcceleratedImage`: Possibly testing resource management or synchronization.
    * `SoftwareCreateResourceProviderForVideoFrame`, `AcceleratedCreateResourceProviderForVideoFrame`, `WorkaroundCreateResourceProviderForVideoFrame`: Testing how resource providers are created in different scenarios (with/without GPU, with workarounds).
    * `DestRectWithoutCanvasResourceProvider`, `CanvasResourceProviderTooSmallForDestRect`, `CanvasResourceProviderDestRect`: Testing the handling of destination rectangles when creating images.

4. **Analyze Test Logic:**  Examine the code within each test case to understand *how* the functionality is being tested:
    * **Setup:**  Look for how test data (video frames, contexts) are created and initialized. Pay attention to different `media::VideoFrame::STORAGE_*` types (OWNED_MEMORY, GPU_MEMORY_BUFFER, OPAQUE).
    * **Action:** Identify the core function being called (e.g., `CreateImageFromVideoFrame`).
    * **Verification:**  Look for `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `ASSERT_TRUE`, `ASSERT_FALSE`. These are used to check if the actual output matches the expected output. Note the specific properties being checked (e.g., `IsTextureBacked()`, `CurrentFrameOrientation()`, mailbox names).

5. **Relate to Web Technologies:**  Consider how the tested functionality relates to JavaScript, HTML, and CSS:
    * **`CreateImageFromVideoFrame`:** This function likely underpins the ability of JavaScript to access and manipulate video frames, for example, when drawing video onto a `<canvas>` element using `drawImage()`. The resulting `Image` object can then be used in various web contexts.
    * **GPU Acceleration:** The tests for accelerated image creation are crucial for performance in web applications. Drawing video efficiently often relies on GPU processing.
    * **Image Orientation:**  The tests for `VideoTransformationToFromImageOrientation` highlight how video metadata (like rotation) is translated into image orientation, which is important for displaying video correctly in web browsers.
    * **Resource Providers:** The tests related to `CreateResourceProviderForVideoFrame` are about managing the underlying graphics resources used to represent images derived from video. This impacts performance and memory usage.

6. **Consider Logic and Assumptions:** Look for any logical steps or assumptions made in the tests. For example, the tests assume specific behaviors based on whether GPU compositing is enabled or disabled. Consider how different inputs (different video frame types, different contexts) lead to different outputs.

7. **Identify Potential User/Programming Errors:** Think about how developers might misuse the tested API:
    * **Forgetting to provide a `CanvasResourceProvider` when specifying a destination rectangle.**
    * **Providing a `CanvasResourceProvider` with insufficient dimensions for the destination rectangle.**
    * **Assuming zero-copy image creation will always succeed on all platforms.**
    * **Not handling different video frame storage types correctly.**

8. **Structure the Output:** Organize the findings into logical categories (Functionality, Relation to Web Technologies, Logic/Assumptions, User Errors). Use clear and concise language. Provide specific examples where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just tests video frame to image conversion."  **Correction:** Realized there's a strong focus on GPU acceleration and different types of video frames.
* **Initial thought:** "How does this relate to JavaScript?" **Refinement:** Connected it to the `<canvas>` API and the ability to manipulate video data in web pages.
* **Stuck on a test:**  If a test's purpose wasn't immediately clear, I would re-read the test code carefully, look at the function being called, and consider the conditions being checked. For example, the `FlushedAcceleratedImage` test initially seemed a bit obscure, but closer inspection revealed it's about resource management.

By following these steps, analyzing the code, and making connections to broader web technologies, a comprehensive understanding of the test file's purpose can be achieved.
这个文件 `video_frame_image_util_test.cc` 是 Chromium Blink 渲染引擎中的一个 C++ 单元测试文件。它的主要功能是测试 `video_frame_image_util.h` 中定义的工具函数，这些函数用于将 `media::VideoFrame` 对象转换为 `blink::Image` 对象。`media::VideoFrame` 通常是解码后的视频帧数据，而 `blink::Image` 是 Blink 中用于表示图像的抽象类。

以下是该文件测试的具体功能，并解释了它们与 JavaScript、HTML 和 CSS 的关系，以及逻辑推理和常见错误：

**文件主要功能:**

1. **`VideoTransformationToFromImageOrientation` 测试:**
   - **功能:** 测试 `ImageOrientationToVideoTransformation` 和 `VideoTransformationToImageOrientation` 两个函数，这两个函数用于在 `blink::ImageOrientationEnum` (Blink 中表示图像方向) 和 `media::VideoTransformation` (media 层表示视频变换，例如旋转和镜像) 之间进行转换。
   - **与 Web 技术的关系:**
     - **JavaScript 和 HTML:**  当 JavaScript 通过 `<video>` 元素播放视频时，视频的旋转和镜像信息可能存储在 `media::VideoFrame` 的元数据中。Blink 需要将这些信息转换为 `blink::Image` 的方向信息，以便正确渲染视频帧到 Canvas 或其他渲染上下文中。例如，如果视频元数据指示视频需要旋转 90 度，那么 `ImageOrientationToVideoTransformation` 和 `VideoTransformationToImageOrientation` 帮助 Blink 正确处理这个旋转。
     - **CSS:** CSS 的 `transform` 属性也可以影响元素（包括视频）的显示方向。Blink 需要协调 CSS transform 和视频帧本身的变换信息。虽然这个测试直接测试的是 C++ 层的转换，但它间接影响了 CSS transform 如何与视频的原始方向相结合。
   - **逻辑推理:**
     - **假设输入:** 遍历所有可能的 `ImageOrientationEnum` 值。
     - **预期输出:**  对于每个 `ImageOrientationEnum`，将其转换为 `media::VideoTransformation`，然后再转换回 `ImageOrientationEnum`，结果应该与原始值相等。

2. **`WillCreateAcceleratedImagesFromVideoFrame` 测试:**
   - **功能:** 测试 `WillCreateAcceleratedImagesFromVideoFrame` 函数，该函数判断是否可以使用 GPU 加速来创建基于给定 `media::VideoFrame` 的 `blink::Image`。这取决于视频帧的存储方式和平台支持。
   - **与 Web 技术的关系:**
     - **JavaScript 和 HTML:** 当 JavaScript 使用 Canvas API (例如 `drawImage`) 绘制视频帧时，如果可以使用 GPU 加速，渲染性能会显著提高。`WillCreateAcceleratedImagesFromVideoFrame` 的结果影响 Blink 如何选择渲染路径。
   - **逻辑推理:**
     - **假设输入:** 不同类型的 `media::VideoFrame`，包括：
       - 使用 alpha 通道的帧 (`media::VideoFrame::CreateTransparentFrame`)
       - 存储在 CPU 内存中的 RGB 帧 (`media::VideoFrame::STORAGE_OWNED_MEMORY`)
       - 使用 GPU 内存缓冲区的帧 (`media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER`)
       - 使用共享图像的帧 (`media::VideoFrame::STORAGE_OPAQUE`)
     - **预期输出:** 根据视频帧的类型和平台，函数应该返回 `true` 或 `false`。例如，通常情况下，共享图像类型的帧可以在某些平台上使用 GPU 加速。

3. **`CreateImageFromVideoFrameZeroCopy` (平台相关) 测试:**
   - **功能:**  测试在支持零拷贝的情况下，使用 `CreateImageFromVideoFrame` 函数从共享图像的 `media::VideoFrame` 创建 `blink::Image`。零拷贝意味着创建的 `blink::Image` 直接引用底层的 GPU 纹理，避免了不必要的内存复制。
   - **与 Web 技术的关系:**
     - **JavaScript 和 HTML:** 零拷贝对于高性能视频渲染至关重要。当 JavaScript 操作视频帧时，零拷贝可以减少 CPU 负担并提高帧率。
   - **逻辑推理:**
     - **假设输入:**  一个 `media::VideoFrame`，其数据存储为共享图像。
     - **预期输出:** 创建的 `blink::Image` 应该是基于纹理的 (`IsTextureBacked()` 返回 `true`)，并且其持有的 mailbox (GPU 纹理的标识符) 应该与原始 `media::VideoFrame` 的共享图像的 mailbox 相同。

4. **`CreateImageFromVideoFrameSoftwareFrame` 和 其他 `CreateImageFromVideoFrame` 测试:**
   - **功能:** 测试使用 `CreateImageFromVideoFrame` 函数从不同类型的 `media::VideoFrame` (例如，CPU 内存、GPU 内存缓冲区) 创建 `blink::Image`。
   - **与 Web 技术的关系:**
     - **JavaScript 和 HTML:**  这些测试覆盖了各种可能的视频帧来源，确保 Blink 可以正确地将这些帧转换为可以在 Canvas 或其他地方使用的图像。
   - **逻辑推理:**
     - **假设输入:**  不同存储类型的 `media::VideoFrame`。
     - **预期输出:**  根据视频帧的类型和是否启用了 GPU 加速，创建的 `blink::Image` 可能是基于纹理的，也可能是基于软件位图的。

5. **`CreateAcceleratedImageFromVideoFrame...` 测试:**
   - **功能:**  专门测试在启用 GPU 加速的情况下，从各种类型的 `media::VideoFrame` 创建 `blink::Image`。
   - **与 Web 技术的关系:**
     - **JavaScript 和 HTML:**  确保在支持 GPU 加速的环境下，视频帧可以高效地转换为图像进行渲染。

6. **`FlushedAcceleratedImage` 测试:**
   - **功能:**  测试当使用 `CreateImageFromVideoFrame` 创建加速图像时，资源提供者 (ResourceProvider) 的行为。这可能涉及到纹理的刷新或同步。
   - **与 Web 技术的关系:**
     - **内部实现:** 这个测试更侧重于 Blink 内部的资源管理，但最终影响了视频渲染的正确性和性能。

7. **`SoftwareCreateResourceProviderForVideoFrame` 和 `AcceleratedCreateResourceProviderForVideoFrame` 测试:**
   - **功能:** 测试 `CreateResourceProviderForVideoFrame` 函数，该函数用于为视频帧创建资源提供者 (CanvasResourceProvider)。资源提供者负责管理用于绘制图像的底层图形资源。测试分别覆盖了软件渲染和硬件加速渲染的情况。
   - **与 Web 技术的关系:**
     - **内部实现:**  资源提供者是 Blink 渲染管道的关键部分，负责高效地管理纹理和其他图形资源。

8. **`DestRectWithoutCanvasResourceProvider` 和 其他 CanvasResourceProvider 相关的测试:**
   - **功能:** 测试在使用 `CreateImageFromVideoFrame` 创建图像时，指定目标矩形 (dest_rect) 的行为。这些测试验证了在需要的情况下是否正确使用了 `CanvasResourceProvider`，以及当 `CanvasResourceProvider` 的尺寸不足时是否能正确处理。
   - **与 Web 技术的关系:**
     - **JavaScript 和 HTML Canvas:** 当 JavaScript 使用 `drawImage` 的时候，可以指定源图像的一部分绘制到目标 Canvas 的特定区域。这些测试确保了 Blink 在处理这种情况时能够正确地裁剪和缩放视频帧。

**用户或编程常见的使用错误举例:**

1. **假设所有平台都支持零拷贝:** 开发者可能会错误地假设在所有浏览器和操作系统上，从共享图像的 `media::VideoFrame` 创建 `blink::Image` 都是零拷贝的。但实际上，某些平台可能不支持，Blink 会回退到软件拷贝。没有正确处理这种情况可能会导致性能问题。
   - **错误代码示例 (JavaScript):**
     ```javascript
     const video = document.querySelector('video');
     const canvas = document.createElement('canvas');
     const ctx = canvas.getContext('2d');

     video.addEventListener('play', () => {
       function drawFrame() {
         ctx.drawImage(video, 0, 0); // 假设总是零拷贝
         requestAnimationFrame(drawFrame);
       }
       drawFrame();
     });
     ```
   - **正确做法:**  虽然 JavaScript 无法直接控制是否零拷贝，但理解其背后的原理有助于开发者编写更高效的代码，例如，尽量使用硬件加速的 Canvas 上下文。

2. **在需要 `CanvasResourceProvider` 的情况下没有提供:** 当开发者尝试从视频帧创建图像并指定了非空的 `dest_rect` 时，如果 Blink 决定需要使用 `CanvasResourceProvider` 来进行裁剪或缩放，但开发者没有提供，则会导致图像创建失败。
   - **错误代码示例 (C++ 假设的 Blink 内部调用):**
     ```c++
     // 错误：指定了 dest_rect，但 provider 为 nullptr
     auto image = CreateImageFromVideoFrame(video_frame, true, nullptr, nullptr, gfx::Rect(10, 10, 50, 50));
     ```
   - **正确做法 (C++ 假设的 Blink 内部调用):**  确保在需要时创建并传递合适的 `CanvasResourceProvider`。

3. **提供的 `CanvasResourceProvider` 尺寸不足:** 如果提供的 `CanvasResourceProvider` 的尺寸小于 `dest_rect` 的尺寸，Blink 将无法正确地执行绘制操作。
   - **错误代码示例 (C++ 假设的 Blink 内部调用):**
     ```c++
     SkImageInfo small_info = SkImageInfo::MakeN32Premul(32, 32);
     scoped_refptr<CanvasResourceProvider> provider = CreateResourceProviderForVideoFrame(small_info, ...);
     // 错误：provider 的尺寸小于 dest_rect
     auto image = CreateImageFromVideoFrame(video_frame, true, provider.get(), nullptr, gfx::Rect(0, 0, 64, 64));
     ```
   - **正确做法 (C++ 假设的 Blink 内部调用):**  确保 `CanvasResourceProvider` 的尺寸足够容纳 `dest_rect`。

总而言之，`video_frame_image_util_test.cc` 通过各种测试用例，确保了 Blink 能够正确且高效地将视频帧转换为图像，这对于 Web 浏览器中视频的播放和处理至关重要。它涵盖了不同的视频帧类型、硬件加速、图像方向处理以及资源管理等方面，间接地保障了基于 JavaScript、HTML 和 CSS 构建的 Web 应用中视频功能的正确性和性能。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/video_frame_image_util_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"

#include "base/functional/callback_helpers.h"
#include "base/test/task_environment.h"
#include "build/build_config.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "components/viz/test/test_context_provider.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "media/base/video_frame.h"
#include "media/renderers/shared_image_video_frame_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_test_utils.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/video_frame_utils.h"
#include "third_party/skia/include/gpu/ganesh/GrDriverBugWorkarounds.h"

namespace blink {

namespace {

constexpr auto kTestSize = gfx::Size(64, 64);
const auto kTestInfo = SkImageInfo::MakeN32Premul(64, 64);

class AcceleratedCompositingTestPlatform
    : public blink::TestingPlatformSupport {
 public:
  bool IsGpuCompositingDisabled() const override { return false; }
};

class ScopedFakeGpuContext {
 public:
  explicit ScopedFakeGpuContext(bool disable_imagebitmap) {
    SharedGpuContext::Reset();
    test_context_provider_ = viz::TestContextProvider::Create();

    if (disable_imagebitmap) {
      // Disable CanvasResourceProvider using GPU.
      auto& feature_info = test_context_provider_->GetWritableGpuFeatureInfo();
      feature_info.enabled_gpu_driver_bug_workarounds.push_back(
          DISABLE_IMAGEBITMAP_FROM_VIDEO_USING_GPU);
    }

    InitializeSharedGpuContextGLES2(test_context_provider_.get());
  }

  scoped_refptr<viz::ContextProvider> context_provider() const {
    return test_context_provider_;
  }

  viz::RasterContextProvider* raster_context_provider() const {
    return test_context_provider_.get();
  }

  ~ScopedFakeGpuContext() {
    task_environment_.RunUntilIdle();
    SharedGpuContext::Reset();
  }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  scoped_refptr<viz::TestContextProvider> test_context_provider_;
  ScopedTestingPlatformSupport<AcceleratedCompositingTestPlatform>
      accelerated_compositing_scope_;
};

// TODO(crbug.com/1186864): Remove |expect_broken_tagging| when fixed.
void TestOrientation(scoped_refptr<media::VideoFrame> frame,
                     bool expect_broken_tagging = false) {
  constexpr auto kTestTransform =
      media::VideoTransformation(media::VIDEO_ROTATION_90, /*mirrored=*/true);
  constexpr auto kTestOrientation = ImageOrientationEnum::kOriginLeftTop;

  frame->metadata().transformation = kTestTransform;
  auto image =
      CreateImageFromVideoFrame(frame, true, nullptr, nullptr, gfx::Rect(),
                                /*prefer_tagged_orientation=*/true);
  if (expect_broken_tagging) {
    EXPECT_EQ(image->CurrentFrameOrientation(), ImageOrientationEnum::kDefault);
  } else {
    EXPECT_EQ(image->CurrentFrameOrientation(), kTestOrientation);
  }

  image = CreateImageFromVideoFrame(frame, true, nullptr, nullptr, gfx::Rect(),
                                    /*prefer_tagged_orientation=*/false);
  EXPECT_EQ(image->CurrentFrameOrientation(), ImageOrientationEnum::kDefault);
}

}  // namespace

TEST(VideoFrameImageUtilTest, VideoTransformationToFromImageOrientation) {
  for (int i = static_cast<int>(ImageOrientationEnum::kMinValue);
       i <= static_cast<int>(ImageOrientationEnum::kMaxValue); ++i) {
    auto blink_orientation = static_cast<ImageOrientationEnum>(i);
    auto media_transform =
        ImageOrientationToVideoTransformation(blink_orientation);
    EXPECT_EQ(blink_orientation,
              VideoTransformationToImageOrientation(media_transform));
  }
}

TEST(VideoFrameImageUtilTest, WillCreateAcceleratedImagesFromVideoFrame) {
  // I420A isn't a supported zero copy format.
  {
    auto alpha_frame = media::VideoFrame::CreateTransparentFrame(kTestSize);
    EXPECT_FALSE(WillCreateAcceleratedImagesFromVideoFrame(alpha_frame.get()));
  }

  // Software RGB frames aren't supported.
  {
    auto cpu_frame =
        CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                        media::VideoFrame::STORAGE_OWNED_MEMORY,
                        media::PIXEL_FORMAT_XRGB, base::TimeDelta());
    EXPECT_FALSE(WillCreateAcceleratedImagesFromVideoFrame(cpu_frame.get()));
  }

  // GpuMemoryBuffer frames aren't supported.
  {
    auto cpu_frame =
        CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                        media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER,
                        media::PIXEL_FORMAT_XRGB, base::TimeDelta());
    EXPECT_FALSE(WillCreateAcceleratedImagesFromVideoFrame(cpu_frame.get()));
  }

  // Single mailbox shared images should be supported on most platforms.
  {
    auto shared_image_frame =
        CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                        media::VideoFrame::STORAGE_OPAQUE,
                        media::PIXEL_FORMAT_XRGB, base::TimeDelta());
    EXPECT_TRUE(shared_image_frame->HasSharedImage());
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_MAC)
    EXPECT_FALSE(
        WillCreateAcceleratedImagesFromVideoFrame(shared_image_frame.get()));
#else
    EXPECT_TRUE(
        WillCreateAcceleratedImagesFromVideoFrame(shared_image_frame.get()));
#endif
  }
}

// Some platforms don't support zero copy images.
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_MAC)
TEST(VideoFrameImageUtilTest, CreateImageFromVideoFrameZeroCopy) {
  ScopedFakeGpuContext fake_context(/*disable_imagebitmap=*/false);
  auto shared_image_frame =
      CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                      media::VideoFrame::STORAGE_OPAQUE,
                      media::PIXEL_FORMAT_XRGB, base::TimeDelta());
  EXPECT_TRUE(shared_image_frame->HasSharedImage());

  auto image = CreateImageFromVideoFrame(shared_image_frame);
  ASSERT_TRUE(image->IsTextureBacked());
  EXPECT_EQ(memcmp(image->GetMailboxHolder().mailbox.name,
                   shared_image_frame->shared_image()->mailbox().name,
                   sizeof(gpu::Mailbox::Name)),
            0);
}
#endif

TEST(VideoFrameImageUtilTest, CreateImageFromVideoFrameSoftwareFrame) {
  base::test::SingleThreadTaskEnvironment task_environment_;
  auto cpu_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   media::PIXEL_FORMAT_XRGB, base::TimeDelta());
  auto image = CreateImageFromVideoFrame(cpu_frame);
  EXPECT_FALSE(image->IsTextureBacked());

  TestOrientation(cpu_frame);
  task_environment_.RunUntilIdle();
}

TEST(VideoFrameImageUtilTest, CreateImageFromVideoFrameGpuMemoryBufferFrame) {
  base::test::SingleThreadTaskEnvironment task_environment_;
  auto cpu_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER,
                                   media::PIXEL_FORMAT_NV12, base::TimeDelta());
  auto image = CreateImageFromVideoFrame(cpu_frame);
  ASSERT_FALSE(image->IsTextureBacked());
  task_environment_.RunUntilIdle();
}

TEST(VideoFrameImageUtilTest, CreateImageFromVideoFrameTextureFrame) {
  base::test::SingleThreadTaskEnvironment task_environment_;
  auto cpu_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_OPAQUE,
                                   media::PIXEL_FORMAT_NV12, base::TimeDelta());
  auto image = CreateImageFromVideoFrame(cpu_frame);

  // An unaccelerated image can't be created from a texture based VideoFrame
  // without a viz::RasterContextProvider.
  ASSERT_FALSE(image);
  task_environment_.RunUntilIdle();
}

TEST(VideoFrameImageUtilTest,
     CreateAcceleratedImageFromVideoFrameBasicSoftwareFrame) {
  ScopedFakeGpuContext fake_context(/*disable_imagebitmap=*/false);
  auto cpu_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   media::PIXEL_FORMAT_XRGB, base::TimeDelta());
  auto image = CreateImageFromVideoFrame(cpu_frame);
  ASSERT_TRUE(image->IsTextureBacked());
}

TEST(VideoFrameImageUtilTest, CreateAcceleratedImageFromGpuMemoryBufferFrame) {
  ScopedFakeGpuContext fake_context(/*disable_imagebitmap=*/false);
  auto gmb_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER,
                                   media::PIXEL_FORMAT_NV12, base::TimeDelta());
  auto image = CreateImageFromVideoFrame(gmb_frame);
  ASSERT_TRUE(image->IsTextureBacked());
  TestOrientation(gmb_frame, /*expect_broken_tagging=*/true);
}

TEST(VideoFrameImageUtilTest, CreateAcceleratedImageFromTextureFrame) {
  ScopedFakeGpuContext fake_context(/*disable_imagebitmap=*/false);

  auto texture_frame = media::CreateSharedImageRGBAFrame(
      fake_context.raster_context_provider(), kTestSize, gfx::Rect(kTestSize),
      base::DoNothing());
  auto image = CreateImageFromVideoFrame(texture_frame,
                                         /*allow_zero_copy_images=*/false);
  ASSERT_TRUE(image->IsTextureBacked());
  TestOrientation(texture_frame, /*expect_broken_tagging=*/true);
}

TEST(VideoFrameImageUtilTest, FlushedAcceleratedImage) {
  ScopedFakeGpuContext fake_context(/*disable_imagebitmap=*/false);
  auto* raster_context_provider = fake_context.raster_context_provider();
  ASSERT_TRUE(raster_context_provider);

  auto texture_frame = media::CreateSharedImageRGBAFrame(
      raster_context_provider, kTestSize, gfx::Rect(kTestSize),
      base::DoNothing());

  auto provider =
      CreateResourceProviderForVideoFrame(kTestInfo, raster_context_provider);
  ASSERT_TRUE(provider);
  EXPECT_TRUE(provider->IsAccelerated());

  auto image = CreateImageFromVideoFrame(texture_frame,
                                         /*allow_zero_copy_images=*/false,
                                         provider.get());
  EXPECT_TRUE(image->IsTextureBacked());

  image = CreateImageFromVideoFrame(texture_frame,
                                    /*allow_zero_copy_images=*/false,
                                    provider.get());
  EXPECT_TRUE(image->IsTextureBacked());

  ASSERT_FALSE(provider->Recorder().HasRecordedDrawOps());
}

TEST(VideoFrameImageUtilTest, SoftwareCreateResourceProviderForVideoFrame) {
  // Creating a provider with a null viz::RasterContextProvider should result in
  // a non-accelerated provider being created.
  auto provider = CreateResourceProviderForVideoFrame(kTestInfo, nullptr);
  ASSERT_TRUE(provider);
  EXPECT_FALSE(provider->IsAccelerated());
}

TEST(VideoFrameImageUtilTest, AcceleratedCreateResourceProviderForVideoFrame) {
  ScopedFakeGpuContext fake_context(/*disable_imagebitmap=*/false);
  ASSERT_TRUE(SharedGpuContext::IsGpuCompositingEnabled());

  auto* raster_context_provider = fake_context.raster_context_provider();
  ASSERT_TRUE(raster_context_provider);

  // Creating a provider with a null viz::RasterContextProvider should result in
  // a non-accelerated provider being created.
  {
    auto provider = CreateResourceProviderForVideoFrame(kTestInfo, nullptr);
    ASSERT_TRUE(provider);
    EXPECT_FALSE(provider->IsAccelerated());
  }

  // Creating a provider with a real raster context provider should result in
  // an accelerated provider being created.
  {
    auto provider =
        CreateResourceProviderForVideoFrame(kTestInfo, raster_context_provider);
    ASSERT_TRUE(provider);
    EXPECT_TRUE(provider->IsAccelerated());
  }
}

TEST(VideoFrameImageUtilTest, WorkaroundCreateResourceProviderForVideoFrame) {
  ScopedFakeGpuContext fake_context(/*disable_imagebitmap=*/true);
  ASSERT_TRUE(SharedGpuContext::IsGpuCompositingEnabled());

  auto* raster_context_provider = fake_context.raster_context_provider();
  ASSERT_TRUE(raster_context_provider);

  // Creating a provider with a real raster context provider should result in
  // an unaccelerated provider being created due to the workaround.
  {
    auto provider =
        CreateResourceProviderForVideoFrame(kTestInfo, raster_context_provider);
    ASSERT_TRUE(provider);
    EXPECT_FALSE(provider->IsAccelerated());
  }
}

TEST(VideoFrameImageUtilTest, DestRectWithoutCanvasResourceProvider) {
  base::test::SingleThreadTaskEnvironment task_environment_;
  auto cpu_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   media::PIXEL_FORMAT_XRGB, base::TimeDelta());

  // A CanvasResourceProvider must be provided with a custom destination rect.
  auto image = CreateImageFromVideoFrame(cpu_frame, true, nullptr, nullptr,
                                         gfx::Rect(0, 0, 10, 10));
  ASSERT_FALSE(image);
  task_environment_.RunUntilIdle();
}

TEST(VideoFrameImageUtilTest, CanvasResourceProviderTooSmallForDestRect) {
  base::test::SingleThreadTaskEnvironment task_environment_;
  auto cpu_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   media::PIXEL_FORMAT_XRGB, base::TimeDelta());

  auto provider = CreateResourceProviderForVideoFrame(
      SkImageInfo::MakeN32Premul(16, 16), nullptr);
  ASSERT_TRUE(provider);
  EXPECT_FALSE(provider->IsAccelerated());

  auto image = CreateImageFromVideoFrame(cpu_frame, true, provider.get(),
                                         nullptr, gfx::Rect(kTestSize));
  ASSERT_FALSE(image);
  task_environment_.RunUntilIdle();
}

TEST(VideoFrameImageUtilTest, CanvasResourceProviderDestRect) {
  base::test::SingleThreadTaskEnvironment task_environment_;
  auto cpu_frame = CreateTestFrame(kTestSize, gfx::Rect(kTestSize), kTestSize,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   media::PIXEL_FORMAT_XRGB, base::TimeDelta());

  auto provider = CreateResourceProviderForVideoFrame(
      SkImageInfo::MakeN32Premul(128, 128), nullptr);
  ASSERT_TRUE(provider);
  EXPECT_FALSE(provider->IsAccelerated());

  auto image = CreateImageFromVideoFrame(cpu_frame, true, provider.get(),
                                         nullptr, gfx::Rect(16, 16, 64, 64));
  ASSERT_TRUE(image);
  task_environment_.RunUntilIdle();
}

}  // namespace blink

"""

```