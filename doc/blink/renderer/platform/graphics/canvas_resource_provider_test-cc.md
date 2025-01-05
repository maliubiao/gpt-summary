Response:
My thinking process to analyze the provided C++ test file goes like this:

1. **Identify the Core Class Under Test:** The filename `canvas_resource_provider_test.cc` immediately points to `CanvasResourceProvider` as the central class being tested.

2. **Understand the Purpose of Tests:** Test files aim to verify the functionality and correctness of a specific unit of code. This means the test file will exercise various methods and states of `CanvasResourceProvider`.

3. **Scan for Test Cases (using `TEST_F`)**: The `TEST_F` macro indicates individual test cases within the `CanvasResourceProviderTest` fixture. I'll go through each `TEST_F` block and summarize what it's testing. This will give me a comprehensive list of the functionalities being validated.

4. **Analyze Each Test Case:** For each test case, I'll try to understand:
    * **Setup:** What kind of `CanvasResourceProvider` is being created (e.g., SharedImage, Bitmap, SwapChain)? What are the initial conditions?
    * **Action:** What methods of the `CanvasResourceProvider` are being called? What operations are being performed on the canvas?
    * **Assertion:** What are the `EXPECT_...` or `ASSERT_...` statements checking? What properties or states of the `CanvasResourceProvider` or related objects are being verified?

5. **Look for Connections to Web Technologies (JavaScript, HTML, CSS):** As I analyze each test case, I'll consider if the tested functionality has a direct or indirect relationship to how Canvas is used in web development. This involves thinking about:
    * **Drawing operations:** `drawImage`, `clear`, `drawRect`, etc., directly correspond to Canvas API methods.
    * **Image handling:** Loading, displaying, and managing images on the canvas.
    * **Performance optimizations:** Features like copy-on-write, resource recycling, and single buffering are related to optimizing Canvas rendering.
    * **Hardware acceleration:**  The distinction between `RasterMode::kGPU` and `RasterMode::kCPU` relates to whether the Canvas is rendered using the GPU.
    * **Compositing:** Direct compositing relates to how the Canvas content is integrated into the overall web page rendering.

6. **Identify Logical Reasoning and Assumptions:**  Some tests involve setting up conditions and verifying outcomes based on expected behavior. I'll try to extract the underlying logic and the assumptions made in those tests. For example, the tests involving `kCanvas2DReclaimUnusedResources` assume a certain timing mechanism for resource cleanup.

7. **Spot Potential User/Programming Errors:** By examining the test cases, I can sometimes infer common mistakes developers might make when using the Canvas API or the underlying `CanvasResourceProvider` implementation. For instance, not properly releasing resources or misunderstanding the implications of copy-on-write.

8. **Synthesize and Organize:**  Finally, I'll organize the collected information into a structured answer, addressing the specific points raised in the prompt: functionality, relationship to web technologies, logical reasoning, and common errors. I'll use clear examples and explanations to illustrate the concepts.

**Self-Correction/Refinement during the process:**

* **Initial broad sweep:** My first pass through the test cases might be a bit superficial, just identifying the main functionality being touched.
* **Deeper dive:** I then go back and examine the assertions more carefully to understand the nuances of what's being tested. For example, not just "resource recycling" but *how* it's being recycled and under what conditions.
* **Connecting to web tech:** I might initially miss some indirect connections to web technologies. I'll revisit the test cases with a specific focus on how the tested behavior manifests in a browser context.
* **Clarifying assumptions:** Sometimes the logic in a test isn't immediately obvious. I'll need to reread the code and the test description to understand the underlying assumptions being made.
* **Improving examples:** My initial examples might be too abstract. I'll try to make them more concrete and relatable to real-world web development scenarios.

By following this iterative and analytical process, I can arrive at a comprehensive and accurate understanding of the `canvas_resource_provider_test.cc` file and its implications.
好的，让我们来分析一下 `blink/renderer/platform/graphics/canvas_resource_provider_test.cc` 文件的功能。

**核心功能：**

这个文件是 Chromium Blink 引擎中 `CanvasResourceProvider` 类的单元测试文件。它的主要功能是验证 `CanvasResourceProvider` 类的各种行为和功能是否符合预期。

**具体功能点 (从测试用例分析):**

* **资源提供类型测试:**
    * 测试创建和管理不同类型的 `CanvasResourceProvider`，包括：
        * `SharedImageProvider` (基于共享内存的纹理)
        * `BitmapProvider` (基于位图)
        * `SharedBitmapProvider` (基于共享内存的位图)
        * `SwapChainProvider` (用于视频等场景的交换链)
        * `PassThroughProvider` (用于直接使用外部纹理)
    * 验证不同类型的 Provider 的特性，例如是否加速、是否支持直接合成、是否支持单缓冲等。
* **共享内存管理 (SharedImageProvider):**
    * 测试 `GetBackingClientSharedImageForExternalWrite` 方法，验证在需要额外用途时，能否正确创建或复用底层的 `ClientSharedImage`。
    * 测试共享内存资源的回收和复用机制，包括正常回收和 LastUnrefCallback 的场景。
    * 测试禁用 copy-on-write 功能的影响。
* **资源生命周期管理:**
    * 测试资源的生产(`ProduceCanvasResource`)、更新和回收机制。
    * 测试未使用资源的回收机制（通过 `kCanvas2DReclaimUnusedResources` feature flag 控制）。
    * 测试在特定条件下（例如资源还很新）不进行回收。
* **快照功能 (Snapshot):**
    * 测试 `Snapshot` 方法能否正确生成 Canvas 内容的静态位图 (`StaticBitmapImage`)。
    * 验证在 Canvas 内容更新后，快照会发生变化。
    * 验证资源在快照被释放后可以被回收。
* **最大纹理尺寸限制:**
    * 测试当 Canvas 尺寸超过最大纹理尺寸 (`kMaxTextureSize`) 时，不同类型的 `CanvasResourceProvider` 的行为。
* **直接合成 (Direct Compositing):**
    * 验证不同类型的 Provider 是否支持直接合成。
* **单缓冲 (Single Buffering):**
    * 验证不同类型的 Provider 是否支持单缓冲以及如何启用。
* **图像缓存 (Image Cache):**
    * 测试 `MemoryManagedPaintCanvas` 的图像缓存功能，验证 `drawImage` 等操作是否会触发图像的解码和缓存。
    * 测试图像锁定的机制以及达到缓存限制后的行为。
    * 测试在 GPU Context 丢失时，图像缓存的处理。
* **Canvas 操作和 Flush:**
    * 测试 `FlushCanvas` 方法，验证其是否能正确释放 Canvas 上的绘图操作。
    * 测试在存在 side recording (用于 Canvas 2D layers) 时，`FlushCanvas` 的行为。
* **与其他模块的交互:**
    * 虽然测试的是 `CanvasResourceProvider`，但也间接涉及了与 `CanvasResourceDispatcher`、`SharedGpuContext`、`cc::DecodeCache` 等模块的交互。
* **GPU 内存缓冲 (GpuMemoryBuffer):**
    * 测试 `CanvasResourceProvider` 与 GPU 内存缓冲的集成。
* **外部资源导入 (ImportResource):**
    * 测试导入外部纹理资源的功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`CanvasResourceProvider` 是 Canvas API 的底层实现关键部分，它负责管理 Canvas 渲染所需的图形资源。

1. **JavaScript `<canvas>` 元素和 Canvas API:**
   * **功能关系:** 当 JavaScript 代码通过 `<canvas>` 元素获取 2D 渲染上下文 (e.g., `canvas.getContext('2d')`) 并调用绘图 API (如 `ctx.fillRect()`, `ctx.drawImage()`) 时，`CanvasResourceProvider` 会被用来创建和管理用于存储 Canvas 内容的图形资源（例如，一块 GPU 纹理或一块系统内存）。
   * **举例说明:**
     ```html
     <canvas id="myCanvas" width="200" height="100"></canvas>
     <script>
Prompt: 
```
这是目录为blink/renderer/platform/graphics/canvas_resource_provider_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"

#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "build/build_config.h"
#include "cc/test/paint_image_matchers.h"
#include "cc/test/skia_common.h"
#include "components/viz/common/resources/release_callback.h"
#include "components/viz/test/test_context_provider.h"
#include "components/viz/test/test_gles2_interface.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_dispatcher.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/test/fake_gles2_interface.h"
#include "third_party/blink/renderer/platform/graphics/test/fake_web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_memory_buffer_test_platform.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_test_utils.h"
#include "third_party/blink/renderer/platform/graphics/test/test_webgraphics_shared_image_interface_provider.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/buffer_types.h"

using testing::_;
using testing::InSequence;
using testing::Return;
using testing::Test;

namespace blink {
namespace {

constexpr int kMaxTextureSize = 1024;

class MockCanvasResourceDispatcherClient
    : public CanvasResourceDispatcherClient {
 public:
  MockCanvasResourceDispatcherClient() = default;

  MOCK_METHOD0(BeginFrame, bool());
  MOCK_METHOD1(SetFilterQualityInResource, void(cc::PaintFlags::FilterQuality));
};

class ImageTrackingDecodeCache : public cc::StubDecodeCache {
 public:
  ImageTrackingDecodeCache() = default;
  ~ImageTrackingDecodeCache() override { EXPECT_EQ(num_locked_images_, 0); }

  cc::DecodedDrawImage GetDecodedImageForDraw(
      const cc::DrawImage& image) override {
    EXPECT_FALSE(disallow_cache_use_);

    ++num_locked_images_;
    ++max_locked_images_;
    decoded_images_.push_back(image);
    SkBitmap bitmap;
    bitmap.allocPixelsFlags(SkImageInfo::MakeN32Premul(10, 10),
                            SkBitmap::kZeroPixels_AllocFlag);
    sk_sp<SkImage> sk_image = SkImages::RasterFromBitmap(bitmap);
    return cc::DecodedDrawImage(
        sk_image, nullptr, SkSize::Make(0, 0), SkSize::Make(1, 1),
        cc::PaintFlags::FilterQuality::kLow, !budget_exceeded_);
  }

  void set_budget_exceeded(bool exceeded) { budget_exceeded_ = exceeded; }
  void set_disallow_cache_use(bool disallow) { disallow_cache_use_ = disallow; }

  void DrawWithImageFinished(
      const cc::DrawImage& image,
      const cc::DecodedDrawImage& decoded_image) override {
    EXPECT_FALSE(disallow_cache_use_);
    num_locked_images_--;
  }

  const Vector<cc::DrawImage>& decoded_images() const {
    return decoded_images_;
  }
  int num_locked_images() const { return num_locked_images_; }
  int max_locked_images() const { return max_locked_images_; }

 private:
  Vector<cc::DrawImage> decoded_images_;
  int num_locked_images_ = 0;
  int max_locked_images_ = 0;
  bool budget_exceeded_ = false;
  bool disallow_cache_use_ = false;
};

class CanvasResourceProviderTest : public Test {
 public:
  void SetUp() override {
    test_context_provider_ = viz::TestContextProvider::Create();
    auto* test_gl = test_context_provider_->UnboundTestContextGL();
    test_gl->set_max_texture_size(kMaxTextureSize);
    test_gl->set_supports_gpu_memory_buffer_format(gfx::BufferFormat::RGBA_8888,
                                                   true);
    test_gl->set_supports_gpu_memory_buffer_format(gfx::BufferFormat::BGRA_8888,
                                                   true);
    test_gl->set_supports_gpu_memory_buffer_format(gfx::BufferFormat::RGBA_F16,
                                                   true);

    gpu::SharedImageCapabilities shared_image_caps;
    shared_image_caps.supports_scanout_shared_images = true;
    shared_image_caps.shared_image_swap_chain = true;
    test_context_provider_->SharedImageInterface()->SetCapabilities(
        shared_image_caps);

    InitializeSharedGpuContextGLES2(test_context_provider_.get(),
                                    &image_decode_cache_);
    context_provider_wrapper_ = SharedGpuContext::ContextProviderWrapper();
  }

  void TearDown() override { SharedGpuContext::Reset(); }

 protected:
  test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  ImageTrackingDecodeCache image_decode_cache_;
  scoped_refptr<viz::TestContextProvider> test_context_provider_;
  base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper_;
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform_;
};

TEST_F(CanvasResourceProviderTest,
       GetBackingClientSharedImageForExternalWrite) {
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);
  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT |
      gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, shared_image_usage_flags);

  auto client_si = provider->GetBackingClientSharedImageForExternalWrite(
      /*internal_access_sync_token=*/nullptr, gpu::SharedImageUsageSet());

  // When supplied required usages that the backing SI already supports, that
  // backing SI should be returned.
  auto client_si_with_no_new_usage_required =
      provider->GetBackingClientSharedImageForExternalWrite(
          /*internal_access_sync_token=*/nullptr,
          gpu::SHARED_IMAGE_USAGE_SCANOUT);
  EXPECT_EQ(client_si_with_no_new_usage_required, client_si);

  // When supplied required usages that the backing SI does not support, a new
  // backing SI should be created that supports the required usages.
  auto client_si_with_webgpu_usage_required =
      provider->GetBackingClientSharedImageForExternalWrite(
          /*internal_access_sync_token=*/nullptr,
          gpu::SHARED_IMAGE_USAGE_WEBGPU_READ);
  EXPECT_NE(client_si_with_webgpu_usage_required, client_si);
  EXPECT_TRUE(client_si_with_webgpu_usage_required->usage().HasAll(
      shared_image_usage_flags));
  EXPECT_TRUE(client_si_with_webgpu_usage_required->usage().Has(
      gpu::SHARED_IMAGE_USAGE_WEBGPU_READ));

  // That new backing SI should then be returned on subsequent calls with
  // already-supported usages.
  client_si_with_no_new_usage_required =
      provider->GetBackingClientSharedImageForExternalWrite(
          /*internal_access_sync_token=*/nullptr,
          gpu::SHARED_IMAGE_USAGE_SCANOUT);
  EXPECT_EQ(client_si_with_no_new_usage_required,
            client_si_with_webgpu_usage_required);
}

TEST_F(CanvasResourceProviderTest, CanvasResourceProviderAcceleratedOverlay) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT |
      gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, shared_image_usage_flags);

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_TRUE(provider->IsAccelerated());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  EXPECT_TRUE(provider->SupportsSingleBuffering());
  // As it is an CanvasResourceProviderSharedImage and an accelerated canvas, it
  // will internally force it to RGBA8, or BGRA8 on MacOS
#if BUILDFLAG(IS_MAC)
  EXPECT_TRUE(provider->GetSkImageInfo() ==
              kInfo.makeColorType(kBGRA_8888_SkColorType));
#else
  EXPECT_TRUE(provider->GetSkImageInfo() ==
              kInfo.makeColorType(kRGBA_8888_SkColorType));
#endif

  EXPECT_FALSE(provider->IsSingleBuffered());
  provider->TryEnableSingleBuffering();
  EXPECT_TRUE(provider->IsSingleBuffered());
}

TEST_F(CanvasResourceProviderTest, CanvasResourceProviderTexture) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, gpu::SharedImageUsageSet());

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_TRUE(provider->IsAccelerated());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  EXPECT_FALSE(provider->SupportsSingleBuffering());
  // As it is an CanvasResourceProviderSharedImage and an accelerated canvas, it
  // will internally force it to kRGBA8
  EXPECT_EQ(provider->GetSkImageInfo(),
            kInfo.makeColorType(kRGBA_8888_SkColorType));

  EXPECT_FALSE(provider->IsSingleBuffered());
}

TEST_F(CanvasResourceProviderTest, CanvasResourceProviderUnacceleratedOverlay) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kCPU, shared_image_usage_flags);

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_FALSE(provider->IsAccelerated());
  EXPECT_TRUE(provider->SupportsDirectCompositing());

  // We do not support single buffering for unaccelerated low latency canvas.
  EXPECT_FALSE(provider->SupportsSingleBuffering());

  EXPECT_EQ(provider->GetSkImageInfo(), kInfo);

  EXPECT_FALSE(provider->IsSingleBuffered());
}

std::unique_ptr<CanvasResourceProvider> MakeCanvasResourceProvider(
    RasterMode raster_mode,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper>
        context_provider_wrapper) {
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);
  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;

  return CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper, raster_mode, shared_image_usage_flags);
}

scoped_refptr<CanvasResource> UpdateResource(CanvasResourceProvider* provider) {
  provider->ProduceCanvasResource(FlushReason::kTesting);
  // Resource updated after draw.
  provider->Canvas().clear(SkColors::kWhite);
  return provider->ProduceCanvasResource(FlushReason::kTesting);
}

void EnsureResourceRecycled(CanvasResourceProvider* provider,
                            scoped_refptr<CanvasResource>&& resource) {
  viz::TransferableResource transferable_resource;
  CanvasResource::ReleaseCallback release_callback;
  auto sync_token = resource->GetSyncToken();
  CHECK(resource->PrepareTransferableResource(
      &transferable_resource, &release_callback,
      /*needs_verified_synctoken=*/false));
  std::move(release_callback).Run(std::move(resource), sync_token, false);
}

TEST_F(CanvasResourceProviderTest,
       CanvasResourceProviderSharedImageResourceRecycling) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, shared_image_usage_flags);

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_TRUE(provider->IsAccelerated());
  EXPECT_FALSE(provider->IsSingleBuffered());
  EXPECT_FALSE(provider->SupportsSingleBuffering());
  // As it is an CanvasResourceProviderSharedImage and an accelerated canvas, it
  // will internally force it to RGBA8, or BGRA8 on MacOS
#if BUILDFLAG(IS_MAC)
  EXPECT_TRUE(provider->GetSkImageInfo() ==
              kInfo.makeColorType(kBGRA_8888_SkColorType));
#else
  EXPECT_TRUE(provider->GetSkImageInfo() ==
              kInfo.makeColorType(kRGBA_8888_SkColorType));
#endif

  // Same resource and sync token if we query again without updating.
  auto resource = provider->ProduceCanvasResource(FlushReason::kTesting);
  auto sync_token = resource->GetSyncToken();
  ASSERT_TRUE(resource);
  EXPECT_EQ(resource, provider->ProduceCanvasResource(FlushReason::kTesting));
  EXPECT_EQ(sync_token, resource->GetSyncToken());

  auto new_resource = UpdateResource(provider.get());
  EXPECT_NE(resource, new_resource);
  EXPECT_NE(resource->GetSyncToken(), new_resource->GetSyncToken());
  auto* resource_ptr = resource.get();

  EnsureResourceRecycled(provider.get(), std::move(resource));

  provider->Canvas().clear(SkColors::kBlack);
  auto resource_again = provider->ProduceCanvasResource(FlushReason::kTesting);
  EXPECT_EQ(resource_ptr, resource_again);
  EXPECT_NE(sync_token, resource_again->GetSyncToken());
}

TEST_F(CanvasResourceProviderTest, CanvasResourceProviderUnusedResources) {
  base::test::ScopedFeatureList feature_list{kCanvas2DReclaimUnusedResources};

  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  auto resource = provider->ProduceCanvasResource(FlushReason::kTesting);
  auto new_resource = UpdateResource(provider.get());
  ASSERT_NE(resource, new_resource);
  ASSERT_NE(resource->GetSyncToken(), new_resource->GetSyncToken());

  EXPECT_FALSE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());
  EnsureResourceRecycled(provider.get(), std::move(resource));
  // The reclaim task has been posted.
  EXPECT_TRUE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());

  // There is a ready-to-reuse resource
  EXPECT_EQ(1u, provider->CanvasResources().size());
  task_environment_.FastForwardBy(
      CanvasResourceProvider::kUnusedResourceExpirationTime);
  // The resource is freed, don't repost the task.
  EXPECT_EQ(0u, provider->CanvasResources().size());
  EXPECT_FALSE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());
}

TEST_F(CanvasResourceProviderTest,
       CanvasResourceProviderDontReclaimUnusedResourcesWhenFeatureIsDisabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(kCanvas2DReclaimUnusedResources);

  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  auto resource = provider->ProduceCanvasResource(FlushReason::kTesting);
  auto new_resource = UpdateResource(provider.get());
  ASSERT_NE(resource, new_resource);
  ASSERT_NE(resource->GetSyncToken(), new_resource->GetSyncToken());
  EXPECT_FALSE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());
  EnsureResourceRecycled(provider.get(), std::move(resource));
  // There is a ready-to-reuse resource
  EXPECT_EQ(1u, provider->CanvasResources().size());
  // No task posted.
  EXPECT_FALSE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());
}

TEST_F(CanvasResourceProviderTest,
       CanvasResourceProviderUnusedResourcesAreNotCollectedWhenYoung) {
  base::test::ScopedFeatureList feature_list{kCanvas2DReclaimUnusedResources};

  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  auto resource = provider->ProduceCanvasResource(FlushReason::kTesting);
  auto new_resource = UpdateResource(provider.get());
  ASSERT_NE(resource, new_resource);
  ASSERT_NE(resource->GetSyncToken(), new_resource->GetSyncToken());
  EXPECT_FALSE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());
  EnsureResourceRecycled(provider.get(), std::move(resource));
  EXPECT_TRUE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());

  // There is a ready-to-reuse resource
  EXPECT_EQ(1u, provider->CanvasResources().size());
  task_environment_.FastForwardBy(
      CanvasResourceProvider::kUnusedResourceExpirationTime - base::Seconds(1));
  // The reclaim task hasn't run yet.
  EXPECT_TRUE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());

  resource = UpdateResource(provider.get());
  EXPECT_EQ(0u, provider->CanvasResources().size());
  new_resource = UpdateResource(provider.get());
  ASSERT_NE(resource, new_resource);
  ASSERT_NE(resource->GetSyncToken(), new_resource->GetSyncToken());

  EnsureResourceRecycled(provider.get(), std::move(resource));
  EXPECT_EQ(1u, provider->CanvasResources().size());
  task_environment_.FastForwardBy(base::Seconds(1));

  // Too young, no release yet.
  EXPECT_EQ(1u, provider->CanvasResources().size());
  // But re-post the task to free it.
  EXPECT_TRUE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());

  task_environment_.FastForwardBy(
      CanvasResourceProvider::kUnusedResourceExpirationTime);
  // Now it's collected.
  EXPECT_EQ(0u, provider->CanvasResources().size());
  // And no new task is posted.
  EXPECT_FALSE(
      provider->unused_resources_reclaim_timer_is_running_for_testing());
}

TEST_F(CanvasResourceProviderTest,
       CanvasResourceProviderSharedImageStaticBitmapImage) {
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, shared_image_usage_flags);

  ASSERT_TRUE(provider->IsValid());

  // Same resource returned until the canvas is updated.
  auto image = provider->Snapshot(FlushReason::kTesting);
  ASSERT_TRUE(image);
  auto new_image = provider->Snapshot(FlushReason::kTesting);
  EXPECT_EQ(image->GetMailboxHolder().mailbox,
            new_image->GetMailboxHolder().mailbox);
  EXPECT_EQ(provider->ProduceCanvasResource(FlushReason::kTesting)
                ->GetClientSharedImage()
                ->mailbox(),
            image->GetMailboxHolder().mailbox);

  // Resource updated after draw.
  provider->Canvas().clear(SkColors::kWhite);
  provider->FlushCanvas(FlushReason::kTesting);
  new_image = provider->Snapshot(FlushReason::kTesting);
  EXPECT_NE(new_image->GetMailboxHolder().mailbox,
            image->GetMailboxHolder().mailbox);

  // Resource recycled.
  auto original_mailbox = image->GetMailboxHolder().mailbox;
  image.reset();
  provider->Canvas().clear(SkColors::kBlack);
  provider->FlushCanvas(FlushReason::kTesting);
  EXPECT_EQ(
      original_mailbox,
      provider->Snapshot(FlushReason::kTesting)->GetMailboxHolder().mailbox);
}

TEST_F(CanvasResourceProviderTest, NoRecycleIfLastRefCallback) {
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, shared_image_usage_flags);

  ASSERT_TRUE(provider->IsValid());

  scoped_refptr<StaticBitmapImage> snapshot1 =
      provider->Snapshot(FlushReason::kTesting);
  ASSERT_TRUE(snapshot1);

  // Set up a LastUnrefCallback that recycles the resource asynchronously,
  // similarly to what OffscreenCanvasPlaceholder would do.
  provider->ProduceCanvasResource(FlushReason::kTesting)
      ->SetLastUnrefCallback(
          base::BindOnce([](scoped_refptr<CanvasResource> resource) {}));

  // Resource updated after draw.
  provider->Canvas().clear(SkColors::kWhite);
  provider->FlushCanvas(FlushReason::kTesting);
  scoped_refptr<StaticBitmapImage> snapshot2 =
      provider->Snapshot(FlushReason::kTesting);
  EXPECT_NE(snapshot2->GetMailboxHolder().mailbox,
            snapshot1->GetMailboxHolder().mailbox);

  auto snapshot1_mailbox = snapshot1->GetMailboxHolder().mailbox;
  snapshot1.reset();  // resource not recycled due to LastUnrefCallback
  provider->Canvas().clear(SkColors::kBlack);
  provider->FlushCanvas(FlushReason::kTesting);
  scoped_refptr<StaticBitmapImage> snapshot3 =
      provider->Snapshot(FlushReason::kTesting);
  // confirm resource is not recycled.
  EXPECT_NE(snapshot3->GetMailboxHolder().mailbox, snapshot1_mailbox);
}

TEST_F(CanvasResourceProviderTest,
       CanvasResourceProviderSharedImageCopyOnWriteDisabled) {
  auto* fake_context = static_cast<FakeWebGraphicsContext3DProvider*>(
      context_provider_wrapper_->ContextProvider());
  auto caps = fake_context->GetCapabilities();
  caps.disable_2d_canvas_copy_on_write = true;
  fake_context->SetCapabilities(caps);

  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, shared_image_usage_flags);

  ASSERT_TRUE(provider->IsValid());

  // Disabling copy-on-write forces a copy each time the resource is queried.
  auto resource = provider->ProduceCanvasResource(FlushReason::kTesting);
  EXPECT_NE(resource->GetClientSharedImage()->mailbox(),
            provider->ProduceCanvasResource(FlushReason::kTesting)
                ->GetClientSharedImage()
                ->mailbox());
}

TEST_F(CanvasResourceProviderTest, CanvasResourceProviderBitmap) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  auto provider = CanvasResourceProvider::CreateBitmapProvider(
      kInfo, cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear);

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_FALSE(provider->IsAccelerated());
  EXPECT_FALSE(provider->SupportsDirectCompositing());
  EXPECT_FALSE(provider->SupportsSingleBuffering());
  EXPECT_TRUE(provider->GetSkImageInfo() == kInfo);

  EXPECT_FALSE(provider->IsSingleBuffered());
}

TEST_F(CanvasResourceProviderTest, CanvasResourceProviderSharedBitmap) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);
  std::unique_ptr<WebGraphicsSharedImageInterfaceProvider>
      test_web_shared_image_interface_provider =
          TestWebGraphicsSharedImageInterfaceProvider::Create();

  MockCanvasResourceDispatcherClient client;
  CanvasResourceDispatcher resource_dispatcher(
      &client, scheduler::GetSingleThreadTaskRunnerForTesting(),
      scheduler::GetSingleThreadTaskRunnerForTesting(), 1 /* client_id */,
      1 /* sink_id */, 1 /* placeholder_canvas_id */, kSize);

  auto provider = CanvasResourceProvider::CreateSharedBitmapProvider(
      kInfo, cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      resource_dispatcher.GetWeakPtr(),
      test_web_shared_image_interface_provider.get());

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_FALSE(provider->IsAccelerated());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  EXPECT_FALSE(provider->SupportsSingleBuffering());
  EXPECT_TRUE(provider->GetSkImageInfo() == kInfo);

  EXPECT_FALSE(provider->IsSingleBuffered());
  provider->TryEnableSingleBuffering();
  EXPECT_FALSE(provider->IsSingleBuffered());
}

TEST_F(CanvasResourceProviderTest,
       CanvasResourceProviderDirect2DGpuMemoryBuffer) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  const gpu::SharedImageUsageSet shared_image_usage_flags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT |
      gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE;

  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, shared_image_usage_flags);

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_TRUE(provider->IsAccelerated());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  EXPECT_TRUE(provider->SupportsSingleBuffering());
  // As it is an CanvasResourceProviderSharedImage and an accelerated canvas, it
  // will internally force it to RGBA8, or BGRA8 on MacOS
#if BUILDFLAG(IS_MAC)
  EXPECT_TRUE(provider->GetSkImageInfo() ==
              kInfo.makeColorType(kBGRA_8888_SkColorType));
#else
  EXPECT_TRUE(provider->GetSkImageInfo() ==
              kInfo.makeColorType(kRGBA_8888_SkColorType));
#endif

  EXPECT_FALSE(provider->IsSingleBuffered());
  provider->TryEnableSingleBuffering();
  EXPECT_TRUE(provider->IsSingleBuffered());
}

TEST_F(CanvasResourceProviderTest,
       CanvasResourceProviderDirect3DGpuMemoryBuffer) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  auto provider = CanvasResourceProvider::CreatePassThroughProvider(
      kInfo, cc::PaintFlags::FilterQuality::kLow, context_provider_wrapper_,
      nullptr /*resource_dispatcher */, true /*is_origin_top_left*/);

  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_TRUE(provider->IsAccelerated());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  EXPECT_TRUE(provider->SupportsSingleBuffering());
  EXPECT_TRUE(provider->GetSkImageInfo() == kInfo);

  EXPECT_FALSE(provider->IsSingleBuffered());
  provider->TryEnableSingleBuffering();
  EXPECT_TRUE(provider->IsSingleBuffered());

  auto client_si = gpu::ClientSharedImage::CreateForTesting();

  viz::TransferableResource tr;
  tr.set_mailbox(client_si->mailbox());
  tr.set_texture_target(GL_TEXTURE_2D);
  tr.set_sync_token(gpu::SyncToken());
  tr.size = kSize;
  tr.is_overlay_candidate = true;

  scoped_refptr<ExternalCanvasResource> resource =
      ExternalCanvasResource::Create(client_si, tr, viz::ReleaseCallback(),
                                     SharedGpuContext::ContextProviderWrapper(),
                                     provider->CreateWeakPtr(),
                                     cc::PaintFlags::FilterQuality::kMedium);

  // NewOrRecycledResource() would return nullptr before an ImportResource().
  EXPECT_TRUE(provider->ImportResource(resource));
  EXPECT_EQ(provider->NewOrRecycledResource(), resource);
  // NewOrRecycledResource() will always return the same |resource|.
  EXPECT_EQ(provider->NewOrRecycledResource(), resource);
}

TEST_F(CanvasResourceProviderTest, DimensionsExceedMaxTextureSize_Bitmap) {
  auto provider = CanvasResourceProvider::CreateBitmapProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize - 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear);
  EXPECT_FALSE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreateBitmapProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear);
  EXPECT_FALSE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreateBitmapProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize + 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear);
  EXPECT_FALSE(provider->SupportsDirectCompositing());
}

TEST_F(CanvasResourceProviderTest, DimensionsExceedMaxTextureSize_SharedImage) {
  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize - 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, gpu::SharedImageUsageSet());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreateSharedImageProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, gpu::SharedImageUsageSet());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreateSharedImageProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize + 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, gpu::SharedImageUsageSet());
  // The CanvasResourceProvider for SharedImage should not be created or valid
  // if the texture size is greater than the maximum value
  EXPECT_TRUE(!provider || !provider->IsValid());
}

TEST_F(CanvasResourceProviderTest, DimensionsExceedMaxTextureSize_SwapChain) {
  auto provider = CanvasResourceProvider::CreateSwapChainProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize - 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, /*resource_dispatcher=*/nullptr);
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreateSwapChainProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, /*resource_dispatcher=*/nullptr);
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreateSwapChainProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize + 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, /*resource_dispatcher=*/nullptr);

  // The CanvasResourceProvider for SwapChain should not be created or valid
  // if the texture size is greater than the maximum value
  EXPECT_TRUE(!provider || !provider->IsValid());
}

TEST_F(CanvasResourceProviderTest, DimensionsExceedMaxTextureSize_PassThrough) {
  auto provider = CanvasResourceProvider::CreatePassThroughProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize - 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow, context_provider_wrapper_,
      nullptr /* resource_dispatcher */, true /*is_origin_top_left*/);
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreatePassThroughProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow, context_provider_wrapper_,
      nullptr /* resource_dispatcher */, true /*is_origin_top_left*/);
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  provider = CanvasResourceProvider::CreatePassThroughProvider(
      SkImageInfo::MakeN32Premul(kMaxTextureSize + 1, kMaxTextureSize),
      cc::PaintFlags::FilterQuality::kLow, context_provider_wrapper_,
      nullptr /* resource_dispatcher */, true /*is_origin_top_left*/);
  // The CanvasResourceProvider for PassThrough should not be created or valid
  // if the texture size is greater than the maximum value
  EXPECT_TRUE(!provider || !provider->IsValid());
}

TEST_F(CanvasResourceProviderTest, CanvasResourceProviderDirect2DSwapChain) {
  const gfx::Size kSize(10, 10);
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  auto provider = CanvasResourceProvider::CreateSwapChainProvider(
      kInfo, cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, /*resource_dispatcher=*/nullptr);

  ASSERT_TRUE(provider);
  EXPECT_EQ(provider->Size(), kSize);
  EXPECT_TRUE(provider->IsValid());
  EXPECT_TRUE(provider->IsAccelerated());
  EXPECT_TRUE(provider->SupportsDirectCompositing());
  EXPECT_TRUE(provider->SupportsSingleBuffering());
  EXPECT_TRUE(provider->IsSingleBuffered());
  EXPECT_EQ(provider->GetSkImageInfo(), kInfo);
}

TEST_F(CanvasResourceProviderTest, FlushForImage) {
  const SkImageInfo kInfo = SkImageInfo::MakeN32Premul(10, 10);

  auto src_provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, gpu::SharedImageUsageSet());

  auto dst_provider = CanvasResourceProvider::CreateSharedImageProvider(
      kInfo, cc::PaintFlags::FilterQuality::kMedium,
      CanvasResourceProvider::ShouldInitialize::kCallClear,
      context_provider_wrapper_, RasterMode::kGPU, gpu::SharedImageUsageSet());

  MemoryManagedPaintCanvas& dst_canvas = dst_provider->Canvas();

  PaintImage paint_image = src_provider->Snapshot(FlushReason::kTesting)
                               ->PaintImageForCurrentFrame();
  PaintImage::ContentId src_content_id = paint_image.GetContentIdForFrame(0u);

  EXPECT_FALSE(dst_canvas.IsCachingImage(src_content_id));

  dst_canvas.drawImage(paint_image, 0, 0, SkSamplingOptions(), nullptr);

  EXPECT_TRUE(dst_canvas.IsCachingImage(src_content_id));

  // Modify the canvas to trigger OnFlushForImage
  src_provider->Canvas().clear(SkColors::kWhite);
  // So that all the cached draws are executed
  src_provider->ProduceCanvasResource(FlushReason::kTesting);

  // The paint canvas may have moved
  MemoryManagedPaintCanvas& new_dst_canvas = dst_provider->Canvas();

  // TODO(aaronhk): The resource on the src_provider should be the same before
  // and after the draw. Something about the program flow within
  // this testing framework (but not in layout tests) makes a reference to
  // the src_resource stick around throughout the FlushForImage call so the
  // src_resource changes in this test. Things work as expected for actual
  // browser code like canvas_to_canvas_draw.html.

  // OnFlushForImage should detect the modification of the source resource and
  // clear the cache of the destination canvas to avoid a copy-on-write.
  EXPECT_FALSE(new_dst_canvas.IsCachingImage(src_content_id));
}

TEST_F(CanvasResourceProviderTest, EnsureCCImageCacheUse) {
  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  cc::TargetColorParams target_color_params;
  Vector<cc::DrawImage> images = {
      cc::DrawImage(cc::CreateDiscardablePaintImage(gfx::Size(10, 10)), false,
                    SkIRect::MakeWH(10, 10),
                    cc::PaintFlags::FilterQuality::kNone, SkM44(), 0u,
                    target_color_params),
      cc::DrawImage(cc::CreateDiscardablePaintImage(gfx::Size(20, 20)), false,
                    SkIRect::MakeWH(5, 5), cc::PaintFlags::FilterQuality::kNone,
                    SkM44(), 0u, target_color_params)};

  provider->Canvas().drawImage(images[0].paint_image(), 0u, 0u,
                               SkSamplingOptions(), nullptr);
  provider->Canvas().drawImageRect(
      images[1].paint_image(), SkRect::MakeWH(5u, 5u), SkRect::MakeWH(5u, 5u),
      SkSamplingOptions(), nullptr, SkCanvas::kFast_SrcRectConstraint);
  provider->FlushCanvas(FlushReason::kTesting);

  EXPECT_THAT(image_decode_cache_.decoded_images(), cc::ImagesAreSame(images));
}

TEST_F(CanvasResourceProviderTest, ImagesLockedUntilCacheLimit) {
  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  Vector<cc::DrawImage> images = {
      cc::DrawImage(cc::CreateDiscardablePaintImage(gfx::Size(10, 10)), false,
                    SkIRect::MakeWH(10, 10),
                    cc::PaintFlags::FilterQuality::kNone, SkM44(), 0u,
                    cc::TargetColorParams()),
      cc::DrawImage(cc::CreateDiscardablePaintImage(gfx::Size(20, 20)), false,
                    SkIRect::MakeWH(5, 5), cc::PaintFlags::FilterQuality::kNone,
                    SkM44(), 0u, cc::TargetColorParams()),
      cc::DrawImage(cc::CreateDiscardablePaintImage(gfx::Size(20, 20)), false,
                    SkIRect::MakeWH(5, 5), cc::PaintFlags::FilterQuality::kNone,
                    SkM44(), 0u, cc::TargetColorParams())};

  // First 2 images are budgeted, they should remain locked after the op.
  provider->Canvas().drawImage(images[0].paint_image(), 0u, 0u,
                               SkSamplingOptions(), nullptr);
  provider->Canvas().drawImage(images[1].paint_image(), 0u, 0u,
                               SkSamplingOptions(), nullptr);
  provider->FlushCanvas(FlushReason::kTesting);
  EXPECT_EQ(image_decode_cache_.max_locked_images(), 2);
  EXPECT_EQ(image_decode_cache_.num_locked_images(), 0);

  // Next image is not budgeted, we should unlock all images other than the last
  // image.
  image_decode_cache_.set_budget_exceeded(true);
  provider->Canvas().drawImage(images[2].paint_image(), 0u, 0u,
                               SkSamplingOptions(), nullptr);
  provider->FlushCanvas(FlushReason::kTesting);
  EXPECT_EQ(image_decode_cache_.max_locked_images(), 3);
  EXPECT_EQ(image_decode_cache_.num_locked_images(), 0);
}

TEST_F(CanvasResourceProviderTest, QueuesCleanupTaskForLockedImages) {
  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  cc::DrawImage image(cc::CreateDiscardablePaintImage(gfx::Size(10, 10)), false,
                      SkIRect::MakeWH(10, 10),
                      cc::PaintFlags::FilterQuality::kNone, SkM44(), 0u,
                      cc::TargetColorParams());
  provider->Canvas().drawImage(image.paint_image(), 0u, 0u, SkSamplingOptions(),
                               nullptr);

  provider->FlushCanvas(FlushReason::kTesting);
  EXPECT_EQ(image_decode_cache_.max_locked_images(), 1);
  EXPECT_EQ(image_decode_cache_.num_locked_images(), 0);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(image_decode_cache_.num_locked_images(), 0);
}

TEST_F(CanvasResourceProviderTest, ImageCacheOnContextLost) {
  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  Vector<cc::DrawImage> images = {
      cc::DrawImage(cc::CreateDiscardablePaintImage(gfx::Size(10, 10)), false,
                    SkIRect::MakeWH(10, 10),
                    cc::PaintFlags::FilterQuality::kNone, SkM44(), 0u,
                    cc::TargetColorParams()),
      cc::DrawImage(cc::CreateDiscardablePaintImage(gfx::Size(20, 20)), false,
                    SkIRect::MakeWH(5, 5), cc::PaintFlags::FilterQuality::kNone,
                    SkM44(), 0u, cc::TargetColorParams())};
  provider->Canvas().drawImage(images[0].paint_image(), 0u, 0u,
                               SkSamplingOptions(), nullptr);

  // Lose the context and ensure that the image provider is not used.
  provider->OnContextDestroyed();
  // We should unref all images on the cache when the context is destroyed.
  EXPECT_EQ(image_decode_cache_.num_locked_images(), 0);
  image_decode_cache_.set_disallow_cache_use(true);
  provider->Canvas().drawImage(images[1].paint_image(), 0u, 0u,
                               SkSamplingOptions(), nullptr);
}

TEST_F(CanvasResourceProviderTest, FlushCanvasReleasesAllReleasableOps) {
  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  EXPECT_FALSE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_FALSE(provider->Recorder().HasReleasableDrawOps());

  provider->Canvas().drawRect({0, 0, 10, 10}, cc::PaintFlags());
  EXPECT_TRUE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_TRUE(provider->Recorder().HasReleasableDrawOps());

  // `FlushCanvas` releases all ops, leaving the canvas clean.
  provider->FlushCanvas(FlushReason::kTesting);
  EXPECT_FALSE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_FALSE(provider->Recorder().HasReleasableDrawOps());
}

TEST_F(CanvasResourceProviderTest, FlushCanvasReleasesAllOpsOutsideLayers) {
  std::unique_ptr<CanvasResourceProvider> provider =
      MakeCanvasResourceProvider(RasterMode::kGPU, context_provider_wrapper_);

  EXPECT_FALSE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_FALSE(provider->Recorder().HasReleasableDrawOps());
  EXPECT_FALSE(provider->Recorder().HasSideRecording());

  // Side canvases (used for canvas 2d layers) cannot be flushed until closed.
  // Open one and validate that flushing the canvas only flushed that main
  // recording, not the side one.
  provider->Canvas().drawRect({0, 0, 10, 10}, cc::PaintFlags());
  provider->Recorder().BeginSideRecording();
  provider->Canvas().saveLayerAlphaf(0.5f);
  provider->Canvas().drawRect({0, 0, 10, 10}, cc::PaintFlags());
  EXPECT_TRUE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_TRUE(provider->Recorder().HasReleasableDrawOps());
  EXPECT_TRUE(provider->Recorder().HasSideRecording());

  provider->FlushCanvas(FlushReason::kTesting);
  EXPECT_TRUE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_FALSE(provider->Recorder().HasReleasableDrawOps());
  EXPECT_TRUE(provider->Recorder().HasSideRecording());

  provider->Canvas().restore();
  EXPECT_TRUE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_FALSE(provider->Recorder().HasReleasableDrawOps());
  EXPECT_TRUE(provider->Recorder().HasSideRecording());

  provider->Recorder().EndSideRecording();
  EXPECT_TRUE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_TRUE(provider->Recorder().HasReleasableDrawOps());
  EXPECT_FALSE(provider->Recorder().HasSideRecording());

  provider->FlushCanvas(FlushReason::kTesting);
  EXPECT_FALSE(provider->Recorder().HasRecordedDrawOps());
  EXPECT_FALSE(provider->Recorder().HasReleasableDrawOps());
  EXPECT_FALSE(provider->Recorder().HasSideRecording());
}

}  // namespace
}  // namespace blink

"""

```