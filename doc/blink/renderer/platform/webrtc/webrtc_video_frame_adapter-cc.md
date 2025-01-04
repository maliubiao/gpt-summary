Response:
My thinking process to answer the request about `webrtc_video_frame_adapter.cc` goes like this:

1. **Understand the Core Purpose:** The file name itself is a big clue: "webrtc_video_frame_adapter". This strongly suggests its role is to bridge the gap between the Chromium media pipeline's `media::VideoFrame` and WebRTC's `webrtc::VideoFrameBuffer` (specifically `webrtc::I420BufferInterface`). The word "adapter" is key here.

2. **High-Level Functionality Extraction (Keywords and Concepts):** I scan the code for key terms and concepts:
    * `#include`:  This tells me about dependencies. `media/base/video_frame.h`, `third_party/webrtc/`, `gpu/command_buffer/`, `cc/trees/`, `blink/renderer/platform/` are important namespaces indicating areas of interaction (media, WebRTC, GPU, Compositor, Blink platform).
    * `SharedResources`: This suggests a mechanism for sharing resources across instances of the adapter.
    * `ConvertToWebRtcVideoFrameBuffer`: This is a crucial function name indicating the primary conversion happening.
    * `ScaledBuffer`, `ScaledBufferSize`: Indicate handling of cropping and scaling.
    * `GpuMemoryBuffer`, `SharedImage`: Point to GPU integration and efficient memory sharing.
    * `RasterContextProvider`:  Highlights the interaction with the GPU rasterization process.
    * `media::VideoFrame`, `webrtc::VideoFrameBuffer`: The core types being adapted.
    * `AdaptBestFrame`:  Suggests optimization strategies for frame adaptation, potentially involving scaling from previously adapted frames.
    * `Feedback`: Indicates a way to communicate requirements back to the video capture pipeline.

3. **Categorize Functionality:** Based on the keywords, I group the functionality into logical categories:

    * **Adaptation/Conversion:**  The core function of converting `media::VideoFrame` to WebRTC's buffer format.
    * **Scaling and Cropping:**  The ability to adjust the video frame dimensions.
    * **GPU Integration:**  Leveraging GPU resources for efficiency (shared memory, texture mapping).
    * **Resource Management:**  Sharing and managing resources like GPU contexts and frame pools.
    * **Feedback Mechanism:** Communicating requirements (like needing pre-mapped frames) to the video source.

4. **Elaborate on Each Functionality:**  I go deeper into each category, explaining *how* the adaptation occurs.

    * **Adaptation:** Explain the `ConvertToWebRtcVideoFrameBuffer` function and the different potential underlying buffer types (raw memory, GPU memory).
    * **Scaling/Cropping:** Detail the `CropAndScale` methods and the `ScaledBuffer` class.
    * **GPU Integration:** Explain the use of `GpuMemoryBuffer`, `SharedImage`, and the role of `RasterContextProvider`. Mention the optimization of GPU readback.
    * **Resource Management:** Describe the `SharedResources` class and its role in managing the GPU context and frame pool.
    * **Feedback:** Explain how `SetFeedback` and `GetFeedback` are used to communicate capture requirements.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  I consider how this C++ code in the browser's rendering engine relates to what web developers can do.

    * **JavaScript:**  Focus on the `getUserMedia` API, the `MediaStreamTrack`, and how the adapted video frames eventually reach the JavaScript layer for use with WebRTC.
    * **HTML:** Briefly mention the `<video>` element as the display target.
    * **CSS:**  Explain how CSS properties can affect the *display* of the video, but the adapter works on the *underlying data*.

6. **Logical Reasoning with Examples (Hypothetical Inputs/Outputs):**  I create simple scenarios to illustrate the adapter's behavior.

    * **Basic Conversion:** Show a `media::VideoFrame` with specific dimensions and format being converted to an `I420BufferInterface`.
    * **Scaling:** Demonstrate how cropping and scaling parameters change the output buffer's dimensions.
    * **GPU Path:** Illustrate the use of a `media::VideoFrame` backed by a GPU texture and its conversion to a GPU-backed WebRTC buffer.

7. **Common Usage Errors:**  I think about potential mistakes developers or the browser itself might make when dealing with video frames.

    * **Incorrect Dimensions:**  Provide an example of providing crop/scale parameters that exceed the original frame boundaries.
    * **Format Mismatch:**  Highlight the expectation of I420 for software encoding and potential issues with other formats if not handled correctly.
    * **Synchronization Issues:**  Mention the importance of synchronizing GPU operations.

8. **Review and Refine:** I reread my answer, ensuring it's clear, concise, and addresses all parts of the original request. I check for technical accuracy and logical flow. I try to anticipate any follow-up questions someone might have. For instance, initially, I might have just said "it converts video frames," but then I elaborate on *how* and the different paths it can take (CPU vs. GPU).

By following these steps, I can build a comprehensive and informative answer that explains the functionality of `webrtc_video_frame_adapter.cc` and its connections to web technologies and potential usage issues. The key is to break down the problem into smaller, manageable parts and then connect those parts back together into a coherent explanation.
`blink/renderer/platform/webrtc/webrtc_video_frame_adapter.cc` 这个文件是 Chromium Blink 引擎中用于将 Chromium 的 `media::VideoFrame` 适配成 WebRTC 所需的 `webrtc::VideoFrameBuffer` 的适配器。它主要负责在 Blink 的视频处理流程和 WebRTC 的视频处理流程之间建立桥梁，确保视频帧可以在这两个系统之间有效地传递和使用。

以下是该文件的主要功能：

**1. 视频帧格式转换和适配:**

*   **核心功能:** 将 Chromium 的 `media::VideoFrame` 对象转换为 WebRTC 的 `webrtc::VideoFrameBuffer` 接口，特别是 `webrtc::I420BufferInterface`。这是 WebRTC 内部最常用的视频帧表示格式。
*   **支持多种存储类型:**  能够处理不同存储类型的 `media::VideoFrame`，包括：
    *   内存映射的帧 (Memory-mapped frames)
    *   GPU 纹理 (GPU textures)
    *   GPU 内存缓冲区 (GPU memory buffers)
*   **颜色空间转换:**  虽然代码中没有显式的颜色空间转换逻辑，但它会传递 `media::VideoFrame` 的颜色空间信息，以便后续处理。

**2. 视频帧的裁剪和缩放 (Cropping and Scaling):**

*   **按需裁剪和缩放:** 提供了 `CropAndScale` 方法，允许在将 `media::VideoFrame` 转换为 WebRTC 的 `VideoFrameBuffer` 时，根据需要进行裁剪和缩放操作。这对于处理不同分辨率或需要特定视角的视频流非常重要。
*   **优化缩放:**  会尝试利用之前适配过的帧进行缩放，以减少计算量，提高效率。例如，如果已经有一个较高分辨率的适配帧，需要生成一个较低分辨率的帧时，会从已有的高分辨率帧进行缩放，而不是从原始帧重新适配。

**3. GPU 资源管理和利用:**

*   **GPU 加速:**  尝试利用 GPU 进行视频帧的处理，例如，当 `media::VideoFrame` 是 GPU 纹理时，可以尝试直接在 GPU 上进行转换或拷贝，以提高性能。
*   **SharedImage 支持:**  利用 `gpu::SharedImage` 机制，可以在 GPU 进程和渲染进程之间高效地共享视频帧数据，避免不必要的拷贝。
*   **GpuMemoryBuffer 支持:**  支持使用 `gfx::GpuMemoryBuffer` 作为视频帧的底层存储，这是一种用于跨进程共享 GPU 资源的机制。
*   **RasterContextProvider:**  使用 `viz::RasterContextProvider` 来获取 GPU 上下文，以便执行 GPU 相关的操作。

**4. 资源共享 (Shared Resources):**

*   **`SharedResources` 类:**  维护了一些在多个 `WebRtcVideoFrameAdapter` 实例之间共享的资源，例如 GPU 上下文、帧池等。这可以避免重复创建资源，提高内存使用效率。
*   **帧池 (`media::RenderableGpuMemoryBufferVideoFramePool`):**  用于管理和重用 GPU 内存缓冲区，减少内存分配和释放的开销。

**5. 反馈机制 (Feedback):**

*   **`SetFeedback` 和 `GetFeedback`:**  提供了反馈机制，允许适配器向视频捕获器 (video capturer) 传递信息，例如是否需要预先映射 (pre-mapped) 的帧。这可以优化视频捕获流程。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件本身不直接与 JavaScript, HTML, CSS 代码交互。它的作用是在 Blink 引擎的底层处理视频数据，为上层的 JavaScript API (如 `getUserMedia`, WebRTC API) 提供必要的视频帧数据。

**举例说明:**

*   **JavaScript (`getUserMedia`):**  当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 获取摄像头视频流时，Blink 引擎会启动视频捕获流程。捕获到的原始视频帧会被封装成 `media::VideoFrame` 对象。
*   **C++ 适配器:**  `WebRtcVideoFrameAdapter` 接收到这些 `media::VideoFrame`，并将其转换为 WebRTC 的 `webrtc::VideoFrameBuffer` 格式，以便 WebRTC 的编码器或其他处理模块使用。
*   **WebRTC API (JavaScript):**  最终，转换后的视频帧数据可以通过 WebRTC 的 JavaScript API (例如 `RTCPeerConnection.addTrack()`) 发送给远端。
*   **HTML (`<video>` 元素):**  在接收端，通过 WebRTC 接收到的视频流可以通过 JavaScript 设置到 HTML 的 `<video>` 元素中进行显示。`WebRtcVideoFrameAdapter` 的反向过程（将 WebRTC 的 `VideoFrameBuffer` 转换为可以在渲染器中显示的格式）也会涉及到类似的适配过程，但可能在不同的文件中处理。
*   **CSS:** CSS 主要负责控制 `<video>` 元素的样式和布局，与 `WebRtcVideoFrameAdapter` 的核心功能没有直接关系。CSS 不会影响视频帧数据的转换和适配过程。

**逻辑推理的假设输入与输出:**

**假设输入:**

*   一个来自摄像头的 `media::VideoFrame` 对象，格式为 `PIXEL_FORMAT_YUY2`，大小为 640x480，存储类型为内存映射。
*   WebRTC 需要的视频帧格式为 `I420`，大小为 320x240。

**输出:**

*   一个 `webrtc::I420BufferInterface` 对象，其数据格式为 `I420`，大小为 320x240。
*   在这个转换过程中，`WebRtcVideoFrameAdapter` 会执行以下操作：
    1. 将 `YUY2` 格式的 `media::VideoFrame` 转换为 `I420` 格式。
    2. 将视频帧的大小从 640x480 缩放到 320x240。

**涉及用户或编程常见的使用错误:**

1. **假设输出格式错误:**  WebRTC 通常期望 `I420` 格式的视频帧进行编码。如果用户或上层代码错误地假设或要求其他格式，可能会导致编码失败或兼容性问题。
    *   **错误示例:**  JavaScript 代码错误地配置 WebRTC 编码器以处理 `NV12` 格式，但 `WebRtcVideoFrameAdapter` 默认输出的是 `I420`。
2. **裁剪或缩放参数错误:**  如果传递给 `CropAndScale` 的参数超出原始视频帧的边界，或者缩放比例不合理，会导致输出的视频帧数据不正确或崩溃。
    *   **错误示例:**  调用 `CropAndScale` 时，`offset_x` 或 `offset_y` 的值大于原始帧的宽度或高度，或者 `crop_width` 或 `crop_height` 导致裁剪区域超出原始帧范围。
3. **GPU 资源未正确初始化或不可用:**  如果 GPU 相关的资源（例如 `RasterContextProvider`）未能正确初始化或当前系统不支持 GPU 加速，尝试使用 GPU 进行帧处理可能会失败。
    *   **错误示例:**  在没有可用 GPU 的环境下，代码尝试使用 `ConstructVideoFrameFromTexture` 处理 GPU 纹理帧，导致错误。
4. **同步问题:**  在涉及 GPU 资源时，需要注意同步问题。如果 GPU 操作未完成就尝试访问其结果，可能会导致数据不一致或崩溃。
    *   **错误示例:**  在调用 `CopyRGBATextureToVideoFrame` 后，没有等待 GPU 操作完成就尝试使用目标 `media::VideoFrame`。

总而言之，`webrtc_video_frame_adapter.cc` 在 Chromium 中扮演着至关重要的角色，它确保了来自不同来源的视频帧能够被 WebRTC 组件正确地处理和编码，从而实现流畅的实时通信功能。理解其功能有助于开发者更好地理解 Blink 引擎中视频处理的流程和机制。

Prompt: 
```
这是目录为blink/renderer/platform/webrtc/webrtc_video_frame_adapter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"

#include <cmath>
#include <vector>

#include "base/containers/contains.h"
#include "base/dcheck_is_on.h"
#include "base/memory/raw_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread_restrictions.h"
#include "cc/trees/raster_context_provider_wrapper.h"
#include "gpu/command_buffer/client/client_shared_image.h"
#include "gpu/command_buffer/client/gpu_memory_buffer_manager.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/common/shared_image_capabilities.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "media/base/simple_sync_token_client.h"
#include "media/base/video_frame.h"
#include "media/base/video_types.h"
#include "media/base/video_util.h"
#include "media/renderers/video_frame_rgba_to_yuva_converter.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_video_frame_pool.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

bool IsApproxEquals(int a, int b) {
  return std::abs(a - b) <= 4;
}

bool IsApproxEquals(const gfx::Rect& a, const gfx::Rect& b) {
  return IsApproxEquals(a.x(), b.x()) && IsApproxEquals(a.y(), b.y()) &&
         IsApproxEquals(a.width(), b.width()) &&
         IsApproxEquals(a.height(), b.height());
}

static void CreateContextProviderOnMainThread(
    scoped_refptr<viz::RasterContextProvider>* result,
    base::WaitableEvent* waitable_event) {
  scoped_refptr<cc::RasterContextProviderWrapper> worker_context_provider =
      blink::Platform::Current()->SharedCompositorWorkerContextProvider(
          nullptr);
  if (worker_context_provider)
    *result = worker_context_provider->GetContext();
  waitable_event->Signal();
}

class Context : public media::RenderableGpuMemoryBufferVideoFramePool::Context {
 public:
  Context(media::GpuVideoAcceleratorFactories* gpu_factories,
          scoped_refptr<viz::RasterContextProvider> raster_context_provider)
      : gpu_factories_(gpu_factories),
        raster_context_provider_(std::move(raster_context_provider)) {}

  scoped_refptr<gpu::ClientSharedImage> CreateSharedImage(
      gfx::GpuMemoryBuffer* gpu_memory_buffer,
      const viz::SharedImageFormat& si_format,
      const gfx::ColorSpace& color_space,
      GrSurfaceOrigin surface_origin,
      SkAlphaType alpha_type,
      gpu::SharedImageUsageSet usage,
      gpu::SyncToken& sync_token) override {
    auto* sii = SharedImageInterface();
    if (!sii) {
      return nullptr;
    }
    auto client_shared_image = sii->CreateSharedImage(
        {si_format, gpu_memory_buffer->GetSize(), color_space, surface_origin,
         alpha_type, usage, "WebRTCVideoFramePool"},
        gpu_memory_buffer->CloneHandle());
    CHECK(client_shared_image);
    sync_token = sii->GenVerifiedSyncToken();
    return client_shared_image;
  }

  scoped_refptr<gpu::ClientSharedImage> CreateSharedImage(
      const gfx::Size& size,
      gfx::BufferUsage buffer_usage,
      const viz::SharedImageFormat& si_format,
      const gfx::ColorSpace& color_space,
      GrSurfaceOrigin surface_origin,
      SkAlphaType alpha_type,
      gpu::SharedImageUsageSet usage,
      gpu::SyncToken& sync_token) override {
    auto* sii = SharedImageInterface();
    if (!sii) {
      return nullptr;
    }
    auto client_shared_image =
        sii->CreateSharedImage({si_format, size, color_space, surface_origin,
                                alpha_type, usage, "WebRTCVideoFramePool"},
                               gpu::kNullSurfaceHandle, buffer_usage);
    if (!client_shared_image) {
      return nullptr;
    }
#if BUILDFLAG(IS_MAC)
    client_shared_image->SetColorSpaceOnNativeBuffer(color_space);
#endif
    sync_token = sii->GenVerifiedSyncToken();
    return client_shared_image;
  }

  void DestroySharedImage(
      const gpu::SyncToken& sync_token,
      scoped_refptr<gpu::ClientSharedImage> shared_image) override {
    CHECK(shared_image);
    shared_image->UpdateDestructionSyncToken(sync_token);
  }

 private:
  gpu::SharedImageInterface* SharedImageInterface() const {
    return raster_context_provider_->SharedImageInterface();
  }

  gpu::GpuMemoryBufferManager* GpuMemoryBufferManager() const {
    auto* manager = gpu_factories_->GpuMemoryBufferManager();
    DCHECK(manager);
    return manager;
  }

  raw_ptr<media::GpuVideoAcceleratorFactories> gpu_factories_;
  scoped_refptr<viz::RasterContextProvider> raster_context_provider_;
};

}  // namespace

scoped_refptr<media::VideoFrame>
WebRtcVideoFrameAdapter::SharedResources::CreateFrame(
    media::VideoPixelFormat format,
    const gfx::Size& coded_size,
    const gfx::Rect& visible_rect,
    const gfx::Size& natural_size,
    base::TimeDelta timestamp) {
  return pool_.CreateFrame(format, coded_size, visible_rect, natural_size,
                           timestamp);
}

media::EncoderStatus WebRtcVideoFrameAdapter::SharedResources::ConvertAndScale(
    const media::VideoFrame& src_frame,
    media::VideoFrame& dest_frame) {
  // The converter is thread safe so multiple threads may convert frames at
  // once.
  return frame_converter_.ConvertAndScale(src_frame, dest_frame);
}

scoped_refptr<viz::RasterContextProvider>
WebRtcVideoFrameAdapter::SharedResources::GetRasterContextProvider() {
  base::AutoLock auto_lock(context_provider_lock_);
  if (raster_context_provider_) {
    // Reuse created context provider if it's alive.
    viz::RasterContextProvider::ScopedRasterContextLock lock(
        raster_context_provider_.get());
    if (lock.RasterInterface()->GetGraphicsResetStatusKHR() == GL_NO_ERROR)
      return raster_context_provider_;
  }

  // Since the accelerated frame pool is attached to the old provider, we need
  // to release it here.
  accelerated_frame_pool_.reset();

  // Recreate the context provider.
  base::WaitableEvent waitable_event;
  PostCrossThreadTask(
      *Thread::MainThread()->GetTaskRunner(MainThreadTaskRunnerRestricted()),
      FROM_HERE,
      CrossThreadBindOnce(&CreateContextProviderOnMainThread,
                          CrossThreadUnretained(&raster_context_provider_),
                          CrossThreadUnretained(&waitable_event)));

  // This wait is necessary because this task is completed via main thread
  // asynchronously but WebRTC API is synchronous.
  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  waitable_event.Wait();

  return raster_context_provider_;
}

bool CanUseGpuMemoryBufferReadback(
    media::VideoPixelFormat format,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  // Since ConvertToWebRtcVideoFrameBuffer will always produce an opaque frame
  // (unless the input is already I420A), we allow using GMB readback from
  // ABGR/ARGB to NV12.
  if (format != media::PIXEL_FORMAT_XBGR &&
      format != media::PIXEL_FORMAT_XRGB &&
      format != media::PIXEL_FORMAT_ABGR &&
      format != media::PIXEL_FORMAT_ARGB) {
    return false;
  }
  if (!gpu_factories) {
    return false;
  }
  if (!gpu_factories->SharedImageInterface()) {
    return false;
  }
#if BUILDFLAG(IS_WIN)
  // CopyToGpuMemoryBuffer is only supported for D3D shared images on Windows.
  if (!gpu_factories->SharedImageInterface()
           ->GetCapabilities()
           .shared_image_d3d) {
    DVLOG(1) << "CopyToGpuMemoryBuffer not supported.";
    return false;
  }
#endif  // BUILDFLAG(IS_WIN)
  return WebGraphicsContext3DVideoFramePool::
      IsGpuMemoryBufferReadbackFromTextureEnabled();
}

scoped_refptr<media::VideoFrame>
WebRtcVideoFrameAdapter::SharedResources::ConstructVideoFrameFromTexture(
    scoped_refptr<media::VideoFrame> source_frame) {
  RTC_DCHECK(source_frame->HasSharedImage());

  auto raster_context_provider = GetRasterContextProvider();
  if (!raster_context_provider) {
    return nullptr;
  }

  viz::RasterContextProvider::ScopedRasterContextLock scoped_context(
      raster_context_provider.get());

  if (!disable_gmb_frames_ &&
      CanUseGpuMemoryBufferReadback(source_frame->format(), gpu_factories_)) {
    if (!accelerated_frame_pool_) {
      accelerated_frame_pool_ =
          media::RenderableGpuMemoryBufferVideoFramePool::Create(
              std::make_unique<Context>(gpu_factories_,
                                        raster_context_provider));
    }

    scoped_refptr<media::VideoFrame> dst_frame;
    {
      // Blocking is necessary to create the GpuMemoryBuffer from this thread.
      base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
      dst_frame = accelerated_frame_pool_->MaybeCreateVideoFrame(
          source_frame->coded_size(), gfx::ColorSpace::CreateREC709());
    }

    if (dst_frame) {
      CHECK(dst_frame->HasSharedImage());
      const bool copy_succeeded = media::CopyRGBATextureToVideoFrame(
          raster_context_provider.get(), source_frame->coded_size(),
          source_frame->shared_image(), source_frame->acquire_sync_token(),
          dst_frame.get());
      if (copy_succeeded) {
        // CopyRGBATextureToVideoFrame() operates on mailboxes and not frames,
        // so we must manually copy over properties relevant to the encoder.
        // TODO(https://crbug.com/1272852): Consider bailing out of this path if
        // visible_rect or natural_size is much smaller than coded_size, or
        // copying only the necessary part.
        if (dst_frame->visible_rect() != source_frame->visible_rect() ||
            dst_frame->natural_size() != source_frame->natural_size()) {
          const auto dst_format = dst_frame->format();
          dst_frame = media::VideoFrame::WrapVideoFrame(
              std::move(dst_frame), dst_format, source_frame->visible_rect(),
              source_frame->natural_size());
          DCHECK(dst_frame);
        }
        dst_frame->set_timestamp(source_frame->timestamp());
        dst_frame->set_metadata(source_frame->metadata());

        auto* ri = raster_context_provider->RasterInterface();
        DCHECK(ri);

#if BUILDFLAG(IS_WIN)
        // For shared memory GMBs on Windows we needed to explicitly request a
        // copy from the shared image GPU texture to the GMB.
        CHECK(dst_frame->HasMappableGpuBuffer());
        CHECK(!dst_frame->HasNativeGpuMemoryBuffer());
        gpu::SyncToken blit_done_sync_token;
        ri->GenUnverifiedSyncTokenCHROMIUM(blit_done_sync_token.GetData());

        auto* sii = raster_context_provider->SharedImageInterface();

        const auto& mailbox = dst_frame->shared_image()->mailbox();
        sii->CopyToGpuMemoryBuffer(blit_done_sync_token, mailbox);

        // Synchronize RasterInterface with SharedImageInterface.
        auto copy_to_gmb_done_sync_token = sii->GenUnverifiedSyncToken();
        ri->WaitSyncTokenCHROMIUM(copy_to_gmb_done_sync_token.GetData());
#endif  // BUILDFLAG(IS_WIN)

        // RI::Finish() makes sure that CopyRGBATextureToVideoFrame() finished
        // texture copy before we call ConstructVideoFrameFromGpu(). It's not
        // the best way to wait for completion, but it's the only sync way
        // to wait, and making this function async is currently impractical.
        ri->Finish();

        // We can just clear the sync token from the video frame now that we've
        // synchronized with the GPU.
        gpu::SyncToken empty_sync_token;
        media::SimpleSyncTokenClient simple_client(empty_sync_token);
        dst_frame->UpdateAcquireSyncToken(&simple_client);
        dst_frame->UpdateReleaseSyncToken(&simple_client);

        auto vf = ConstructVideoFrameFromGpu(std::move(dst_frame));
        return vf;
      }
    }

    DLOG(WARNING) << "Disabling GpuMemoryBuffer based readback due to failure.";
    disable_gmb_frames_ = true;
    accelerated_frame_pool_.reset();
  }

  auto* ri = scoped_context.RasterInterface();
  if (!ri) {
    return nullptr;
  }

  return media::ReadbackTextureBackedFrameToMemorySync(
      *source_frame, ri, raster_context_provider->ContextCapabilities(),
      &pool_for_mapped_frames_);
}

scoped_refptr<media::VideoFrame>
WebRtcVideoFrameAdapter::SharedResources::ConstructVideoFrameFromGpu(
    scoped_refptr<media::VideoFrame> source_frame) {
  CHECK(source_frame);
  // NV12 is the only supported format.
  DCHECK_EQ(source_frame->format(), media::PIXEL_FORMAT_NV12);
  DCHECK_EQ(source_frame->storage_type(),
            media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER);

  // This is necessary because mapping may require waiting on IO thread,
  // but webrtc API is synchronous.
  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;

  return media::ConvertToMemoryMappedFrame(std::move(source_frame));
}

void WebRtcVideoFrameAdapter::SharedResources::SetFeedback(
    const media::VideoCaptureFeedback& feedback) {
  base::AutoLock auto_lock(feedback_lock_);
  last_feedback_ = feedback;
}

media::VideoCaptureFeedback
WebRtcVideoFrameAdapter::SharedResources::GetFeedback() {
  base::AutoLock auto_lock(feedback_lock_);
  return last_feedback_;
}

WebRtcVideoFrameAdapter::SharedResources::SharedResources(
    media::GpuVideoAcceleratorFactories* gpu_factories)
    : gpu_factories_(gpu_factories) {}

WebRtcVideoFrameAdapter::SharedResources::~SharedResources() = default;

WebRtcVideoFrameAdapter::ScaledBufferSize::ScaledBufferSize(
    gfx::Rect visible_rect,
    gfx::Size natural_size)
    : visible_rect(std::move(visible_rect)),
      natural_size(std::move(natural_size)) {}

bool WebRtcVideoFrameAdapter::ScaledBufferSize::operator==(
    const ScaledBufferSize& rhs) const {
  return visible_rect == rhs.visible_rect && natural_size == rhs.natural_size;
}

bool WebRtcVideoFrameAdapter::ScaledBufferSize::operator!=(
    const ScaledBufferSize& rhs) const {
  return !(*this == rhs);
}

WebRtcVideoFrameAdapter::ScaledBufferSize
WebRtcVideoFrameAdapter::ScaledBufferSize::CropAndScale(
    int offset_x,
    int offset_y,
    int crop_width,
    int crop_height,
    int scaled_width,
    int scaled_height) const {
  DCHECK_LT(offset_x, natural_size.width());
  DCHECK_LT(offset_y, natural_size.height());
  DCHECK_LE(offset_x + crop_width, natural_size.width());
  DCHECK_LE(offset_y + crop_height, natural_size.height());
  DCHECK_LE(scaled_width, crop_width);
  DCHECK_LE(scaled_height, crop_height);
  // Used to convert requested visible rect to the natural size, i.e. undo
  // scaling.
  double horizontal_scale =
      static_cast<double>(visible_rect.width()) / natural_size.width();
  double vertical_scale =
      static_cast<double>(visible_rect.height()) / natural_size.height();
  return ScaledBufferSize(
      gfx::Rect(visible_rect.x() + offset_x * horizontal_scale,
                visible_rect.y() + offset_y * vertical_scale,
                crop_width * horizontal_scale, crop_height * vertical_scale),
      gfx::Size(scaled_width, scaled_height));
}

WebRtcVideoFrameAdapter::ScaledBuffer::ScaledBuffer(
    scoped_refptr<WebRtcVideoFrameAdapter> parent,
    ScaledBufferSize size)
    : parent_(std::move(parent)), size_(std::move(size)) {}

rtc::scoped_refptr<webrtc::I420BufferInterface>
WebRtcVideoFrameAdapter::ScaledBuffer::ToI420() {
  return parent_->GetOrCreateFrameBufferForSize(size_)->ToI420();
}

rtc::scoped_refptr<webrtc::VideoFrameBuffer>
WebRtcVideoFrameAdapter::ScaledBuffer::GetMappedFrameBuffer(
    rtc::ArrayView<webrtc::VideoFrameBuffer::Type> types) {
  auto frame_buffer = parent_->GetOrCreateFrameBufferForSize(size_);
  return base::Contains(types, frame_buffer->type()) ? frame_buffer : nullptr;
}

rtc::scoped_refptr<webrtc::VideoFrameBuffer>
WebRtcVideoFrameAdapter::ScaledBuffer::CropAndScale(int offset_x,
                                                    int offset_y,
                                                    int crop_width,
                                                    int crop_height,
                                                    int scaled_width,
                                                    int scaled_height) {
  return rtc::scoped_refptr<webrtc::VideoFrameBuffer>(
      new rtc::RefCountedObject<ScaledBuffer>(
          parent_,
          size_.CropAndScale(offset_x, offset_y, crop_width, crop_height,
                             scaled_width, scaled_height)));
}

std::string WebRtcVideoFrameAdapter::ScaledBuffer::storage_representation()
    const {
  return "ScaledBuffer(" + parent_->storage_representation() + ")";
}

WebRtcVideoFrameAdapter::WebRtcVideoFrameAdapter(
    scoped_refptr<media::VideoFrame> frame)
    : WebRtcVideoFrameAdapter(std::move(frame), nullptr) {}

WebRtcVideoFrameAdapter::WebRtcVideoFrameAdapter(
    scoped_refptr<media::VideoFrame> frame,
    scoped_refptr<SharedResources> shared_resources)
    : frame_(std::move(frame)),
      shared_resources_(std::move(shared_resources)),
      full_size_(frame_->visible_rect(), frame_->natural_size()) {}

WebRtcVideoFrameAdapter::~WebRtcVideoFrameAdapter() {
  // Mapping is always required when WebRTC uses software encoding.  If hardware
  // encoding is used, we may not always need to do mapping; however, if scaling
  // is needed we may do mapping and downscaling here anyway.  Therefore, notify
  // the capturer that premapped frames are required.
  if (shared_resources_) {
    shared_resources_->SetFeedback(
        media::VideoCaptureFeedback().RequireMapped(!adapted_frames_.empty()));
  }
}

rtc::scoped_refptr<webrtc::I420BufferInterface>
WebRtcVideoFrameAdapter::ToI420() {
  return GetOrCreateFrameBufferForSize(full_size_)->ToI420();
}

rtc::scoped_refptr<webrtc::VideoFrameBuffer>
WebRtcVideoFrameAdapter::GetMappedFrameBuffer(
    rtc::ArrayView<webrtc::VideoFrameBuffer::Type> types) {
  auto frame_buffer = GetOrCreateFrameBufferForSize(full_size_);
  return base::Contains(types, frame_buffer->type()) ? frame_buffer : nullptr;
}

// Soft-applies cropping and scaling. The result is a ScaledBuffer.
rtc::scoped_refptr<webrtc::VideoFrameBuffer>
WebRtcVideoFrameAdapter::CropAndScale(int offset_x,
                                      int offset_y,
                                      int crop_width,
                                      int crop_height,
                                      int scaled_width,
                                      int scaled_height) {
  return rtc::scoped_refptr<webrtc::VideoFrameBuffer>(
      new rtc::RefCountedObject<ScaledBuffer>(
          this,
          full_size_.CropAndScale(offset_x, offset_y, crop_width, crop_height,
                                  scaled_width, scaled_height)));
}

rtc::scoped_refptr<webrtc::VideoFrameBuffer>
WebRtcVideoFrameAdapter::GetOrCreateFrameBufferForSize(
    const ScaledBufferSize& size) {
  base::AutoLock auto_lock(adapted_frames_lock_);
  // Does this buffer already exist?
  for (const auto& adapted_frame : adapted_frames_) {
    if (adapted_frame.size == size)
      return adapted_frame.frame_buffer;
  }
  // Adapt the frame for this size.
  adapted_frames_.push_back(AdaptBestFrame(size));
  return adapted_frames_.back().frame_buffer;
}

WebRtcVideoFrameAdapter::AdaptedFrame WebRtcVideoFrameAdapter::AdaptBestFrame(
    const ScaledBufferSize& size) const {
  double requested_scale_factor =
      static_cast<double>(size.natural_size.width()) /
      size.visible_rect.width();
  if (requested_scale_factor != 1.0) {
    // Scaling is needed. Consider if there is a previously adapted frame we can
    // scale from. This would be a smaller scaling operation than scaling from
    // the full resolution `frame_`.
    rtc::scoped_refptr<webrtc::VideoFrameBuffer> best_webrtc_frame;
    double best_frame_scale_factor = 1.0;
    for (const auto& adapted_frame : adapted_frames_) {
      // For simplicity, ignore frames where the cropping is not identical to a
      // previous mapping.
      if (size.visible_rect != adapted_frame.size.visible_rect) {
        continue;
      }
      double scale_factor =
          static_cast<double>(adapted_frame.size.natural_size.width()) /
          adapted_frame.size.visible_rect.width();
      if (scale_factor >= requested_scale_factor &&
          scale_factor < best_frame_scale_factor) {
        best_webrtc_frame = adapted_frame.frame_buffer;
        best_frame_scale_factor = scale_factor;
      }
    }
    if (best_webrtc_frame) {
      rtc::scoped_refptr<webrtc::VideoFrameBuffer> adapted_webrtc_frame =
          best_webrtc_frame->Scale(size.natural_size.width(),
                                   size.natural_size.height());
      return AdaptedFrame(size, nullptr, adapted_webrtc_frame);
    }
  }
  // Because |size| is expressed relative to the full size'd frame, we need to
  // adjust the visible rect for the scale of the best frame.
  gfx::Rect visible_rect(size.visible_rect.x(), size.visible_rect.y(),
                         size.visible_rect.width(), size.visible_rect.height());
  if (IsApproxEquals(visible_rect, frame_->visible_rect())) {
    // Due to rounding errors it is possible for |visible_rect| to be slightly
    // off, which could either cause unnecessary cropping/scaling or cause
    // crashes if |visible_rect| is not contained within
    // |frame_->visible_rect()|, so we adjust it.
    visible_rect = frame_->visible_rect();
  }
  CHECK(frame_->visible_rect().Contains(visible_rect))
      << visible_rect.ToString() << " is not contained within "
      << frame_->visible_rect().ToString();
  // Wrapping is only needed if we need to crop or scale the best frame.
  scoped_refptr<media::VideoFrame> media_frame = frame_;
  if (frame_->visible_rect() != visible_rect ||
      frame_->natural_size() != size.natural_size) {
    media_frame = media::VideoFrame::WrapVideoFrame(
        frame_, frame_->format(), visible_rect, size.natural_size);
  }
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> adapted_webrtc_frame =
      ConvertToWebRtcVideoFrameBuffer(media_frame, shared_resources_);
  return AdaptedFrame(size, media_frame, adapted_webrtc_frame);
}

scoped_refptr<media::VideoFrame>
WebRtcVideoFrameAdapter::GetAdaptedVideoBufferForTesting(
    const ScaledBufferSize& size) {
  base::AutoLock auto_lock(adapted_frames_lock_);
  for (const auto& adapted_frame : adapted_frames_) {
    if (adapted_frame.size == size)
      return adapted_frame.video_frame;
  }
  return nullptr;
}

std::string WebRtcVideoFrameAdapter::storage_representation() const {
  std::string result = media::VideoPixelFormatToString(frame_->format());
  result.append(" ");
  result.append(media::VideoFrame::StorageTypeToString(frame_->storage_type()));
  return result;
}

}  // namespace blink

"""

```