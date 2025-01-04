Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `background_readback.cc` file in Chromium's Blink rendering engine. It also asks about its relation to web technologies (JS, HTML, CSS), logic, potential errors, and how a user might trigger this code.

2. **Initial Skim for Keywords and Structure:** Quickly scan the code for obvious patterns and keywords. Look for:
    * Includes: These tell you about dependencies and what the code might be interacting with (`media`, `gpu`, `webcodecs`, `webaudio`, `bindings`).
    * Class names: `BackgroundReadback`, `SyncReadbackThread`. These are central.
    * Method names: `ReadbackToFrame`, `ReadbackToBuffer`, `ReadbackRGBTextureBackedFrameToMemory`, etc. These are actions the code performs.
    * Namespaces: `blink`, `WTF`. Indicate organizational units.
    * `#ifdef` directives: Conditional compilation, like `UNSAFE_BUFFERS_BUILD`.
    * Comments: Often provide high-level explanations (e.g., the copyright notice, the description of `SyncReadbackThread`).
    * `DCHECK` statements: Assertions, useful for understanding assumptions.
    * Tracing macros: `TRACE_EVENT_*`. Indicate performance monitoring points.

3. **Identify Core Functionality - The "Readback" Concept:** The file name and the prominent method names (`Readback...`) immediately suggest the core purpose: reading back data from the GPU, specifically video frame data. The "background" part implies this happens asynchronously or on a separate thread to avoid blocking the main rendering thread.

4. **Dissect the `BackgroundReadback` Class:** This appears to be the main interface.
    * **`From(ExecutionContext& context)`:**  This is a common pattern in Blink for accessing singleton-like services associated with a document/frame. It suggests this class manages readback operations within a specific browsing context.
    * **`ReadbackTextureBackedFrameToMemoryFrame` and `ReadbackTextureBackedFrameToBuffer`:** These are the primary public methods for initiating readback. The "texture-backed" part points to the source of the data being on the GPU. The "memory frame" and "buffer" indicate the destination of the read data.
    * **`worker_task_runner_`:** This strongly indicates asynchronous operation on a dedicated thread.
    * **RGB Optimization:** The `CanUseRgbReadback` check and the separate `ReadbackRGBTextureBackedFrameToMemory` and `ReadbackRGBTextureBackedFrameToBuffer` methods suggest a performance optimization for RGB video frames, likely using a more direct GPU readback path.

5. **Analyze the `SyncReadbackThread` Class:** This class handles the actual GPU interaction.
    * **`LazyInitialize()`:** Sets up the GPU context, which is a potentially expensive operation, so it's done on demand.
    * **`ReadbackToFrame` and `ReadbackToBuffer`:** These are the worker thread counterparts to the methods in `BackgroundReadback`, performing the synchronous GPU readback.
    * **`WebGraphicsContext3DProvider`:** This is the key interface for interacting with the GPU.

6. **Trace the Data Flow (Conceptual):** A high-level flow emerges:
    1. A request to read back a video frame (likely triggered by JavaScript).
    2. The request goes to `BackgroundReadback` on the main thread.
    3. The task is offloaded to the `worker_task_runner_` and the `SyncReadbackThread`.
    4. `SyncReadbackThread` initializes the GPU context if needed.
    5. It uses the GPU's raster interface (`gpu::raster::RasterInterface`) to read back the texture data.
    6. The data is copied into a new `media::VideoFrame` or a provided buffer.
    7. The result is passed back to the main thread via a callback.

7. **Connect to Web Technologies:**
    * **JavaScript:** The WebCodecs API (`VideoFrame`, `AudioData`) is directly mentioned in the includes. This is the most likely entry point. Methods like `VideoFrame.copyTo()` would internally use this readback mechanism.
    * **HTML:**  The `<video>` element is the primary way video is displayed in HTML. Operations on a `<video>` element's frames (e.g., capturing a snapshot) could trigger this. The `<canvas>` element is also relevant, as `drawImage()` can render video frames, and reading data back from the canvas might involve similar GPU interactions.
    * **CSS:**  CSS styling of video elements or canvases doesn't directly trigger *this* code, but it influences how the video is rendered, which could indirectly affect the need for readback in certain scenarios.

8. **Identify Potential Issues and Errors:**
    * **GPU Context Failure:**  The `LazyInitialize()` checks for context creation and binding failures.
    * **Buffer Size Mismatch:** The code checks if the provided buffer is large enough.
    * **Thread Safety:** The use of `DCHECK_CALLED_ON_VALID_THREAD` and separate threads highlights the importance of thread safety.
    * **Sync Token Management:** The use of `WaitSyncTokenCHROMIUM` and `UpdateReleaseSyncToken` is critical for ensuring correct synchronization between the CPU and GPU.

9. **Construct Examples and Scenarios:** Based on the identified functionality, create concrete examples of how JavaScript code might interact with this C++ code. Think about common use cases for `VideoFrame` manipulation.

10. **Debugging Clues:** Consider how a developer might arrive at this code during debugging. Likely scenarios involve investigating issues with:
    * Reading pixel data from video frames.
    * Performance problems related to video processing.
    * GPU-related errors when working with video.

11. **Review and Refine:** Read through the generated explanation, ensuring clarity, accuracy, and completeness. Check for any logical gaps or areas that need further clarification. For example, ensure the explanation of sync tokens is understandable.

This systematic approach, moving from high-level understanding to detailed analysis and then back to concrete examples and debugging scenarios, is crucial for effectively analyzing and explaining complex code like this. The process isn't strictly linear; there's often back-and-forth as new information emerges.
这个文件 `blink/renderer/modules/webcodecs/background_readback.cc` 的主要功能是 **在后台线程中安全高效地将 GPU 上的纹理数据（通常是视频帧）读取回 CPU 内存**。这是 WebCodecs API 实现的一部分，允许 JavaScript 代码访问和操作视频和音频数据。

以下是更详细的功能分解：

**核心功能:**

1. **异步读取回 CPU 内存:**  它提供了一种机制，将存储在 GPU 纹理中的视频帧数据读取回 CPU 内存中的 `media::VideoFrame` 对象或用户提供的 `base::span<uint8_t>` 缓冲区。这个过程是在一个独立的后台线程中完成的，以避免阻塞主渲染线程，从而保证用户界面的流畅性。

2. **支持不同目标:** 可以将数据读取回 `media::VideoFrame` 对象（`ReadbackTextureBackedFrameToMemoryFrame`）或者直接读取到预分配的字节缓冲区（`ReadbackTextureBackedFrameToBuffer`）。

3. **RGB 格式优化:**  对于 RGB 格式的纹理帧（`CanUseRgbReadback`），它使用更高效的 GPU 读取路径 (`ReadbackRGBTextureBackedFrameToMemory`, `ReadbackRGBTextureBackedFrameToBuffer`)，直接从共享纹理读取数据。

4. **跨线程操作管理:** 使用 `worker_task_runner_` 将读取任务调度到后台线程 `SyncReadbackThread` 上执行，并使用回调函数将结果返回到主线程。

5. **GPU 上下文管理:** `SyncReadbackThread` 负责在后台线程上创建和管理必要的 GPU 上下文 (`WebGraphicsContext3DProvider`)，以便进行纹理读取操作。

6. **同步机制:** 使用 GPU 同步令牌 (`WaitSyncTokenCHROMIUM`, `UpdateReleaseSyncToken`) 来确保在读取 GPU 纹理之前，GPU 渲染操作已经完成，并且在读取完成后，可以安全地释放 GPU 资源。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接服务于 **JavaScript** 的 WebCodecs API。通过 WebCodecs，JavaScript 可以访问和操作原始的视频帧数据，例如用于图像处理、分析或自定义渲染。

* **JavaScript:**
    * **`VideoFrame.copyTo(buffer)`:**  当 JavaScript 调用 `VideoFrame` 对象的 `copyTo()` 方法时，如果 `VideoFrame` 的数据存储在 GPU 纹理中，Blink 引擎就会使用 `BackgroundReadback` 来将纹理数据读取到 JavaScript 提供的 `buffer` 中。
        ```javascript
        const video = document.querySelector('video');
        const reader = new VideoFrameReader(video.captureStream().getVideoTracks()[0]);
        reader.read().then(({ value, done }) => {
          if (!done) {
            const videoFrame = value;
            const buffer = new ArrayBuffer(videoFrame.allocationSize());
            videoFrame.copyTo(buffer).then(() => {
              // buffer 中包含了视频帧的像素数据
              console.log("Video frame data copied to buffer:", buffer);
              videoFrame.close();
            });
          }
        });
        ```
    * **`VideoFrame` 构造函数 (从 `HTMLCanvasElement` 或 `OffscreenCanvas`)**: 如果使用 Canvas 的内容创建 `VideoFrame`，当需要访问其像素数据时，也可能触发 `BackgroundReadback`。

* **HTML:**
    * **`<video>` 元素:**  WebCodecs 经常用于处理来自 `<video>` 元素捕获的视频流。当 JavaScript 需要访问 `<video>` 当前帧的像素数据时，就会使用 WebCodecs 和 `BackgroundReadback`。
    * **`<canvas>` 元素:**  可以通过 Canvas 绘制视频帧，然后使用 `getImageData()` 等方法读取 Canvas 上的像素数据。在某些情况下，如果 Canvas 的内容来自 GPU 纹理（例如通过 `drawImage` 绘制的 `VideoFrame`），那么读取 Canvas 数据的过程可能会间接涉及到类似的 GPU 读回机制，虽然这个文件本身不直接处理 Canvas 的读回，但概念上类似。

* **CSS:**
    * **没有直接关系:** CSS 主要负责样式和布局，不直接涉及读取视频帧的像素数据。但是，CSS 的某些属性（例如 `transform`）可能会影响视频帧的渲染方式，间接影响到 WebCodecs 需要处理的帧数据。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码创建了一个从 GPU 纹理获取数据的 `VideoFrame` 对象，并调用了 `copyTo()` 方法：

**假设输入:**

* `txt_frame`: 一个指向 GPU 纹理支持的 `media::VideoFrame` 对象的智能指针，包含视频帧的元数据（尺寸、格式、时间戳等）和 GPU 纹理句柄。
* `dest_layout`:  描述目标缓冲区布局的 `VideoFrameLayout` 对象（例如，宽度、高度、像素格式、步幅等）。
* `dest_buffer`: 一个 `base::span<uint8_t>`，指向用于存储读取到的像素数据的缓冲区。
* (对于 `ReadbackToFrame`，没有 `dest_layout` 和 `dest_buffer`，目标是创建一个新的 `media::VideoFrame`)

**逻辑输出 (成功情况下):**

* `ReadbackToFrame`: 返回一个新的 `media::VideoFrame` 对象，其内存缓冲区中包含从 GPU 纹理读取的视频帧像素数据。
* `ReadbackToBuffer`: `done_cb` 回调函数被调用，参数为 `true`，表示读取成功，并且 `dest_buffer` 中的内容已被 GPU 纹理的像素数据填充。

**用户或编程常见的使用错误:**

1. **缓冲区大小不足:** 用户提供的缓冲区 (`dest_buffer`) 的大小不足以容纳读取的像素数据。这会导致 `ReadbackToBuffer` 中 `DLOG(ERROR)` 输出，并且回调函数会返回 `false`。
    ```javascript
    const videoFrame = ...; // 从 GPU 纹理获取的 VideoFrame
    const smallBuffer = new ArrayBuffer(10); // 故意分配一个很小的缓冲区
    videoFrame.copyTo(smallBuffer).catch(() => {
      console.error("Failed to copy video frame: buffer too small");
    });
    ```
    **调试线索:** 查看控制台的错误日志，检查回调函数的返回值。

2. **在错误的线程上调用:** 尽管 `BackgroundReadback` 旨在在后台运行，但其公共接口 (`ReadbackTextureBackedFrameToMemoryFrame`, `ReadbackTextureBackedFrameToBuffer`) 应该在主渲染线程上调用。如果在错误的线程上调用，可能会导致断言失败 (`DCHECK_CALLED_ON_VALID_SEQUENCE`)。

3. **未等待 GPU 操作完成:** 虽然 `BackgroundReadback` 内部处理了同步，但在某些复杂的场景下，如果过早地释放或修改了与要读取的纹理相关的 GPU 资源，可能会导致读取错误。这通常是更底层的 GPU 编程问题，但在 WebCodecs 的上下文中，意味着要正确管理 `VideoFrame` 的生命周期和 GPU 同步令牌。

4. **使用不支持的像素格式:** 虽然代码尝试处理不同格式，但如果 GPU 纹理的格式与 `BackgroundReadback` 的实现不兼容，可能会导致读取失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载包含 `<video>` 元素的网页。**
2. **网页 JavaScript 代码使用 `video.captureStream()` 获取视频流。**
3. **JavaScript 代码创建一个 `VideoFrameReader` 对象来读取视频帧。**
4. **`reader.read()` 返回一个 Promise，当视频帧准备好时 resolve。**
5. **获取到的 `VideoFrame` 对象的数据可能存储在 GPU 纹理中 (特别是在性能敏感的场景下)。**
6. **JavaScript 代码调用 `videoFrame.copyTo(buffer)`，尝试将视频帧数据复制到 ArrayBuffer。**
7. **Blink 引擎识别到 `VideoFrame` 的数据在 GPU 上，因此调用 `BackgroundReadback::ReadbackTextureBackedFrameToBuffer` (或 `ReadbackTextureBackedFrameToMemoryFrame`)。**
8. **`BackgroundReadback` 将读取任务发布到后台线程 `SyncReadbackThread`。**
9. **`SyncReadbackThread` 初始化 GPU 上下文，并使用 GPU 的 raster interface 读取纹理数据。**
10. **读取到的数据被复制到提供的缓冲区或新的 `media::VideoFrame` 中。**
11. **结果通过回调函数返回到主线程，最终传递给 JavaScript 的 Promise。**

**调试线索:**

* **查看 Chrome 的 `chrome://gpu` 页面:** 可以了解 GPU 的状态、驱动信息以及 WebGL/WebGPU 的支持情况，这有助于判断是否存在 GPU 相关的问题。
* **使用 Chrome 开发者工具的 Performance 面板:** 可以观察主线程和 worker 线程的活动，查看是否有长时间运行的任务阻塞了主线程。
* **在 `BackgroundReadback.cc` 中添加日志或断点:**  可以追踪代码的执行流程，查看关键变量的值，例如 `txt_frame` 的信息、缓冲区的大小、GPU 同步令牌的状态等。
* **检查 WebCodecs API 的使用方式:** 确保 JavaScript 代码正确地使用了 `VideoFrame` 和相关的 API，例如正确分配缓冲区大小，并在适当的时机调用 `close()` 方法释放资源。
* **检查错误回调:**  确保 JavaScript 代码处理了 `copyTo()` 方法返回的 Promise 的 rejection 情况，以便捕获潜在的读取错误。

总而言之，`background_readback.cc` 是 WebCodecs 实现中的一个关键组件，它桥接了 JavaScript 和底层的 GPU 资源，使得在 Web 平台上进行高性能的视频处理成为可能。理解其功能和工作原理有助于调试与 WebCodecs 相关的性能和正确性问题。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/background_readback.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webcodecs/background_readback.h"

#include "base/feature_list.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/bind_post_task.h"
#include "base/task/task_traits.h"
#include "base/threading/thread_checker.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "media/base/video_frame_pool.h"
#include "media/base/video_util.h"
#include "media/base/wait_and_replace_sync_token_client.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_init.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_rect_util.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_provider_util.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_gfx.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"

namespace {
bool CanUseRgbReadback(media::VideoFrame& frame) {
  return media::IsRGB(frame.format()) && frame.HasSharedImage();
}

SkImageInfo GetImageInfoForFrame(const media::VideoFrame& frame,
                                 const gfx::Size& size) {
  SkColorType color_type =
      SkColorTypeForPlane(frame.format(), media::VideoFrame::Plane::kARGB);
  SkAlphaType alpha_type = kUnpremul_SkAlphaType;
  return SkImageInfo::Make(size.width(), size.height(), color_type, alpha_type);
}

gpu::raster::RasterInterface* GetSharedGpuRasterInterface() {
  auto wrapper = blink::SharedGpuContext::ContextProviderWrapper();
  if (wrapper && wrapper->ContextProvider()) {
    auto* raster_provider = wrapper->ContextProvider()->RasterContextProvider();
    if (raster_provider)
      return raster_provider->RasterInterface();
  }
  return nullptr;
}

}  // namespace

namespace WTF {

template <>
struct CrossThreadCopier<blink::VideoFrameLayout>
    : public CrossThreadCopierPassThrough<blink::VideoFrameLayout> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<base::span<uint8_t>>
    : public CrossThreadCopierPassThrough<base::span<uint8_t>> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

// This is a part of BackgroundReadback that lives and dies on the worker's
// thread and does all the actual work of creating GPU context and calling
// sync readback functions.
class SyncReadbackThread
    : public WTF::ThreadSafeRefCounted<SyncReadbackThread> {
 public:
  SyncReadbackThread();
  scoped_refptr<media::VideoFrame> ReadbackToFrame(
      scoped_refptr<media::VideoFrame> frame);

  bool ReadbackToBuffer(scoped_refptr<media::VideoFrame> frame,
                        const gfx::Rect src_rect,
                        const VideoFrameLayout dest_layout,
                        base::span<uint8_t> dest_buffer);

 private:
  bool LazyInitialize();
  media::VideoFramePool result_frame_pool_;
  std::unique_ptr<WebGraphicsContext3DProvider> context_provider_;
  THREAD_CHECKER(thread_checker_);
};

BackgroundReadback::BackgroundReadback(base::PassKey<BackgroundReadback> key,
                                       ExecutionContext& context)
    : Supplement<ExecutionContext>(context),
      sync_readback_impl_(base::MakeRefCounted<SyncReadbackThread>()),
      worker_task_runner_(base::ThreadPool::CreateSingleThreadTaskRunner(
          {base::WithBaseSyncPrimitives()},
          base::SingleThreadTaskRunnerThreadMode::DEDICATED)) {}

BackgroundReadback::~BackgroundReadback() {
  worker_task_runner_->ReleaseSoon(FROM_HERE, std::move(sync_readback_impl_));
}

const char BackgroundReadback::kSupplementName[] = "BackgroundReadback";
// static
BackgroundReadback* BackgroundReadback::From(ExecutionContext& context) {
  BackgroundReadback* supplement =
      Supplement<ExecutionContext>::From<BackgroundReadback>(context);
  if (!supplement) {
    supplement = MakeGarbageCollected<BackgroundReadback>(
        base::PassKey<BackgroundReadback>(), context);
    Supplement<ExecutionContext>::ProvideTo(context, supplement);
  }
  return supplement;
}

void BackgroundReadback::ReadbackTextureBackedFrameToMemoryFrame(
    scoped_refptr<media::VideoFrame> txt_frame,
    ReadbackToFrameDoneCallback result_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(txt_frame);

  if (CanUseRgbReadback(*txt_frame)) {
    ReadbackRGBTextureBackedFrameToMemory(std::move(txt_frame),
                                          std::move(result_cb));
    return;
  }
  ReadbackOnThread(std::move(txt_frame), std::move(result_cb));
}

void BackgroundReadback::ReadbackTextureBackedFrameToBuffer(
    scoped_refptr<media::VideoFrame> txt_frame,
    const gfx::Rect& src_rect,
    const VideoFrameLayout& dest_layout,
    base::span<uint8_t> dest_buffer,
    ReadbackDoneCallback done_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(txt_frame);

  if (CanUseRgbReadback(*txt_frame)) {
    ReadbackRGBTextureBackedFrameToBuffer(txt_frame, src_rect, dest_layout,
                                          dest_buffer, std::move(done_cb));
    return;
  }
  ReadbackOnThread(std::move(txt_frame), src_rect, dest_layout, dest_buffer,
                   std::move(done_cb));
}

void BackgroundReadback::ReadbackOnThread(
    scoped_refptr<media::VideoFrame> txt_frame,
    ReadbackToFrameDoneCallback result_cb) {
  worker_task_runner_->PostTaskAndReplyWithResult(
      FROM_HERE,
      ConvertToBaseOnceCallback(
          CrossThreadBindOnce(&SyncReadbackThread::ReadbackToFrame,
                              sync_readback_impl_, std::move(txt_frame))),
      std::move(result_cb));
}

void BackgroundReadback::ReadbackOnThread(
    scoped_refptr<media::VideoFrame> txt_frame,
    const gfx::Rect& src_rect,
    const VideoFrameLayout& dest_layout,
    base::span<uint8_t> dest_buffer,
    ReadbackDoneCallback done_cb) {
  worker_task_runner_->PostTaskAndReplyWithResult(
      FROM_HERE,
      ConvertToBaseOnceCallback(CrossThreadBindOnce(
          &SyncReadbackThread::ReadbackToBuffer, sync_readback_impl_,
          std::move(txt_frame), src_rect, dest_layout, dest_buffer)),
      std::move(done_cb));
}

void BackgroundReadback::ReadbackRGBTextureBackedFrameToMemory(
    scoped_refptr<media::VideoFrame> txt_frame,
    ReadbackToFrameDoneCallback result_cb) {
  DCHECK(CanUseRgbReadback(*txt_frame));

  SkImageInfo info = GetImageInfoForFrame(*txt_frame, txt_frame->coded_size());
  const auto format = media::VideoPixelFormatFromSkColorType(
      info.colorType(), media::IsOpaque(txt_frame->format()));

  auto result = result_frame_pool_.CreateFrame(
      format, txt_frame->coded_size(), txt_frame->visible_rect(),
      txt_frame->natural_size(), txt_frame->timestamp());

  auto* ri = GetSharedGpuRasterInterface();
  if (!ri || !result) {
    base::BindPostTaskToCurrentDefault(std::move(std::move(result_cb)))
        .Run(nullptr);
    return;
  }

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
      "media", "ReadbackRGBTextureBackedFrameToMemory", txt_frame.get(),
      "timestamp", txt_frame->timestamp());

  uint8_t* dst_pixels =
      result->GetWritableVisibleData(media::VideoFrame::Plane::kARGB);
  int rgba_stide = result->stride(media::VideoFrame::Plane::kARGB);
  DCHECK_GT(rgba_stide, 0);

  auto origin = txt_frame->metadata().texture_origin_is_top_left
                    ? kTopLeft_GrSurfaceOrigin
                    : kBottomLeft_GrSurfaceOrigin;

  gfx::Point src_point;
  auto shared_image = txt_frame->shared_image();
  ri->WaitSyncTokenCHROMIUM(txt_frame->acquire_sync_token().GetConstData());

  gfx::Size texture_size = txt_frame->coded_size();
  ri->ReadbackARGBPixelsAsync(
      shared_image->mailbox(), shared_image->GetTextureTarget(), origin,
      texture_size, src_point, info, base::saturated_cast<GLuint>(rgba_stide),
      dst_pixels,
      WTF::BindOnce(&BackgroundReadback::OnARGBPixelsFrameReadCompleted,
                    WrapWeakPersistent(this), std::move(result_cb),
                    std::move(txt_frame), std::move(result)));
}

void BackgroundReadback::OnARGBPixelsFrameReadCompleted(
    ReadbackToFrameDoneCallback result_cb,
    scoped_refptr<media::VideoFrame> txt_frame,
    scoped_refptr<media::VideoFrame> result_frame,
    bool success) {
  TRACE_EVENT_NESTABLE_ASYNC_END1("media",
                                  "ReadbackRGBTextureBackedFrameToMemory",
                                  txt_frame.get(), "success", success);
  if (!success) {
    ReadbackOnThread(std::move(txt_frame), std::move(result_cb));
    return;
  }
  if (auto* ri = GetSharedGpuRasterInterface()) {
    media::WaitAndReplaceSyncTokenClient client(ri);
    txt_frame->UpdateReleaseSyncToken(&client);
  } else {
    success = false;
  }

  result_frame->set_color_space(txt_frame->ColorSpace());
  result_frame->metadata().MergeMetadataFrom(txt_frame->metadata());
  result_frame->metadata().ClearTextureFrameMetadata();
  std::move(result_cb).Run(success ? std::move(result_frame) : nullptr);
}

void BackgroundReadback::ReadbackRGBTextureBackedFrameToBuffer(
    scoped_refptr<media::VideoFrame> txt_frame,
    const gfx::Rect& src_rect,
    const VideoFrameLayout& dest_layout,
    base::span<uint8_t> dest_buffer,
    ReadbackDoneCallback done_cb) {
  if (dest_layout.NumPlanes() != 1) {
    NOTREACHED()
        << "This method shouldn't be called on anything but RGB frames";
  }

  auto* ri = GetSharedGpuRasterInterface();
  if (!ri) {
    base::BindPostTaskToCurrentDefault(std::move(std::move(done_cb)))
        .Run(false);
    return;
  }

  uint32_t offset = dest_layout.Offset(0);
  uint32_t stride = dest_layout.Stride(0);

  uint8_t* dst_pixels = dest_buffer.data() + offset;
  size_t max_bytes_written = stride * src_rect.height();
  if (stride <= 0 || max_bytes_written > dest_buffer.size()) {
    DLOG(ERROR) << "Buffer is not sufficiently large for readback";
    base::BindPostTaskToCurrentDefault(std::move(std::move(done_cb)))
        .Run(false);
    return;
  }

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
      "media", "ReadbackRGBTextureBackedFrameToBuffer", txt_frame.get(),
      "timestamp", txt_frame->timestamp());

  SkImageInfo info = GetImageInfoForFrame(*txt_frame, src_rect.size());
  gfx::Point src_point = src_rect.origin();
  auto origin = txt_frame->metadata().texture_origin_is_top_left
                    ? kTopLeft_GrSurfaceOrigin
                    : kBottomLeft_GrSurfaceOrigin;

  auto shared_image = txt_frame->shared_image();
  ri->WaitSyncTokenCHROMIUM(txt_frame->acquire_sync_token().GetConstData());

  gfx::Size texture_size = txt_frame->coded_size();
  ri->ReadbackARGBPixelsAsync(
      shared_image->mailbox(), shared_image->GetTextureTarget(), origin,
      texture_size, src_point, info, base::saturated_cast<GLuint>(stride),
      dst_pixels,
      WTF::BindOnce(&BackgroundReadback::OnARGBPixelsBufferReadCompleted,
                    WrapWeakPersistent(this), std::move(txt_frame), src_rect,
                    dest_layout, dest_buffer, std::move(done_cb)));
}

void BackgroundReadback::OnARGBPixelsBufferReadCompleted(
    scoped_refptr<media::VideoFrame> txt_frame,
    const gfx::Rect& src_rect,
    const VideoFrameLayout& dest_layout,
    base::span<uint8_t> dest_buffer,
    ReadbackDoneCallback done_cb,
    bool success) {
  TRACE_EVENT_NESTABLE_ASYNC_END1("media",
                                  "ReadbackRGBTextureBackedFrameToBuffer",
                                  txt_frame.get(), "success", success);
  if (!success) {
    ReadbackOnThread(std::move(txt_frame), src_rect, dest_layout, dest_buffer,
                     std::move(done_cb));
    return;
  }

  if (auto* ri = GetSharedGpuRasterInterface()) {
    media::WaitAndReplaceSyncTokenClient client(ri);
    txt_frame->UpdateReleaseSyncToken(&client);
  } else {
    success = false;
  }

  std::move(done_cb).Run(success);
}

SyncReadbackThread::SyncReadbackThread() {
  DETACH_FROM_THREAD(thread_checker_);
}

bool SyncReadbackThread::LazyInitialize() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (context_provider_)
    return true;
  Platform::ContextAttributes attributes;
  attributes.enable_raster_interface = true;
  attributes.support_grcontext = true;
  attributes.prefer_low_power_gpu = true;

  Platform::GraphicsInfo info;
  context_provider_ = CreateOffscreenGraphicsContext3DProvider(
      attributes, &info, KURL("chrome://BackgroundReadback"));

  if (!context_provider_) {
    DLOG(ERROR) << "Can't create context provider.";
    return false;
  }

  if (!context_provider_->BindToCurrentSequence()) {
    DLOG(ERROR) << "Can't bind context provider.";
    context_provider_ = nullptr;
    return false;
  }
  return true;
}

scoped_refptr<media::VideoFrame> SyncReadbackThread::ReadbackToFrame(
    scoped_refptr<media::VideoFrame> frame) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!LazyInitialize())
    return nullptr;

  auto* ri = context_provider_->RasterInterface();
  return media::ReadbackTextureBackedFrameToMemorySync(
      *frame, ri, context_provider_->GetCapabilities(), &result_frame_pool_);
}

bool SyncReadbackThread::ReadbackToBuffer(
    scoped_refptr<media::VideoFrame> frame,
    const gfx::Rect src_rect,
    const VideoFrameLayout dest_layout,
    base::span<uint8_t> dest_buffer) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  TRACE_EVENT1("media", "SyncReadbackThread::ReadbackToBuffer", "timestamp",
               frame->timestamp());

  if (!LazyInitialize() || !frame)
    return false;

  auto* ri = context_provider_->RasterInterface();
  if (!ri)
    return false;

  for (wtf_size_t i = 0; i < dest_layout.NumPlanes(); i++) {
    const gfx::Size sample_size =
        media::VideoFrame::SampleSize(dest_layout.Format(), i);
    gfx::Rect plane_src_rect = PlaneRect(src_rect, sample_size);
    uint8_t* dest_pixels = dest_buffer.data() + dest_layout.Offset(i);
    if (!media::ReadbackTexturePlaneToMemorySync(
            *frame, i, plane_src_rect, dest_pixels, dest_layout.Stride(i), ri,
            context_provider_->GetCapabilities())) {
      // It's possible to fail after copying some but not all planes, leaving
      // the output buffer in a corrupt state D:
      return false;
    }
  }

  return true;
}

}  // namespace blink

"""

```