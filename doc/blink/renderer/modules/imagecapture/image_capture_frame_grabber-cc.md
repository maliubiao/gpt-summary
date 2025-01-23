Response:
Let's break down the thought process to analyze the provided C++ code for `ImageCaptureFrameGrabber`.

1. **Understand the Goal:** The request is to analyze a specific Chromium source file and explain its functionality, its relationship with web technologies, provide examples of logic, common errors, and how a user might trigger it.

2. **Initial Skim for High-Level Functionality:**  The filename `image_capture_frame_grabber.cc` and the namespace `blink::imagecapture` strongly suggest this code is related to capturing still images from a video stream within the web browser. Keywords like "frame grabber," "video frame," "SkImage" reinforce this.

3. **Identify Key Classes and Methods:**  Focus on the main class, `ImageCaptureFrameGrabber`, and its public methods, particularly `GrabFrame`. Also note the internal helper class `SingleShotFrameHandler`. These are the core components.

4. **Analyze `GrabFrame` Method:** This seems to be the main entry point. Observe its parameters:
    * `MediaStreamComponent* component`:  Indicates it works with video tracks from the WebRTC API.
    * `std::unique_ptr<ImageCaptureGrabFrameCallbacks> callbacks`:  Suggests asynchronous operation, with success and error callbacks.
    * `scoped_refptr<base::SingleThreadTaskRunner> task_runner`:  Highlights thread safety and the need to execute callbacks on the correct thread (likely the main thread).
    * `base::TimeDelta timeout`:  Points to a mechanism to prevent indefinite waiting.

5. **Analyze `SingleShotFrameHandler`:** This class is designed to handle a single video frame. Notice:
    * `OnVideoFrameOnIOThread`:  Executed on the IO thread when a video frame arrives.
    * `ConvertAndDeliverFrame`:  Handles the conversion of the video frame to a SkImage (Skia's image representation). This involves considerations for different video formats and rotations.
    * The usage of `libyuv`: This library is used for video frame manipulation, specifically format conversion and rotation.

6. **Map to Web Technologies:** Connect the identified components and methods to their corresponding JavaScript APIs:
    * `ImageCapture API`:  The most direct connection. The `grabFrame()` method in JavaScript likely triggers the `GrabFrame` method in C++.
    * `MediaStream API`:  The `MediaStreamTrack` from which the video frames originate. The `component` parameter represents this.
    * `HTML <video>` element:  Often the source of the video stream, though the `ImageCapture API` can work with other media sources.
    * `CSS`: While not directly involved in the core logic of grabbing the frame, CSS could affect the *rendering* of the video, but the `ImageCapture` captures the underlying frame data.

7. **Trace the User Flow:**  Think about how a user interacts with a webpage to trigger this code:
    * The user grants camera access.
    * JavaScript uses `getUserMedia()` to get a `MediaStream`.
    * The `MediaStream` is often displayed in a `<video>` element.
    * JavaScript uses the `ImageCapture` API, associated with a video track, and calls `grabFrame()`.
    * This JavaScript call bridges to the C++ `GrabFrame` method.

8. **Identify Potential Issues and Errors:** Look for error handling and edge cases:
    * `frame_grab_in_progress_`: Prevents multiple simultaneous grab requests.
    * Timeout mechanism: Handles cases where no frame is received.
    * Video format handling: The code deals with different pixel formats (I420, NV12, etc.) and GPU-backed frames. Errors might occur if an unsupported format is encountered.
    * Threading issues: Incorrect thread usage can lead to crashes or unexpected behavior. The use of `SingleThreadTaskRunner` and `PostCrossThreadTask` indicates a focus on thread safety.

9. **Construct Examples:** Create concrete examples of how JavaScript code interacts with this C++ code. Show the basic structure of using the `ImageCapture` API.

10. **Simulate Logic with Input/Output:** For `ConvertAndDeliverFrame`, consider a simple scenario:
    * **Input:** An I420 video frame with no rotation.
    * **Output:** An `SkImage` representing the same frame data.
    * Then, consider a more complex scenario:
    * **Input:** An NV12 video frame with 90-degree rotation.
    * **Output:** An `SkImage` representing the rotated frame, with dimensions swapped.

11. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that need more explanation. Ensure the language is accessible to someone who understands web development concepts but might not be a Chromium internals expert. For example, explain what SkImage is at a high level. Double-check the thread usage explanations.

This systematic approach, starting with a broad understanding and progressively diving into the details, allows for a comprehensive analysis of the provided code snippet and its role in the larger web ecosystem.
这是一个 Chromium Blink 引擎的源代码文件，名为 `image_capture_frame_grabber.cc`，它位于 `blink/renderer/modules/imagecapture` 目录下。从文件名和路径来看，它很明显与 **Image Capture API** 相关。

**功能列举:**

1. **抓取视频帧 (Grab Video Frame):**  该文件的核心功能是接收来自 `MediaStreamTrack` (通常是摄像头或视频流) 的视频帧，并将其转换为静态图像格式，通常是 `SkImage` (Skia 图形库的图像对象)。
2. **单次抓取 (Single Shot):**  类名 `SingleShotFrameHandler` 表明它主要处理单次抓取帧的请求。当一个 `grabFrame()` 请求被调用时，这个类会负责获取并处理一个单一的视频帧。
3. **处理不同视频格式 (Handle Different Video Formats):** 代码中使用了 `libyuv` 库进行视频格式转换和旋转。这表明它可以处理多种视频像素格式，例如 `I420`, `NV12`, `I420A`，并能进行必要的转换以生成 `SkImage`。
4. **处理视频旋转 (Handle Video Rotation):**  代码检查了 `VideoFrame` 的元数据中的旋转信息，并使用 `libyuv` 进行相应的旋转处理。
5. **处理 GPU 内存缓冲 (Handle GPU Memory Buffer):** 代码能够处理存储在 GPU 内存缓冲区的视频帧 (`STORAGE_GPU_MEMORY_BUFFER`)，并进行必要的映射和转换。
6. **超时机制 (Timeout Mechanism):**  `GrabFrame` 方法中设置了一个超时任务，如果指定时间内没有成功抓取到帧，会触发 `OnTimeout` 并断开连接，防止请求无限期挂起。
7. **线程安全 (Thread Safety):**  代码使用了 `base::Lock` 和线程相关的工具，表明它考虑了多线程环境下的同步问题，例如视频帧可能在 IO 线程到达，但最终结果需要在主线程处理。
8. **异步操作 (Asynchronous Operation):**  通过回调函数 `ImageCaptureGrabFrameCallbacks` 来传递抓取结果（成功或失败），这符合 JavaScript 中异步 API 的模式。

**与 JavaScript, HTML, CSS 的关系 (并举例说明):**

`ImageCaptureFrameGrabber.cc` 是浏览器引擎内部实现的一部分，直接与 JavaScript 的 **Image Capture API** 交互。

* **JavaScript:**
    * **`ImageCapture.grabFrame()` 方法:**  当 JavaScript 代码调用 `ImageCapture` 对象的 `grabFrame()` 方法时，最终会触发 C++ 层的 `ImageCaptureFrameGrabber::GrabFrame` 方法。
    * **`MediaStreamTrack` 对象:**  `ImageCapture` 对象需要关联一个视频 `MediaStreamTrack`。这个 track 提供了视频帧数据，`ImageCaptureFrameGrabber` 从这个 track 中获取帧。
    * **Promise:** `grabFrame()` 方法返回一个 Promise，当帧抓取成功时，Promise 会 resolve 并返回一个 `ImageBitmap` 对象，如果失败则 reject。C++ 层的回调函数 `OnSuccess` 和 `OnError` 分别对应 Promise 的 resolve 和 reject 行为。

    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(function(stream) {
        const videoTrack = stream.getVideoTracks()[0];
### 提示词
```
这是目录为blink/renderer/modules/imagecapture/image_capture_frame_grabber.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/imagecapture/image_capture_frame_grabber.h"

#include "base/synchronization/lock.h"
#include "base/task/bind_post_task.h"
#include "base/task/single_thread_task_runner.h"
#include "base/thread_annotations.h"
#include "base/time/time.h"
#include "cc/paint/skia_paint_canvas.h"
#include "media/base/video_frame.h"
#include "media/base/video_types.h"
#include "media/base/video_util.h"
#include "skia/ext/legacy_display_globals.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cancellable_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/libyuv/include/libyuv.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "ui/gfx/gpu_memory_buffer.h"

namespace WTF {
// Template specialization of [1], needed to be able to pass callbacks
// that have ScopedWebCallbacks paramaters across threads.
//
// [1] third_party/blink/renderer/platform/wtf/cross_thread_copier.h.
template <typename T>
struct CrossThreadCopier<blink::ScopedWebCallbacks<T>>
    : public CrossThreadCopierPassThrough<blink::ScopedWebCallbacks<T>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = blink::ScopedWebCallbacks<T>;
  static blink::ScopedWebCallbacks<T> Copy(
      blink::ScopedWebCallbacks<T> pointer) {
    return pointer;
  }
};

}  // namespace WTF

namespace blink {

namespace {

void OnError(std::unique_ptr<ImageCaptureGrabFrameCallbacks> callbacks) {
  callbacks->OnError();
}

}  // anonymous namespace

// Ref-counted class to receive a single VideoFrame on IO thread, convert it and
// send it to |task_runner|, where this class is created and destroyed.
class ImageCaptureFrameGrabber::SingleShotFrameHandler
    : public WTF::ThreadSafeRefCounted<SingleShotFrameHandler> {
 public:
  using SkImageDeliverCB = WTF::CrossThreadOnceFunction<void(sk_sp<SkImage>)>;

  explicit SingleShotFrameHandler(
      SkImageDeliverCB deliver_cb,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : deliver_cb_(std::move(deliver_cb)),
        task_runner_(std::move(task_runner)) {
    DCHECK(deliver_cb_);
  }

  SingleShotFrameHandler(const SingleShotFrameHandler&) = delete;
  SingleShotFrameHandler& operator=(const SingleShotFrameHandler&) = delete;

  ~SingleShotFrameHandler();

  // Receives a |frame| and converts its pixels into a SkImage via an internal
  // PaintSurface and SkPixmap. Alpha channel, if any, is copied.
  void OnVideoFrameOnIOThread(
      scoped_refptr<media::VideoFrame> frame,
      base::TimeTicks current_time);

 private:
  friend class WTF::ThreadSafeRefCounted<SingleShotFrameHandler>;

  // Converts the media::VideoFrame into a SkImage on the |task_runner|.
  void ConvertAndDeliverFrame(SkImageDeliverCB callback,
                              scoped_refptr<media::VideoFrame> frame);

  base::Lock lock_;
  // Null once the initial frame has been queued for delivery.
  SkImageDeliverCB deliver_cb_ GUARDED_BY(lock_);
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

ImageCaptureFrameGrabber::SingleShotFrameHandler::~SingleShotFrameHandler() {
  base::AutoLock locker(lock_);
  if (deliver_cb_) {
    // Reject the promise if no frame was received.
    // Post to `task_runner_` to ensure the promise is always rejected on the
    // main thread.
    PostCrossThreadTask(*task_runner_, FROM_HERE,
                        CrossThreadBindOnce(std::move(deliver_cb_), nullptr));
  }
}

void ImageCaptureFrameGrabber::SingleShotFrameHandler::OnVideoFrameOnIOThread(
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks /*current_time*/) {
  base::AutoLock locker(lock_);
  if (!deliver_cb_)
    return;

  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&SingleShotFrameHandler::ConvertAndDeliverFrame,
                          base::WrapRefCounted(this), std::move(deliver_cb_),
                          std::move(frame)));
}

void ImageCaptureFrameGrabber::SingleShotFrameHandler::ConvertAndDeliverFrame(
    SkImageDeliverCB callback,
    scoped_refptr<media::VideoFrame> frame) {
  media::VideoRotation rotation = media::VIDEO_ROTATION_0;
  if (frame->metadata().transformation) {
    rotation = frame->metadata().transformation->rotation;
  }

  const gfx::Size& original_size = frame->visible_rect().size();
  gfx::Size display_size = original_size;
  if (rotation == media::VIDEO_ROTATION_90 ||
      rotation == media::VIDEO_ROTATION_270) {
    display_size.SetSize(display_size.height(), display_size.width());
  }
  const SkAlphaType alpha = media::IsOpaque(frame->format())
                                ? kOpaque_SkAlphaType
                                : kPremul_SkAlphaType;
  const SkImageInfo info =
      SkImageInfo::MakeN32(display_size.width(), display_size.height(), alpha);

  SkSurfaceProps props = skia::LegacyDisplayGlobals::GetSkSurfaceProps();
  sk_sp<SkSurface> surface = SkSurfaces::Raster(info, &props);
  DCHECK(surface);

  // If a frame is GPU backed, we need to use PaintCanvasVideoRenderer to read
  // it back from the GPU.
  const bool is_readable = frame->format() == media::PIXEL_FORMAT_I420 ||
                           frame->format() == media::PIXEL_FORMAT_I420A ||
                           (frame->format() == media::PIXEL_FORMAT_NV12 &&
                            frame->HasMappableGpuBuffer());
  if (!is_readable) {
    cc::SkiaPaintCanvas canvas(surface->getCanvas());
    cc::PaintFlags paint_flags;
    DrawVideoFrameIntoCanvas(std::move(frame), &canvas, paint_flags,
                             /*ignore_video_transformation=*/false);
    std::move(callback).Run(surface->makeImageSnapshot());
    return;
  }

  SkPixmap pixmap;
  if (!skia::GetWritablePixels(surface->getCanvas(), &pixmap)) {
    DLOG(ERROR) << "Error trying to map SkSurface's pixels";
    std::move(callback).Run(sk_sp<SkImage>());
    return;
  }

#if SK_PMCOLOR_BYTE_ORDER(R, G, B, A)
  const uint32_t destination_pixel_format = libyuv::FOURCC_ABGR;
#else
  const uint32_t destination_pixel_format = libyuv::FOURCC_ARGB;
#endif
  uint8_t* destination_plane = static_cast<uint8_t*>(pixmap.writable_addr());
  int destination_stride = pixmap.width() * 4;
  int destination_width = pixmap.width();
  int destination_height = pixmap.height();

  // The frame rotating code path based on libyuv will convert any format to
  // I420, rotate under I420 and transform I420 to destination format.
  bool need_rotate = rotation != media::VIDEO_ROTATION_0;
  scoped_refptr<media::VideoFrame> i420_frame;

  if (frame->storage_type() == media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER) {
    DCHECK_EQ(frame->format(), media::PIXEL_FORMAT_NV12);
    auto scoped_mapping = frame->MapGMBOrSharedImage();
    if (!scoped_mapping) {
      DLOG(ERROR) << "Failed to get the mapped memory.";
      std::move(callback).Run(sk_sp<SkImage>());
      return;
    }

    // NV12 is the only supported pixel format at the moment.
    DCHECK_EQ(frame->format(), media::PIXEL_FORMAT_NV12);
    int y_stride = static_cast<int>(scoped_mapping->Stride(0));
    int uv_stride = static_cast<int>(scoped_mapping->Stride(1));
    const uint8_t* y_plane =
        (static_cast<uint8_t*>(scoped_mapping->Memory(0)) +
         frame->visible_rect().x() + (frame->visible_rect().y() * y_stride));
    // UV plane of NV12 has 2-byte pixel width, with half chroma subsampling
    // both horizontally and vertically.
    const uint8_t* uv_plane = scoped_mapping->Memory(1) +
                              ((frame->visible_rect().x() * 2) / 2) +
                              ((frame->visible_rect().y() / 2) * uv_stride);

    if (need_rotate) {
      // Transform to I420 first to be later on rotated.
      i420_frame = media::VideoFrame::CreateFrame(
          media::PIXEL_FORMAT_I420, original_size, gfx::Rect(original_size),
          original_size, base::TimeDelta());

      libyuv::NV12ToI420(
          y_plane, y_stride, uv_plane, uv_stride,
          i420_frame->GetWritableVisibleData(media::VideoFrame::Plane::kY),
          i420_frame->stride(media::VideoFrame::Plane::kY),
          i420_frame->GetWritableVisibleData(media::VideoFrame::Plane::kU),
          i420_frame->stride(media::VideoFrame::Plane::kU),
          i420_frame->GetWritableVisibleData(media::VideoFrame::Plane::kV),
          i420_frame->stride(media::VideoFrame::Plane::kV),
          original_size.width(), original_size.height());
    } else {
      switch (destination_pixel_format) {
        case libyuv::FOURCC_ABGR:
          libyuv::NV12ToABGR(y_plane, y_stride, uv_plane, uv_stride,
                             destination_plane, destination_stride,
                             destination_width, destination_height);
          break;
        case libyuv::FOURCC_ARGB:
          libyuv::NV12ToARGB(y_plane, y_stride, uv_plane, uv_stride,
                             destination_plane, destination_stride,
                             destination_width, destination_height);
          break;
        default:
          NOTREACHED();
      }
    }
  } else {
    DCHECK(frame->format() == media::PIXEL_FORMAT_I420 ||
           frame->format() == media::PIXEL_FORMAT_I420A);
    i420_frame = std::move(frame);
  }

  if (i420_frame) {
    if (need_rotate) {
      scoped_refptr<media::VideoFrame> rotated_frame =
          media::VideoFrame::CreateFrame(media::PIXEL_FORMAT_I420, display_size,
                                         gfx::Rect(display_size), display_size,
                                         base::TimeDelta());

      libyuv::RotationMode libyuv_rotate = [rotation]() {
        switch (rotation) {
          case media::VIDEO_ROTATION_0:
            return libyuv::kRotate0;
          case media::VIDEO_ROTATION_90:
            return libyuv::kRotate90;
          case media::VIDEO_ROTATION_180:
            return libyuv::kRotate180;
          case media::VIDEO_ROTATION_270:
            return libyuv::kRotate270;
        }
      }();

      libyuv::I420Rotate(
          i420_frame->visible_data(media::VideoFrame::Plane::kY),
          i420_frame->stride(media::VideoFrame::Plane::kY),
          i420_frame->visible_data(media::VideoFrame::Plane::kU),
          i420_frame->stride(media::VideoFrame::Plane::kU),
          i420_frame->visible_data(media::VideoFrame::Plane::kV),
          i420_frame->stride(media::VideoFrame::Plane::kV),
          rotated_frame->GetWritableVisibleData(media::VideoFrame::Plane::kY),
          rotated_frame->stride(media::VideoFrame::Plane::kY),
          rotated_frame->GetWritableVisibleData(media::VideoFrame::Plane::kU),
          rotated_frame->stride(media::VideoFrame::Plane::kU),
          rotated_frame->GetWritableVisibleData(media::VideoFrame::Plane::kV),
          rotated_frame->stride(media::VideoFrame::Plane::kV),
          original_size.width(), original_size.height(), libyuv_rotate);
      i420_frame = std::move(rotated_frame);
    }

    libyuv::ConvertFromI420(
        i420_frame->visible_data(media::VideoFrame::Plane::kY),
        i420_frame->stride(media::VideoFrame::Plane::kY),
        i420_frame->visible_data(media::VideoFrame::Plane::kU),
        i420_frame->stride(media::VideoFrame::Plane::kU),
        i420_frame->visible_data(media::VideoFrame::Plane::kV),
        i420_frame->stride(media::VideoFrame::Plane::kV), destination_plane,
        destination_stride, destination_width, destination_height,
        destination_pixel_format);

    if (i420_frame->format() == media::PIXEL_FORMAT_I420A) {
      DCHECK(!info.isOpaque());
      // This function copies any plane into the alpha channel of an ARGB image.
      libyuv::ARGBCopyYToAlpha(
          i420_frame->visible_data(media::VideoFrame::Plane::kA),
          i420_frame->stride(media::VideoFrame::Plane::kA), destination_plane,
          destination_stride, destination_width, destination_height);
    }
  }

  std::move(callback).Run(surface->makeImageSnapshot());
}

ImageCaptureFrameGrabber::~ImageCaptureFrameGrabber() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

void ImageCaptureFrameGrabber::GrabFrame(
    MediaStreamComponent* component,
    std::unique_ptr<ImageCaptureGrabFrameCallbacks> callbacks,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    base::TimeDelta timeout) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!!callbacks);

  DCHECK(component && component->GetPlatformTrack());
  DCHECK_EQ(MediaStreamSource::kTypeVideo, component->GetSourceType());

  if (frame_grab_in_progress_) {
    // Reject grabFrame()s too close back to back.
    callbacks->OnError();
    return;
  }

  auto scoped_callbacks = MakeScopedWebCallbacks(
      std::move(callbacks),
      base::BindPostTask(task_runner, WTF::BindOnce(&OnError)));

  // A SingleShotFrameHandler is bound and given to the Track to guarantee that
  // only one VideoFrame is converted and delivered to OnSkImage(), otherwise
  // SKImages might be sent to resolved |callbacks| while DisconnectFromTrack()
  // is being processed, which might be further held up if UI is busy, see
  // https://crbug.com/623042.
  frame_grab_in_progress_ = true;

  // Fail the grabFrame request if no frame is received for some time to prevent
  // the promise from hanging indefinitely if no frame is ever produced.
  timeout_task_handle_ = PostDelayedCancellableTask(
      *task_runner, FROM_HERE,
      WTF::BindOnce(&ImageCaptureFrameGrabber::OnTimeout,
                    weak_factory_.GetWeakPtr()),
      timeout);

  MediaStreamVideoSink::ConnectToTrack(
      WebMediaStreamTrack(component),
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &SingleShotFrameHandler::OnVideoFrameOnIOThread,
          base::MakeRefCounted<SingleShotFrameHandler>(
              CrossThreadBindOnce(&ImageCaptureFrameGrabber::OnSkImage,
                                  weak_factory_.GetWeakPtr(),
                                  std::move(scoped_callbacks)),
              std::move(task_runner)))),
      MediaStreamVideoSink::IsSecure::kNo,
      MediaStreamVideoSink::UsesAlpha::kDefault);
}

void ImageCaptureFrameGrabber::OnSkImage(
    ScopedWebCallbacks<ImageCaptureGrabFrameCallbacks> callbacks,
    sk_sp<SkImage> image) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  timeout_task_handle_.Cancel();
  MediaStreamVideoSink::DisconnectFromTrack();
  frame_grab_in_progress_ = false;
  if (image)
    callbacks.PassCallbacks()->OnSuccess(image);
  else
    callbacks.PassCallbacks()->OnError();
}

void ImageCaptureFrameGrabber::OnTimeout() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (frame_grab_in_progress_) {
    MediaStreamVideoSink::DisconnectFromTrack();
    frame_grab_in_progress_ = false;
  }
}

}  // namespace blink
```