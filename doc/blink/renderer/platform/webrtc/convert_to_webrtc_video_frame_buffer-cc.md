Response:
The user wants to understand the functionality of the `convert_to_webrtc_video_frame_buffer.cc` file in the Chromium Blink engine. I need to explain its purpose, relate it to web technologies (JavaScript, HTML, CSS), provide examples with hypothetical inputs and outputs for logical deductions, and highlight common usage errors.

**Plan:**

1. **Core Functionality:** Explain that this file handles the conversion of `media::VideoFrame` objects (Chromium's internal representation of video frames) to `webrtc::VideoFrameBuffer` objects (the format used by the WebRTC library).
2. **Web Technology Relationship:** Describe how this conversion is crucial for enabling real-time communication features in web browsers. Specifically:
    *   **JavaScript:**  Explain how JavaScript interacts with WebRTC APIs (like `getUserMedia` and `RTCPeerConnection`) to capture and send video. This file is a backend component that facilitates the processing of the captured video.
    *   **HTML:** Mention how video elements (`<video>`) are used to display local or remote video streams, and how this conversion is essential for transmitting the data.
    *   **CSS:** Briefly touch upon how CSS can style video elements, but emphasize that this file deals with the underlying data format, not the visual presentation.
3. **Logical Deduction Examples:**
    *   **Input:** A `media::VideoFrame` in `NV12` format.
    *   **Output:** A `webrtc::VideoFrameBuffer` in `NV12` format (or potentially `I420` if conversion is needed).
    *   **Input:** A `media::VideoFrame` from a GPU texture.
    *   **Output:** A `webrtc::VideoFrameBuffer` after potential readback and format conversion.
4. **Common Usage Errors:**
    *   Passing an unsupported `media::VideoFrame` format.
    *   Not providing necessary `SharedResources` for GPU/texture backed frames.
    *   Issues related to frame scaling and cropping.
## blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.cc 的功能

该文件的主要功能是将 Chromium 的 Blink 渲染引擎中表示视频帧的 `media::VideoFrame` 对象转换为 WebRTC 库使用的 `webrtc::VideoFrameBuffer` 对象。这个转换过程是 WebRTC 功能在浏览器中实现的关键步骤。

具体来说，该文件包含了以下功能：

1. **判断是否可以转换:**  `CanConvertToWebRtcVideoFrameBuffer` 函数用于检查给定的 `media::VideoFrame` 是否可以被转换为 `webrtc::VideoFrameBuffer`。它会检查视频帧的像素格式（例如 I420, I420A, NV12, ARGB 等）以及存储类型（例如可映射内存、GPU 内存缓冲、共享图像）。

2. **获取可转换的像素格式:** `GetPixelFormatsMappableToWebRtcVideoFrameBuffer` 函数返回一个列表，列出了可以被直接映射为 `webrtc::VideoFrameBuffer` 的 `media::VideoFrame` 的像素格式。

3. **执行转换:** `ConvertToWebRtcVideoFrameBuffer` 函数是核心转换函数。它接收一个 `media::VideoFrame` 和一个 `WebRtcVideoFrameAdapter::SharedResources` 对象作为输入，并返回一个 `rtc::scoped_refptr<webrtc::VideoFrameBuffer>`。
    *   对于可以直接映射内存的帧（例如 I420, I420A, NV12），它会创建一个适配器（例如 `I420FrameAdapter`, `I420AFrameAdapter`, `NV12FrameAdapter`），这些适配器实现了 `webrtc::VideoFrameBuffer` 的接口，但底层数据仍然指向原始的 `media::VideoFrame`。
    *   对于 GPU 内存缓冲或纹理支持的帧，它会使用 `SharedResources` 来读取帧数据并可能进行格式转换和缩放。
    *   如果需要缩放或格式转换，它会使用 `MakeScaledVideoFrame` 函数创建一个新的 `media::VideoFrame`，并将数据转换或缩放到目标尺寸和格式。
    *   如果转换失败，它会创建一个黑帧作为占位符。

4. **从 WebRTC 转换回 Chromium 格式:** `ConvertFromMappedWebRtcVideoFrameBuffer` 函数执行反向操作，将 `webrtc::VideoFrameBuffer` 转换回 `media::VideoFrame`。这个函数主要用于接收来自 WebRTC 层的视频帧。

## 与 JavaScript, HTML, CSS 的关系

该文件主要负责视频数据的底层处理，直接与 JavaScript 的 WebRTC API 交互，而与 HTML 和 CSS 的关系较为间接。

**JavaScript:**

*   **关系:** 当 JavaScript 代码使用 WebRTC API (例如 `getUserMedia` 获取本地摄像头视频流，或通过 `RTCPeerConnection` 接收远程视频流) 时，捕获到的或接收到的原始视频数据需要被转换成 WebRTC 库可以理解的格式才能进行编码、传输和解码。 `convert_to_webrtc_video_frame_buffer.cc` 文件中的 `ConvertToWebRtcVideoFrameBuffer` 函数就在这个过程中发挥着关键作用。它将 Chromium 内部的视频帧格式转换为 WebRTC 使用的格式。
*   **举例:**
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(function(stream) {
        const videoTrack = stream
### 提示词
```
这是目录为blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.h"

#include "base/containers/contains.h"
#include "base/containers/span.h"
#include "base/logging.h"
#include "media/base/video_frame_converter.h"
#include "media/base/video_util.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/libyuv/include/libyuv/convert.h"
#include "third_party/libyuv/include/libyuv/convert_from_argb.h"
#include "third_party/libyuv/include/libyuv/scale.h"
#include "third_party/webrtc/api/video/i420_buffer.h"
#include "third_party/webrtc/common_video/include/video_frame_buffer.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"
#include "ui/gfx/gpu_memory_buffer.h"

namespace WTF {

// Template specializations of [1], needed to be able to pass WTF callbacks
// that have VideoTrackAdapterSettings or gfx::Size parameters across threads.
//
// [1] third_party/blink/renderer/platform/wtf/cross_thread_copier.h.
template <>
struct CrossThreadCopier<scoped_refptr<webrtc::VideoFrameBuffer>>
    : public CrossThreadCopierPassThrough<
          scoped_refptr<webrtc::VideoFrameBuffer>> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace {

class I420FrameAdapter : public webrtc::I420BufferInterface {
 public:
  explicit I420FrameAdapter(scoped_refptr<media::VideoFrame> frame)
      : frame_(std::move(frame)) {
    DCHECK_EQ(frame_->format(), media::PIXEL_FORMAT_I420);
    DCHECK_EQ(frame_->visible_rect().size(), frame_->natural_size());
  }

  int width() const override { return frame_->visible_rect().width(); }
  int height() const override { return frame_->visible_rect().height(); }

  const uint8_t* DataY() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kY);
  }

  const uint8_t* DataU() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kU);
  }

  const uint8_t* DataV() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kV);
  }

  int StrideY() const override {
    return frame_->stride(media::VideoFrame::Plane::kY);
  }

  int StrideU() const override {
    return frame_->stride(media::VideoFrame::Plane::kU);
  }

  int StrideV() const override {
    return frame_->stride(media::VideoFrame::Plane::kV);
  }

 protected:
  scoped_refptr<media::VideoFrame> frame_;
};

class I420AFrameAdapter : public webrtc::I420ABufferInterface {
 public:
  explicit I420AFrameAdapter(scoped_refptr<media::VideoFrame> frame)
      : frame_(std::move(frame)) {
    DCHECK_EQ(frame_->format(), media::PIXEL_FORMAT_I420A);
    DCHECK_EQ(frame_->visible_rect().size(), frame_->natural_size());
  }

  int width() const override { return frame_->visible_rect().width(); }
  int height() const override { return frame_->visible_rect().height(); }

  const uint8_t* DataY() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kY);
  }

  const uint8_t* DataU() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kU);
  }

  const uint8_t* DataV() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kV);
  }

  const uint8_t* DataA() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kA);
  }

  int StrideY() const override {
    return frame_->stride(media::VideoFrame::Plane::kY);
  }

  int StrideU() const override {
    return frame_->stride(media::VideoFrame::Plane::kU);
  }

  int StrideV() const override {
    return frame_->stride(media::VideoFrame::Plane::kV);
  }

  int StrideA() const override {
    return frame_->stride(media::VideoFrame::Plane::kA);
  }

 protected:
  scoped_refptr<media::VideoFrame> frame_;
};

class NV12FrameAdapter : public webrtc::NV12BufferInterface {
 public:
  explicit NV12FrameAdapter(scoped_refptr<media::VideoFrame> frame)
      : frame_(std::move(frame)) {
    DCHECK_EQ(frame_->format(), media::PIXEL_FORMAT_NV12);
    DCHECK_EQ(frame_->visible_rect().size(), frame_->natural_size());
  }

  int width() const override { return frame_->visible_rect().width(); }
  int height() const override { return frame_->visible_rect().height(); }

  const uint8_t* DataY() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kY);
  }

  const uint8_t* DataUV() const override {
    return frame_->visible_data(media::VideoFrame::Plane::kUV);
  }

  int StrideY() const override {
    return frame_->stride(media::VideoFrame::Plane::kY);
  }

  int StrideUV() const override {
    return frame_->stride(media::VideoFrame::Plane::kUV);
  }

  rtc::scoped_refptr<webrtc::I420BufferInterface> ToI420() override {
    rtc::scoped_refptr<webrtc::I420Buffer> i420_buffer;
    i420_buffer = webrtc::I420Buffer::Create(width(), height());
    libyuv::NV12ToI420(DataY(), StrideY(), DataUV(), StrideUV(),
                       i420_buffer->MutableDataY(), i420_buffer->StrideY(),
                       i420_buffer->MutableDataU(), i420_buffer->StrideU(),
                       i420_buffer->MutableDataV(), i420_buffer->StrideV(),
                       width(), height());
    return i420_buffer;
  }

 protected:
  scoped_refptr<media::VideoFrame> frame_;
};

rtc::scoped_refptr<webrtc::VideoFrameBuffer> MakeFrameAdapter(
    scoped_refptr<media::VideoFrame> video_frame) {
  switch (video_frame->format()) {
    case media::PIXEL_FORMAT_I420:
      return rtc::scoped_refptr<webrtc::VideoFrameBuffer>(
          new rtc::RefCountedObject<I420FrameAdapter>(std::move(video_frame)));
    case media::PIXEL_FORMAT_I420A:
      return rtc::scoped_refptr<webrtc::VideoFrameBuffer>(
          new rtc::RefCountedObject<I420AFrameAdapter>(std::move(video_frame)));
    case media::PIXEL_FORMAT_NV12:
      return rtc::scoped_refptr<webrtc::VideoFrameBuffer>(
          new rtc::RefCountedObject<NV12FrameAdapter>(std::move(video_frame)));
    default:
      NOTREACHED();
  }
}

scoped_refptr<media::VideoFrame> MakeScaledVideoFrame(
    scoped_refptr<media::VideoFrame> source_frame,
    scoped_refptr<blink::WebRtcVideoFrameAdapter::SharedResources>
        shared_resources,
    bool source_is_nv12) {
  media::VideoPixelFormat dst_format = media::PIXEL_FORMAT_UNKNOWN;
  if (source_is_nv12) {
    DCHECK_EQ(source_frame->format(), media::PIXEL_FORMAT_NV12);
    dst_format = media::PIXEL_FORMAT_NV12;
  } else {
    // ARGB pixel format may be produced by readback of texture backed frames.
    if (source_frame->format() != media::PIXEL_FORMAT_I420 &&
        source_frame->format() != media::PIXEL_FORMAT_I420A) {
      DCHECK(source_frame->format() == media::PIXEL_FORMAT_ARGB ||
             source_frame->format() == media::PIXEL_FORMAT_XRGB ||
             source_frame->format() == media::PIXEL_FORMAT_ABGR ||
             source_frame->format() == media::PIXEL_FORMAT_XBGR);
    }

    dst_format = source_frame->format() == media::PIXEL_FORMAT_I420A
                     ? media::PIXEL_FORMAT_I420A
                     : media::PIXEL_FORMAT_I420;
  }

  // Convert to dst format and scale to the natural size specified in
  // |source_frame|.
  auto dst_frame = shared_resources->CreateFrame(
      dst_format, source_frame->natural_size(),
      gfx::Rect(source_frame->natural_size()), source_frame->natural_size(),
      source_frame->timestamp());
  if (!dst_frame) {
    LOG(ERROR) << "Failed to create dst frame from pool.";
    return nullptr;
  }
  dst_frame->metadata().MergeMetadataFrom(source_frame->metadata());

  auto status = shared_resources->ConvertAndScale(*source_frame, *dst_frame);
  return status.is_ok() ? dst_frame : nullptr;
}

scoped_refptr<media::VideoFrame> MaybeConvertAndScaleFrame(
    scoped_refptr<media::VideoFrame> source_frame,
    scoped_refptr<blink::WebRtcVideoFrameAdapter::SharedResources>
        shared_resources) {
  if (!source_frame)
    return nullptr;
  // Texture frames may be readback in ARGB format.
  RTC_DCHECK(source_frame->format() == media::PIXEL_FORMAT_I420 ||
             source_frame->format() == media::PIXEL_FORMAT_I420A ||
             source_frame->format() == media::PIXEL_FORMAT_NV12 ||
             source_frame->format() == media::PIXEL_FORMAT_ARGB ||
             source_frame->format() == media::PIXEL_FORMAT_XRGB ||
             source_frame->format() == media::PIXEL_FORMAT_ABGR ||
             source_frame->format() == media::PIXEL_FORMAT_XBGR);
  RTC_DCHECK(shared_resources);

  const bool source_is_i420 =
      source_frame->format() == media::PIXEL_FORMAT_I420 ||
      source_frame->format() == media::PIXEL_FORMAT_I420A;
  const bool source_is_nv12 =
      source_frame->format() == media::PIXEL_FORMAT_NV12;
  const bool no_scaling_needed =
      source_frame->natural_size() == source_frame->visible_rect().size();

  if ((source_is_nv12 || source_is_i420) && no_scaling_needed) {
    // |source_frame| already has correct pixel format and resolution.
    return source_frame;
  }
  return MakeScaledVideoFrame(std::move(source_frame),
                              std::move(shared_resources), source_is_nv12);
}

}  // anonymous namespace

namespace blink {

// static
bool CanConvertToWebRtcVideoFrameBuffer(const media::VideoFrame* frame) {
  // Currently accept I420, I420A, NV12 formats in a mapped frame,
  // or a texture or GPU memory buffer frame.
  return (frame->IsMappable() &&
          base::Contains(GetPixelFormatsMappableToWebRtcVideoFrameBuffer(),
                         frame->format())) ||
         frame->storage_type() ==
             media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER ||
         frame->HasSharedImage();
}

// static
base::span<const media::VideoPixelFormat>
GetPixelFormatsMappableToWebRtcVideoFrameBuffer() {
  static constexpr const media::VideoPixelFormat
      kGetPixelFormatsMappableToWebRtcVideoFrameBuffer[] = {
          media::PIXEL_FORMAT_I420, media::PIXEL_FORMAT_I420A,
          media::PIXEL_FORMAT_NV12, media::PIXEL_FORMAT_ARGB,
          media::PIXEL_FORMAT_XRGB, media::PIXEL_FORMAT_ABGR,
          media::PIXEL_FORMAT_XBGR};
  return base::make_span(kGetPixelFormatsMappableToWebRtcVideoFrameBuffer);
}

rtc::scoped_refptr<webrtc::VideoFrameBuffer> ConvertToWebRtcVideoFrameBuffer(
    scoped_refptr<media::VideoFrame> video_frame,
    scoped_refptr<WebRtcVideoFrameAdapter::SharedResources> shared_resources) {
  DCHECK(CanConvertToWebRtcVideoFrameBuffer(video_frame.get()))
      << "Can not create WebRTC frame buffer for frame "
      << video_frame->AsHumanReadableString();

  auto create_placeholder_frame = [](const media::VideoFrame& frame) {
    LOG(ERROR)
        << "Mapping frame failed. Generating black frame instead. Frame: "
        << frame.AsHumanReadableString();
    return MakeFrameAdapter(media::VideoFrame::CreateColorFrame(
        frame.natural_size(), 0u, 0x80, 0x80, frame.timestamp()));
  };

  if (video_frame->storage_type() ==
      media::VideoFrame::StorageType::STORAGE_GPU_MEMORY_BUFFER) {
    auto converted_frame =
        shared_resources
            ? shared_resources->ConstructVideoFrameFromGpu(video_frame)
            : nullptr;
    converted_frame =
        MaybeConvertAndScaleFrame(converted_frame, shared_resources);
    if (!converted_frame) {
      return create_placeholder_frame(*video_frame);
    }
    return MakeFrameAdapter(std::move(converted_frame));
  } else if (video_frame->HasSharedImage()) {
    auto converted_frame =
        shared_resources
            ? shared_resources->ConstructVideoFrameFromTexture(video_frame)
            : nullptr;
    converted_frame =
        MaybeConvertAndScaleFrame(converted_frame, shared_resources);
    if (!converted_frame) {
      DLOG(ERROR) << "Texture backed frame cannot be accessed.";
      return create_placeholder_frame(*video_frame);
    }
    return MakeFrameAdapter(std::move(converted_frame));
  }

  // Since scaling is required, hard-apply both the cropping and scaling
  // before we hand the frame over to WebRTC.
  auto scaled_frame = MaybeConvertAndScaleFrame(video_frame, shared_resources);
  if (!scaled_frame) {
    return create_placeholder_frame(*video_frame);
  }
  return MakeFrameAdapter(std::move(scaled_frame));
}

scoped_refptr<media::VideoFrame> ConvertFromMappedWebRtcVideoFrameBuffer(
    rtc::scoped_refptr<webrtc::VideoFrameBuffer> buffer,
    base::TimeDelta timestamp) {
  RTC_DCHECK(buffer->type() != webrtc::VideoFrameBuffer::Type::kNative);
  const gfx::Size size(buffer->width(), buffer->height());
  scoped_refptr<media::VideoFrame> video_frame;
  switch (buffer->type()) {
    case webrtc::VideoFrameBuffer::Type::kI420A: {
      const webrtc::I420ABufferInterface* yuva_buffer = buffer->GetI420A();
      video_frame = media::VideoFrame::WrapExternalYuvaData(
          media::PIXEL_FORMAT_I420A, size, gfx::Rect(size), size,
          yuva_buffer->StrideY(), yuva_buffer->StrideU(),
          yuva_buffer->StrideV(), yuva_buffer->StrideA(),
          const_cast<uint8_t*>(yuva_buffer->DataY()),
          const_cast<uint8_t*>(yuva_buffer->DataU()),
          const_cast<uint8_t*>(yuva_buffer->DataV()),
          const_cast<uint8_t*>(yuva_buffer->DataA()), timestamp);
      break;
    }
    case webrtc::VideoFrameBuffer::Type::kI420: {
      const webrtc::I420BufferInterface* yuv_buffer = buffer->GetI420();
      video_frame = media::VideoFrame::WrapExternalYuvData(
          media::PIXEL_FORMAT_I420, size, gfx::Rect(size), size,
          yuv_buffer->StrideY(), yuv_buffer->StrideU(), yuv_buffer->StrideV(),
          const_cast<uint8_t*>(yuv_buffer->DataY()),
          const_cast<uint8_t*>(yuv_buffer->DataU()),
          const_cast<uint8_t*>(yuv_buffer->DataV()), timestamp);
      break;
    }
    case webrtc::VideoFrameBuffer::Type::kI444: {
      const webrtc::I444BufferInterface* yuv_buffer = buffer->GetI444();
      video_frame = media::VideoFrame::WrapExternalYuvData(
          media::PIXEL_FORMAT_I444, size, gfx::Rect(size), size,
          yuv_buffer->StrideY(), yuv_buffer->StrideU(), yuv_buffer->StrideV(),
          const_cast<uint8_t*>(yuv_buffer->DataY()),
          const_cast<uint8_t*>(yuv_buffer->DataU()),
          const_cast<uint8_t*>(yuv_buffer->DataV()), timestamp);
      break;
    }
    case webrtc::VideoFrameBuffer::Type::kI422: {
      const webrtc::I422BufferInterface* yuv_buffer = buffer->GetI422();
      video_frame = media::VideoFrame::WrapExternalYuvData(
          media::PIXEL_FORMAT_I422, size, gfx::Rect(size), size,
          yuv_buffer->StrideY(), yuv_buffer->StrideU(), yuv_buffer->StrideV(),
          const_cast<uint8_t*>(yuv_buffer->DataY()),
          const_cast<uint8_t*>(yuv_buffer->DataU()),
          const_cast<uint8_t*>(yuv_buffer->DataV()), timestamp);
      break;
    }
    case webrtc::VideoFrameBuffer::Type::kI010: {
      const webrtc::I010BufferInterface* yuv_buffer = buffer->GetI010();
      // WebRTC defines I010 data as uint16 whereas Chromium uses uint8 for all
      // video formats, so conversion and cast is needed.
      video_frame = media::VideoFrame::WrapExternalYuvData(
          media::PIXEL_FORMAT_YUV420P10, size, gfx::Rect(size), size,
          yuv_buffer->StrideY() * 2, yuv_buffer->StrideU() * 2,
          yuv_buffer->StrideV() * 2,
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataY())),
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataU())),
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataV())),
          timestamp);
      break;
    }
    case webrtc::VideoFrameBuffer::Type::kI210: {
      const webrtc::I210BufferInterface* yuv_buffer = buffer->GetI210();
      // WebRTC defines I210 data as uint16 whereas Chromium uses uint8 for all
      // video formats, so conversion and cast is needed.
      video_frame = media::VideoFrame::WrapExternalYuvData(
          media::PIXEL_FORMAT_YUV422P10, size, gfx::Rect(size), size,
          yuv_buffer->StrideY() * 2, yuv_buffer->StrideU() * 2,
          yuv_buffer->StrideV() * 2,
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataY())),
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataU())),
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataV())),
          timestamp);
      break;
    }
    case webrtc::VideoFrameBuffer::Type::kI410: {
      const webrtc::I410BufferInterface* yuv_buffer = buffer->GetI410();
      // WebRTC defines I410 data as uint16 whereas Chromium uses uint8 for all
      // video formats, so conversion and cast is needed.
      video_frame = media::VideoFrame::WrapExternalYuvData(
          media::PIXEL_FORMAT_YUV444P10, size, gfx::Rect(size), size,
          yuv_buffer->StrideY() * 2, yuv_buffer->StrideU() * 2,
          yuv_buffer->StrideV() * 2,
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataY())),
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataU())),
          const_cast<uint8_t*>(
              reinterpret_cast<const uint8_t*>(yuv_buffer->DataV())),
          timestamp);
      break;
    }
    case webrtc::VideoFrameBuffer::Type::kNV12: {
      const webrtc::NV12BufferInterface* nv12_buffer = buffer->GetNV12();
      video_frame = media::VideoFrame::WrapExternalYuvData(
          media::PIXEL_FORMAT_NV12, size, gfx::Rect(size), size,
          nv12_buffer->StrideY(), nv12_buffer->StrideUV(),
          const_cast<uint8_t*>(nv12_buffer->DataY()),
          const_cast<uint8_t*>(nv12_buffer->DataUV()), timestamp);
      break;
    }
    default:
      NOTREACHED();
  }
  if (!video_frame) {
    return nullptr;
  }
  // The bind ensures that we keep a reference to the underlying buffer.
  video_frame->AddDestructionObserver(
      ConvertToBaseOnceCallback(CrossThreadBindOnce(
          [](const scoped_refptr<webrtc::RefCountInterface>&) {},
          scoped_refptr<webrtc::VideoFrameBuffer>(buffer.get()))));
  return video_frame;
}

}  // namespace blink
```