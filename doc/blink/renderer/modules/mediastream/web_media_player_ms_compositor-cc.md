Response:
The user wants a summary of the functionality of the `WebMediaPlayerMSCompositor` class, based on the provided C++ source code. I need to identify the main responsibilities of this class and how it interacts with other components.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The name "Compositor" suggests a role in combining or managing video frames for display. The "MS" likely refers to MediaStream, indicating it handles video from media streams.

2. **Examine Key Members and Methods:** Look for variables and functions that reveal the class's state and actions. Pay attention to those dealing with video frames, rendering, synchronization, and interaction with other components.

3. **Trace Data Flow:** Observe how video frames are received, processed, and presented. Look for methods like `EnqueueFrame`, `UpdateCurrentFrame`, `GetCurrentFrame`, and `PutCurrentFrame`.

4. **Identify External Interactions:** Note any interactions with other classes or systems, such as `WebVideoFrameSubmitter`, `VideoFrameProvider`, `MediaStreamDescriptor`, and the graphics pipeline (through `cc::VideoFrameProvider::Client`).

5. **Look for Threading Considerations:** The class uses multiple task runners, suggesting a need for careful synchronization. Identify which tasks run on which threads.

6. **Infer Functionality from Names and Types:**  The names of variables and functions often hint at their purpose (e.g., `dropped_frame_count_`, `SetIsSurfaceVisible`). The types of variables (e.g., `scoped_refptr<media::VideoFrame>`) provide context.

7. **Consider Edge Cases and Error Handling:** Look for code that handles potential issues like out-of-order frames, lost contexts, or missing metadata.

8. **Connect to Web Technologies (JavaScript, HTML, CSS):** Think about how the actions performed by this C++ class relate to the user's experience in a web browser. How would a developer using JavaScript's `getUserMedia` or a `<video>` element interact with the functionality provided here?

9. **Address Specific Instructions:** Pay close attention to the request for examples relating to JavaScript, HTML, and CSS, as well as the need for hypothetical input/output and common usage errors.

10. **Structure the Summary:** Organize the findings logically, starting with the main purpose and then detailing specific functionalities.

**Pre-computation and Pre-analysis (Mental Walkthrough):**

* **Frame Handling:**  The code seems to receive video frames, potentially reorder them, and select the appropriate frame for rendering. The presence of `rendering_frame_buffer_` (especially with the "Algorithm" suffixes) suggests different strategies for frame selection.
* **Synchronization:** The interaction with `WebVideoFrameSubmitter` and `cc::VideoFrameProvider::Client` points to a synchronization role with the rendering pipeline. It needs to provide frames at the right time.
* **Metadata:** The class deals with video frame metadata (timestamps, transformations).
* **Error Handling:**  The code includes checks for null pointers, out-of-order frames, and context loss.
* **Metrics:**  The use of histograms indicates that the class collects performance data.

**Drafting the Summary (Internal Monologue):**

Okay, so this class is the heart of displaying MediaStream video. It gets frames, figures out when to show them, and sends them to the graphics system. It uses different strategies depending on whether an "algorithm" is enabled. It needs to handle things like the video being paused or the browser tab being hidden. It also needs to deal with potential problems like frames arriving late or in the wrong order. The `WebVideoFrameSubmitter` seems like the interface to the actual rendering.

**Refining the Summary:**

Need to be more precise about the different rendering paths (with and without the algorithm). Also need to explicitly mention the role of metadata and the synchronization with the rendering pipeline. The error handling and metrics collection are important details too. Don't forget to link it to the web technologies.

By following these steps, I can generate a comprehensive and accurate summary of the `WebMediaPlayerMSCompositor`'s functionality, addressing all the user's requests.
```cpp
WebMediaPlayerMSCompositor::WebMediaPlayerMSCompositor(
    scoped_refptr<base::SingleThreadTaskRunner>
        video_frame_compositor_task_runner,
    scoped_refptr<base::SequencedTaskRunner> video_task_runner,
    MediaStreamDescriptor* media_stream_descriptor,
    std::unique_ptr<WebVideoFrameSubmitter> submitter,
    bool use_surface_layer,
    const base::WeakPtr<WebMediaPlayerMS>& player)
    : video_frame_compositor_task_runner_(video_frame_compositor_task_runner),
      video_task_runner_(video_task_runner),
      main_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      player_(player),
      video_frame_provider_client_(nullptr),
      current_frame_rendered_(false),
      last_render_length_(base::Seconds(1.0 / 60.0)),
      total_frame_count_(0),
      dropped_frame_count_(0),
      stopped_(true),
      render_started_(!stopped_) {
  weak_this_ = weak_ptr_factory_.GetWeakPtr();
  if (use_surface_layer) {
    submitter_ = std::move(submitter);

    PostCrossThreadTask(
        *video_frame_compositor_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&WebMediaPlayerMSCompositor::InitializeSubmitter,
                            weak_this_));
    update_submission_state_callback_ = base::BindPostTask(
        video_frame_compositor_task_runner_,
        ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
            &WebMediaPlayerMSCompositor::SetIsSurfaceVisible, weak_this_)));
  }

  HeapVector<Member<MediaStreamComponent>> video_components;
  if (media_stream_descriptor)
    video_components = media_stream_descriptor->VideoComponents();

  const bool remote_video =
      video_components.size() && video_components[0]->Remote();

  if (remote_video && Platform::Current()->RTCSmoothnessAlgorithmEnabled()) {
    base::AutoLock auto_lock(current_frame_lock_);
    rendering_frame_buffer_ = std::make_unique<VideoRendererAlgorithmWrapper>(
        ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
            &WebMediaPlayerMSCompositor::MapTimestampsToRenderTimeTicks,
            CrossThreadUnretained(this))),
        &media_log_);
  }

  // Just for logging purpose.
  std::string stream_id = media_stream_descriptor
                              ? media_stream_descriptor->Id().Utf8()
                              : std::string();
  const uint32_t hash_value = base::Hash(stream_id);
  serial_ = (hash_value << 1) | (remote_video ? 1 : 0);
}

WebMediaPlayerMSCompositor::~WebMediaPlayerMSCompositor() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (video_frame_provider_client_) {
    video_frame_provider_client_->StopUsingProvider();
  }
}

void WebMediaPlayerMSCompositor::InitializeSubmitter() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  submitter_->Initialize(this, /*is_media_stream=*/true);
}

void WebMediaPlayerMSCompositor::SetIsSurfaceVisible(
    bool state,
    base::WaitableEvent* done_event) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  submitter_->SetIsSurfaceVisible(state);
  if (done_event)
    done_event->Signal();
}

// TODO(https://crbug/879424): Rename, since it really doesn't enable
// submission. Do this along with the VideoFrameSubmitter refactor.
void WebMediaPlayerMSCompositor::EnableSubmission(
    const viz::SurfaceId& id,
    media::VideoTransformation transformation,
    bool force_submit) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());

  // If we're switching to |submitter_| from some other client, then tell it.
  if (video_frame_provider_client_ &&
      video_frame_provider_client_ != submitter_.get()) {
    video_frame_provider_client_->StopUsingProvider();
  }

  submitter_->SetTransform(transformation);
  submitter_->SetForceSubmit(force_submit);
  submitter_->EnableSubmission(id);
  video_frame_provider_client_ = submitter_.get();

  if (!stopped_)
    video_frame_provider_client_->StartRendering();
}

void WebMediaPlayerMSCompositor::SetForceBeginFrames(bool enable) {
  if (!submitter_)
    return;

  if (!video_frame_compositor_task_runner_->BelongsToCurrentThread()) {
    PostCrossThreadTask(
        *video_frame_compositor_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&WebMediaPlayerMSCompositor::SetForceBeginFrames,
                            weak_this_, enable));
    return;
  }

  submitter_->SetForceBeginFrames(enable);
}

WebMediaPlayerMSCompositor::Metadata WebMediaPlayerMSCompositor::GetMetadata() {
  base::AutoLock auto_lock(current_frame_lock_);
  return current_metadata_;
}

void WebMediaPlayerMSCompositor::SetForceSubmit(bool force_submit) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  submitter_->SetForceSubmit(force_submit);
}

void WebMediaPlayerMSCompositor::SetIsPageVisible(bool is_visible) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (submitter_)
    submitter_->SetIsPageVisible(is_visible);
}

size_t WebMediaPlayerMSCompositor::total_frame_count() {
  base::AutoLock auto_lock(current_frame_lock_);
  DVLOG(1) << __func__ << ", " << total_frame_count_;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return total_frame_count_;
}

size_t WebMediaPlayerMSCompositor::dropped_frame_count() {
  base::AutoLock auto_lock(current_frame_lock_);
  DVLOG(1) << __func__ << ", " << dropped_frame_count_;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return dropped_frame_count_;
}

void WebMediaPlayerMSCompositor::SetVideoFrameProviderClient(
    cc::VideoFrameProvider::Client* client) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (video_frame_provider_client_)
    video_frame_provider_client_->StopUsingProvider();

  video_frame_provider_client_ = client;
  if (video_frame_provider_client_ && !stopped_)
    video_frame_provider_client_->StartRendering();
}

void WebMediaPlayerMSCompositor::RecordFrameDecodedStats(
    std::optional<base::TimeTicks> frame_received_time,
    std::optional<base::TimeDelta> frame_processing_time,
    std::optional<uint32_t> frame_rtp_timestamp) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  if (frame_received_time && last_enqueued_frame_receive_time_) {
    base::TimeDelta frame_receive_time_delta =
        *frame_received_time - *last_enqueued_frame_receive_time_;
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".FrameReceivedTimeDelta",
                          frame_receive_time_delta);
  }
  last_enqueued_frame_receive_time_ = frame_received_time;

  auto now = base::TimeTicks::Now();
  if (last_enqueued_frame_decoded_time_) {
    base::TimeDelta frame_decoded_time_delta =
        now - *last_enqueued_frame_decoded_time_;
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".FrameDecodedTimeDelta",
                          frame_decoded_time_delta);
  }
  last_enqueued_frame_decoded_time_ = now;

  if (frame_processing_time) {
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".DecodeDuration",
                          frame_processing_time.value());
  }

  if (frame_rtp_timestamp && last_enqueued_frame_rtp_timestamp_) {
    LOCAL_HISTOGRAM_COUNTS_10000(
        UmaPrefix() + ".FrameDecodedRtpTimestampDelta",
        *frame_rtp_timestamp - *last_enqueued_frame_rtp_timestamp_);
  }
  last_enqueued_frame_rtp_timestamp_ = frame_rtp_timestamp;
}

void WebMediaPlayerMSCompositor::SetMetadata() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  current_frame_lock_.AssertAcquired();
  current_metadata_.natural_size = current_frame_->natural_size();
  current_metadata_.video_transform =
      current_frame_->metadata().transformation.value_or(
          media::kNoTransformation);
}

void WebMediaPlayerMSCompositor::EnqueueFrame(
    scoped_refptr<media::VideoFrame> frame,
    bool is_copy) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock auto_lock(current_frame_lock_);
  TRACE_EVENT_INSTANT1("media", "WebMediaPlayerMSCompositor::EnqueueFrame",
                       TRACE_EVENT_SCOPE_THREAD, "Timestamp",
                       frame->timestamp().InMicroseconds());
  ++total_frame_count_;
  ++frame_enqueued_since_last_vsync_;
  std::optional<uint32_t> enqueue_frame_rtp_timestamp;
  if (frame->metadata().rtp_timestamp) {
    enqueue_frame_rtp_timestamp =
        static_cast<uint32_t>(frame->metadata().rtp_timestamp.value());
  }
  RecordFrameDecodedStats(frame->metadata().receive_time,
                          frame->metadata().processing_time,
                          enqueue_frame_rtp_timestamp);

  // With algorithm off, just let |current_frame_| hold the incoming |frame|.
  if (!rendering_frame_buffer_) {
    RenderWithoutAlgorithm(std::move(frame), is_copy);
    return;
  }

  // This is a signal frame saying that the stream is stopped.
  if (frame->metadata().end_of_stream) {
    rendering_frame_buffer_.reset();
    RenderWithoutAlgorithm(std::move(frame), is_copy);
    return;
  }

  // If we detect a bad frame without |reference_time|, we switch off algorithm,
  // because without |reference_time|, algorithm cannot work.
  //
  // |reference_time| is not set for low-latency video streams and are therefore
  // rendered without algorithm, unless |maximum_composition_delay_in_frames| is
  // set in which case a dedicated low-latency algorithm is switched on. Please
  // note that this is an experimental feature that is only active if certain
  // experimental parameters are specified in WebRTC. See crbug.com/1138888 for
  // more information.
  if (!frame->metadata().reference_time.has_value() &&
      !frame->metadata().maximum_composition_delay_in_frames) {
    DLOG(WARNING) << "Incoming VideoFrames have no reference_time, "
                     "switching off super sophisticated rendering algorithm";
    rendering_frame_buffer_.reset();
    pending_frames_info_.clear();
    RenderWithoutAlgorithm(std::move(frame), is_copy);
    return;
  }
  base::TimeTicks render_time =
      frame->metadata().reference_time.value_or(base::TimeTicks());

  // WebRTC can sometimes submit frames with out-of-order timestamps. This
  // occurs because the mapping between RTP timestamps and presentation
  // timestamps might not have stabilized yet.
  // See https://issues.webrtc.org/370818168.
  const bool is_out_of_order =
      pending_frames_info_.empty()
          ? false
          : frame->timestamp() < pending_frames_info_.back().timestamp;

  const base::TimeTicks now = base::TimeTicks::Now();
  // |last_deadline_max_| is typically in the future in which case
  // |deadline_offset| is negative. If |deadline_offset| is positive, it means
  // that UpdateCurrentFrame() hasn't been called in a while. These callbacks
  // can stop when the tab is hidden or the page area containing the video frame
  // is scrolled out of view. Since some hardware decoders only have a limited
  // number of output frames, we must aggressively release frames in this case.
  const base::TimeDelta deadline_offset = now - last_deadline_max_;
  auto max_frame_delay = frame->metadata().maximum_composition_delay_in_frames
                             ? kMaximumVsyncDelayForLowLatencyRenderer
                             : base::TimeDelta();
  const bool is_update_overdue = deadline_offset > max_frame_delay;

  if (is_out_of_order || is_update_overdue) {
    base::UmaHistogramEnumeration(
        UmaPrefix() + ".ReasonToClearRenderBuffer",
        is_out_of_order ? ReasonToClearRenderBuffer::kOutOfOrder
                        : ReasonToClearRenderBuffer::kUpdateOverdue);
    // Note: the frame in |rendering_frame_buffer_| with lowest index is the
    // same as |current_frame_|. Function SetCurrentFrame() handles whether
    // to increase |dropped_frame_count_| for that frame, so here we should
    // increase |dropped_frame_count_| by the count of all other frames.
    dropped_frame_count_ += rendering_frame_buffer_->frames_queued() - 1;
    rendering_frame_buffer_->Reset();
    pending_frames_info_.clear();
    RenderWithoutAlgorithm(frame, is_copy);
  }

  pending_frames_info_.emplace_back(frame->unique_id(), frame->timestamp(),
                                    render_time, is_copy);
  rendering_frame_buffer_->EnqueueFrame(std::move(frame));

  // Note 2: `EnqueueFrame` may drop the frame instead of enqueuing it for many
  // reasons, so if this happens drop our info entry. These dropped frames will
  // be accounted for during the next Render() call.
  if (pending_frames_info_.size() != rendering_frame_buffer_->frames_queued()) {
    pending_frames_info_.pop_back();
    DCHECK_EQ(pending_frames_info_.size(),
              rendering_frame_buffer_->frames_queued());
  }
}
```

### 功能归纳

`WebMediaPlayerMSCompositor` 的主要功能是**管理和选择最佳的视频帧用于渲染显示，特别是在处理来自 MediaStream 的视频流时**。它充当了视频帧的接收者、处理者和提交者，最终将选定的帧交给渲染管道进行展示。

具体来说，它的功能包括：

1. **接收和队列化视频帧:** 从视频解码器或其他来源接收解码后的视频帧 (`EnqueueFrame`).
2. **帧选择逻辑 (Compositing):**  根据时间戳和其他元数据，决定哪个帧应该被渲染。它维护一个帧缓冲区 (`rendering_frame_buffer_`)，并可能使用不同的算法来选择最佳帧，尤其是在处理远程视频流时（`RTCSmoothnessAlgorithmEnabled`）。
3. **同步和定时:**  与渲染管道进行同步，根据 VSync 信号 (`UpdateCurrentFrame`) 以及提供的 deadline 信息来选择和提供帧。
4. **帧提交:** 将选定的视频帧提交给渲染器 (`WebVideoFrameSubmitter`) 或其他 `cc::VideoFrameProvider::Client`。
5. **元数据管理:**  处理和传递视频帧的元数据，例如时间戳、变换信息等。
6. **性能监控:**  记录帧率、丢帧数等性能指标，用于调试和优化。
7. **处理暂停和恢复:**  处理视频渲染的启动和停止。
8. **处理页面可见性:** 根据页面是否可见来调整渲染行为。
9. **处理上下文丢失:** 当 GPU 上下文丢失时采取措施，例如设置黑帧。

总结来说，`WebMediaPlayerMSCompositor` 负责确保来自 MediaStream 的视频能够平滑、及时地渲染到屏幕上，并处理各种可能影响渲染质量的因素，例如网络抖动、帧到达顺序、以及渲染时机等。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/web_media_player_ms_compositor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/web_media_player_ms_compositor.h"

#include <stdint.h>

#include <string>
#include <utility>

#include "base/hash/hash.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/values.h"
#include "build/build_config.h"
#include "cc/paint/skia_paint_canvas.h"
#include "media/base/media_switches.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "media/renderers/paint_canvas_video_renderer.h"
#include "services/viz/public/cpp/gpu/context_provider_command_buffer.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_video_frame_submitter.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/public/web/modules/mediastream/web_media_player_ms.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_media.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/libyuv/include/libyuv/convert.h"
#include "third_party/libyuv/include/libyuv/planar_functions.h"
#include "third_party/libyuv/include/libyuv/video_common.h"
#include "third_party/skia/include/core/SkSurface.h"

namespace WTF {

template <typename T>
struct CrossThreadCopier<std::optional<T>>
    : public CrossThreadCopierPassThrough<std::optional<T>> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
//
// LINT.IfChange(ReasonToClearRenderBuffer)
enum class ReasonToClearRenderBuffer {
  kOutOfOrder = 0,
  kUpdateOverdue = 1,
  kMaxValue = kUpdateOverdue,
};
// LINT.ThenChange(/tools/metrics/histograms/metadata/media/enums.xml)

// This function copies |frame| to a new I420 or YV12A media::VideoFrame.
scoped_refptr<media::VideoFrame> CopyFrame(
    scoped_refptr<media::VideoFrame> frame,
    media::PaintCanvasVideoRenderer* video_renderer) {
  scoped_refptr<media::VideoFrame> new_frame;
  if (frame->HasSharedImage()) {
    DCHECK(frame->format() == media::PIXEL_FORMAT_ARGB ||
           frame->format() == media::PIXEL_FORMAT_XRGB ||
           frame->format() == media::PIXEL_FORMAT_ABGR ||
           frame->format() == media::PIXEL_FORMAT_XBGR ||
           frame->format() == media::PIXEL_FORMAT_I420 ||
           frame->format() == media::PIXEL_FORMAT_NV12);
    auto provider = Platform::Current()->SharedMainThreadContextProvider();
    if (!provider) {
      // Return a black frame (yuv = {0, 0x80, 0x80}).
      return media::VideoFrame::CreateColorFrame(
          frame->visible_rect().size(), 0u, 0x80, 0x80, frame->timestamp());
    }

    SkBitmap bitmap;
    bitmap.allocPixels(SkImageInfo::MakeN32Premul(
        frame->visible_rect().width(), frame->visible_rect().height()));
    cc::SkiaPaintCanvas paint_canvas(bitmap);

    DCHECK(provider->RasterInterface());
    video_renderer->Copy(frame.get(), &paint_canvas, provider.get());

    bitmap.setImmutable();
    new_frame =
        media::CreateFromSkImage(bitmap.asImage(), frame->visible_rect(),
                                 frame->natural_size(), frame->timestamp());
    if (!new_frame) {
      return media::VideoFrame::CreateColorFrame(
          frame->visible_rect().size(), 0u, 0x80, 0x80, frame->timestamp());
    }
  } else {
    DCHECK(frame->IsMappable());
    if (frame->format() != media::PIXEL_FORMAT_I420A &&
        frame->format() != media::PIXEL_FORMAT_I420 &&
        frame->format() != media::PIXEL_FORMAT_NV12 &&
        frame->format() != media::PIXEL_FORMAT_ARGB) {
      DLOG(WARNING) << frame->format() << " is not supported.";
      return media::VideoFrame::CreateColorFrame(
          frame->visible_rect().size(), 0u, 0x80, 0x80, frame->timestamp());
    }

    const gfx::Size& coded_size = frame->coded_size();
    new_frame = media::VideoFrame::CreateFrame(
        frame->format(), coded_size, frame->visible_rect(),
        frame->natural_size(), frame->timestamp());
    if (!new_frame) {
      return media::VideoFrame::CreateColorFrame(
          frame->visible_rect().size(), 0u, 0x80, 0x80, frame->timestamp());
    }

    if (frame->format() == media::PIXEL_FORMAT_NV12) {
      libyuv::NV12Copy(frame->data(media::VideoFrame::Plane::kY),
                       frame->stride(media::VideoFrame::Plane::kY),
                       frame->data(media::VideoFrame::Plane::kUV),
                       frame->stride(media::VideoFrame::Plane::kUV),
                       new_frame->writable_data(media::VideoFrame::Plane::kY),
                       new_frame->stride(media::VideoFrame::Plane::kY),
                       new_frame->writable_data(media::VideoFrame::Plane::kUV),
                       new_frame->stride(media::VideoFrame::Plane::kUV),
                       coded_size.width(), coded_size.height());
    } else if (frame->format() == media::PIXEL_FORMAT_ARGB) {
      libyuv::ARGBCopy(
          frame->data(media::VideoFrame::Plane::kARGB),
          frame->stride(media::VideoFrame::Plane::kARGB),
          new_frame->writable_data(media::VideoFrame::Plane::kARGB),
          new_frame->stride(media::VideoFrame::Plane::kARGB),
          coded_size.width(), coded_size.height());
    } else {
      libyuv::I420Copy(frame->data(media::VideoFrame::Plane::kY),
                       frame->stride(media::VideoFrame::Plane::kY),
                       frame->data(media::VideoFrame::Plane::kU),
                       frame->stride(media::VideoFrame::Plane::kU),
                       frame->data(media::VideoFrame::Plane::kV),
                       frame->stride(media::VideoFrame::Plane::kV),
                       new_frame->writable_data(media::VideoFrame::Plane::kY),
                       new_frame->stride(media::VideoFrame::Plane::kY),
                       new_frame->writable_data(media::VideoFrame::Plane::kU),
                       new_frame->stride(media::VideoFrame::Plane::kU),
                       new_frame->writable_data(media::VideoFrame::Plane::kV),
                       new_frame->stride(media::VideoFrame::Plane::kV),
                       coded_size.width(), coded_size.height());
    }
    if (frame->format() == media::PIXEL_FORMAT_I420A) {
      libyuv::CopyPlane(frame->data(media::VideoFrame::Plane::kA),
                        frame->stride(media::VideoFrame::Plane::kA),
                        new_frame->writable_data(media::VideoFrame::Plane::kA),
                        new_frame->stride(media::VideoFrame::Plane::kA),
                        coded_size.width(), coded_size.height());
    }
  }

  // Transfer metadata keys.
  new_frame->metadata().MergeMetadataFrom(frame->metadata());
  return new_frame;
}

gfx::Size RotationAdjustedSize(media::VideoRotation rotation,
                               const gfx::Size& size) {
  if (rotation == media::VIDEO_ROTATION_90 ||
      rotation == media::VIDEO_ROTATION_270) {
    return gfx::Size(size.height(), size.width());
  }

  return size;
}

// Returns the UMA histogram prefix for the decoded frame metrics reported from
// the file.
std::string UmaPrefix() {
  return "Media.WebMediaPlayerCompositor";
}

// UpdateCurrentFrame() callbacks can stop when the tab is hidden or the page
// area containing the video frame is scrolled out of view. Maximum allowed
// delay in the callbacks which will drop all the pending decoder output frames
// and reset the frame queue.
constexpr base::TimeDelta kMaximumVsyncDelayForLowLatencyRenderer =
    base::Milliseconds(50);

}  // anonymous namespace

WebMediaPlayerMSCompositor::WebMediaPlayerMSCompositor(
    scoped_refptr<base::SingleThreadTaskRunner>
        video_frame_compositor_task_runner,
    scoped_refptr<base::SequencedTaskRunner> video_task_runner,
    MediaStreamDescriptor* media_stream_descriptor,
    std::unique_ptr<WebVideoFrameSubmitter> submitter,
    bool use_surface_layer,
    const base::WeakPtr<WebMediaPlayerMS>& player)
    : video_frame_compositor_task_runner_(video_frame_compositor_task_runner),
      video_task_runner_(video_task_runner),
      main_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      player_(player),
      video_frame_provider_client_(nullptr),
      current_frame_rendered_(false),
      last_render_length_(base::Seconds(1.0 / 60.0)),
      total_frame_count_(0),
      dropped_frame_count_(0),
      stopped_(true),
      render_started_(!stopped_) {
  weak_this_ = weak_ptr_factory_.GetWeakPtr();
  if (use_surface_layer) {
    submitter_ = std::move(submitter);

    PostCrossThreadTask(
        *video_frame_compositor_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&WebMediaPlayerMSCompositor::InitializeSubmitter,
                            weak_this_));
    update_submission_state_callback_ = base::BindPostTask(
        video_frame_compositor_task_runner_,
        ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
            &WebMediaPlayerMSCompositor::SetIsSurfaceVisible, weak_this_)));
  }

  HeapVector<Member<MediaStreamComponent>> video_components;
  if (media_stream_descriptor)
    video_components = media_stream_descriptor->VideoComponents();

  const bool remote_video =
      video_components.size() && video_components[0]->Remote();

  if (remote_video && Platform::Current()->RTCSmoothnessAlgorithmEnabled()) {
    base::AutoLock auto_lock(current_frame_lock_);
    rendering_frame_buffer_ = std::make_unique<VideoRendererAlgorithmWrapper>(
        ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
            &WebMediaPlayerMSCompositor::MapTimestampsToRenderTimeTicks,
            CrossThreadUnretained(this))),
        &media_log_);
  }

  // Just for logging purpose.
  std::string stream_id = media_stream_descriptor
                              ? media_stream_descriptor->Id().Utf8()
                              : std::string();
  const uint32_t hash_value = base::Hash(stream_id);
  serial_ = (hash_value << 1) | (remote_video ? 1 : 0);
}

WebMediaPlayerMSCompositor::~WebMediaPlayerMSCompositor() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (video_frame_provider_client_) {
    video_frame_provider_client_->StopUsingProvider();
  }
}

void WebMediaPlayerMSCompositor::InitializeSubmitter() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  submitter_->Initialize(this, /*is_media_stream=*/true);
}

void WebMediaPlayerMSCompositor::SetIsSurfaceVisible(
    bool state,
    base::WaitableEvent* done_event) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  submitter_->SetIsSurfaceVisible(state);
  if (done_event)
    done_event->Signal();
}

// TODO(https://crbug/879424): Rename, since it really doesn't enable
// submission. Do this along with the VideoFrameSubmitter refactor.
void WebMediaPlayerMSCompositor::EnableSubmission(
    const viz::SurfaceId& id,
    media::VideoTransformation transformation,
    bool force_submit) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());

  // If we're switching to |submitter_| from some other client, then tell it.
  if (video_frame_provider_client_ &&
      video_frame_provider_client_ != submitter_.get()) {
    video_frame_provider_client_->StopUsingProvider();
  }

  submitter_->SetTransform(transformation);
  submitter_->SetForceSubmit(force_submit);
  submitter_->EnableSubmission(id);
  video_frame_provider_client_ = submitter_.get();

  if (!stopped_)
    video_frame_provider_client_->StartRendering();
}

void WebMediaPlayerMSCompositor::SetForceBeginFrames(bool enable) {
  if (!submitter_)
    return;

  if (!video_frame_compositor_task_runner_->BelongsToCurrentThread()) {
    PostCrossThreadTask(
        *video_frame_compositor_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&WebMediaPlayerMSCompositor::SetForceBeginFrames,
                            weak_this_, enable));
    return;
  }

  submitter_->SetForceBeginFrames(enable);
}

WebMediaPlayerMSCompositor::Metadata WebMediaPlayerMSCompositor::GetMetadata() {
  base::AutoLock auto_lock(current_frame_lock_);
  return current_metadata_;
}

void WebMediaPlayerMSCompositor::SetForceSubmit(bool force_submit) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  submitter_->SetForceSubmit(force_submit);
}

void WebMediaPlayerMSCompositor::SetIsPageVisible(bool is_visible) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (submitter_)
    submitter_->SetIsPageVisible(is_visible);
}

size_t WebMediaPlayerMSCompositor::total_frame_count() {
  base::AutoLock auto_lock(current_frame_lock_);
  DVLOG(1) << __func__ << ", " << total_frame_count_;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return total_frame_count_;
}

size_t WebMediaPlayerMSCompositor::dropped_frame_count() {
  base::AutoLock auto_lock(current_frame_lock_);
  DVLOG(1) << __func__ << ", " << dropped_frame_count_;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return dropped_frame_count_;
}

void WebMediaPlayerMSCompositor::SetVideoFrameProviderClient(
    cc::VideoFrameProvider::Client* client) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (video_frame_provider_client_)
    video_frame_provider_client_->StopUsingProvider();

  video_frame_provider_client_ = client;
  if (video_frame_provider_client_ && !stopped_)
    video_frame_provider_client_->StartRendering();
}

void WebMediaPlayerMSCompositor::RecordFrameDecodedStats(
    std::optional<base::TimeTicks> frame_received_time,
    std::optional<base::TimeDelta> frame_processing_time,
    std::optional<uint32_t> frame_rtp_timestamp) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  if (frame_received_time && last_enqueued_frame_receive_time_) {
    base::TimeDelta frame_receive_time_delta =
        *frame_received_time - *last_enqueued_frame_receive_time_;
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".FrameReceivedTimeDelta",
                          frame_receive_time_delta);
  }
  last_enqueued_frame_receive_time_ = frame_received_time;

  auto now = base::TimeTicks::Now();
  if (last_enqueued_frame_decoded_time_) {
    base::TimeDelta frame_decoded_time_delta =
        now - *last_enqueued_frame_decoded_time_;
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".FrameDecodedTimeDelta",
                          frame_decoded_time_delta);
  }
  last_enqueued_frame_decoded_time_ = now;

  if (frame_processing_time) {
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".DecodeDuration",
                          frame_processing_time.value());
  }

  if (frame_rtp_timestamp && last_enqueued_frame_rtp_timestamp_) {
    LOCAL_HISTOGRAM_COUNTS_10000(
        UmaPrefix() + ".FrameDecodedRtpTimestampDelta",
        *frame_rtp_timestamp - *last_enqueued_frame_rtp_timestamp_);
  }
  last_enqueued_frame_rtp_timestamp_ = frame_rtp_timestamp;
}

void WebMediaPlayerMSCompositor::SetMetadata() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  current_frame_lock_.AssertAcquired();
  current_metadata_.natural_size = current_frame_->natural_size();
  current_metadata_.video_transform =
      current_frame_->metadata().transformation.value_or(
          media::kNoTransformation);
}

void WebMediaPlayerMSCompositor::EnqueueFrame(
    scoped_refptr<media::VideoFrame> frame,
    bool is_copy) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock auto_lock(current_frame_lock_);
  TRACE_EVENT_INSTANT1("media", "WebMediaPlayerMSCompositor::EnqueueFrame",
                       TRACE_EVENT_SCOPE_THREAD, "Timestamp",
                       frame->timestamp().InMicroseconds());
  ++total_frame_count_;
  ++frame_enqueued_since_last_vsync_;
  std::optional<uint32_t> enqueue_frame_rtp_timestamp;
  if (frame->metadata().rtp_timestamp) {
    enqueue_frame_rtp_timestamp =
        static_cast<uint32_t>(frame->metadata().rtp_timestamp.value());
  }
  RecordFrameDecodedStats(frame->metadata().receive_time,
                          frame->metadata().processing_time,
                          enqueue_frame_rtp_timestamp);

  // With algorithm off, just let |current_frame_| hold the incoming |frame|.
  if (!rendering_frame_buffer_) {
    RenderWithoutAlgorithm(std::move(frame), is_copy);
    return;
  }

  // This is a signal frame saying that the stream is stopped.
  if (frame->metadata().end_of_stream) {
    rendering_frame_buffer_.reset();
    RenderWithoutAlgorithm(std::move(frame), is_copy);
    return;
  }

  // If we detect a bad frame without |reference_time|, we switch off algorithm,
  // because without |reference_time|, algorithm cannot work.
  //
  // |reference_time| is not set for low-latency video streams and are therefore
  // rendered without algorithm, unless |maximum_composition_delay_in_frames| is
  // set in which case a dedicated low-latency algorithm is switched on. Please
  // note that this is an experimental feature that is only active if certain
  // experimental parameters are specified in WebRTC. See crbug.com/1138888 for
  // more information.
  if (!frame->metadata().reference_time.has_value() &&
      !frame->metadata().maximum_composition_delay_in_frames) {
    DLOG(WARNING) << "Incoming VideoFrames have no reference_time, "
                     "switching off super sophisticated rendering algorithm";
    rendering_frame_buffer_.reset();
    pending_frames_info_.clear();
    RenderWithoutAlgorithm(std::move(frame), is_copy);
    return;
  }
  base::TimeTicks render_time =
      frame->metadata().reference_time.value_or(base::TimeTicks());

  // WebRTC can sometimes submit frames with out-of-order timestamps. This
  // occurs because the mapping between RTP timestamps and presentation
  // timestamps might not have stabilized yet.
  // See https://issues.webrtc.org/370818168.
  const bool is_out_of_order =
      pending_frames_info_.empty()
          ? false
          : frame->timestamp() < pending_frames_info_.back().timestamp;

  const base::TimeTicks now = base::TimeTicks::Now();
  // |last_deadline_max_| is typically in the future in which case
  // |deadline_offset| is negative. If |deadline_offset| is positive, it means
  // that UpdateCurrentFrame() hasn't been called in a while. These callbacks
  // can stop when the tab is hidden or the page area containing the video frame
  // is scrolled out of view. Since some hardware decoders only have a limited
  // number of output frames, we must aggressively release frames in this case.
  const base::TimeDelta deadline_offset = now - last_deadline_max_;
  auto max_frame_delay = frame->metadata().maximum_composition_delay_in_frames
                             ? kMaximumVsyncDelayForLowLatencyRenderer
                             : base::TimeDelta();
  const bool is_update_overdue = deadline_offset > max_frame_delay;

  if (is_out_of_order || is_update_overdue) {
    base::UmaHistogramEnumeration(
        UmaPrefix() + ".ReasonToClearRenderBuffer",
        is_out_of_order ? ReasonToClearRenderBuffer::kOutOfOrder
                        : ReasonToClearRenderBuffer::kUpdateOverdue);
    // Note: the frame in |rendering_frame_buffer_| with lowest index is the
    // same as |current_frame_|. Function SetCurrentFrame() handles whether
    // to increase |dropped_frame_count_| for that frame, so here we should
    // increase |dropped_frame_count_| by the count of all other frames.
    dropped_frame_count_ += rendering_frame_buffer_->frames_queued() - 1;
    rendering_frame_buffer_->Reset();
    pending_frames_info_.clear();
    RenderWithoutAlgorithm(frame, is_copy);
  }

  pending_frames_info_.emplace_back(frame->unique_id(), frame->timestamp(),
                                    render_time, is_copy);
  rendering_frame_buffer_->EnqueueFrame(std::move(frame));

  // Note 2: `EnqueueFrame` may drop the frame instead of enqueuing it for many
  // reasons, so if this happens drop our info entry. These dropped frames will
  // be accounted for during the next Render() call.
  if (pending_frames_info_.size() != rendering_frame_buffer_->frames_queued()) {
    pending_frames_info_.pop_back();
    DCHECK_EQ(pending_frames_info_.size(),
              rendering_frame_buffer_->frames_queued());
  }
}

bool WebMediaPlayerMSCompositor::UpdateCurrentFrame(
    base::TimeTicks deadline_min,
    base::TimeTicks deadline_max) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());

  TRACE_EVENT_BEGIN2("media", "UpdateCurrentFrame", "Actual Render Begin",
                     deadline_min.ToInternalValue(), "Actual Render End",
                     deadline_max.ToInternalValue());
  if (stopped_)
    return false;

  base::AutoLock auto_lock(current_frame_lock_);

  last_deadline_max_ = deadline_max;
  last_deadline_min_ = deadline_min;
  last_render_length_ = deadline_max - deadline_min;

  if (rendering_frame_buffer_)
    RenderUsingAlgorithm(deadline_min, deadline_max);

  {
    bool tracing_or_dcheck_enabled = false;
    TRACE_EVENT_CATEGORY_GROUP_ENABLED("media", &tracing_or_dcheck_enabled);
#if DCHECK_IS_ON()
    tracing_or_dcheck_enabled = true;
#endif  // DCHECK_IS_ON()
    if (tracing_or_dcheck_enabled && current_frame_) {
      base::TimeTicks render_time =
          current_frame_->metadata().reference_time.value_or(base::TimeTicks());
      DCHECK(current_frame_->metadata().reference_time.has_value() ||
             !rendering_frame_buffer_ ||
             (rendering_frame_buffer_ &&
              !rendering_frame_buffer_->NeedsReferenceTime()))
          << "VideoFrames need REFERENCE_TIME to use "
             "sophisticated video rendering algorithm.";
      TRACE_EVENT_END2("media", "UpdateCurrentFrame", "Ideal Render Instant",
                       render_time.ToInternalValue(), "Serial", serial_);
    }
  }

  return !current_frame_rendered_;
}

bool WebMediaPlayerMSCompositor::HasCurrentFrame() {
  base::AutoLock auto_lock(current_frame_lock_);
  return !!current_frame_;
}

scoped_refptr<media::VideoFrame> WebMediaPlayerMSCompositor::GetCurrentFrame() {
  DVLOG(3) << __func__;
  base::AutoLock auto_lock(current_frame_lock_);
  if (!current_frame_)
    return nullptr;

  TRACE_EVENT_INSTANT1("media", "WebMediaPlayerMSCompositor::GetCurrentFrame",
                       TRACE_EVENT_SCOPE_THREAD, "Timestamp",
                       current_frame_->timestamp().InMicroseconds());
  if (!render_started_)
    return nullptr;

  return current_frame_;
}

void WebMediaPlayerMSCompositor::RecordFrameDisplayedStats(
    base::TimeTicks frame_displayed_time) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (last_presented_frame_display_time_) {
    base::TimeDelta presentation_timestamp_delta =
        frame_displayed_time - *last_presented_frame_display_time_;
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".FramePresentationDelta",
                          presentation_timestamp_delta);
  }
  last_presented_frame_display_time_ = frame_displayed_time;

  if (current_frame_rtp_timestamp_ && last_presented_frame_rtp_timestamp_) {
    int32_t rtp_timestamp_delta =
        *current_frame_rtp_timestamp_ - *last_presented_frame_rtp_timestamp_;
    LOCAL_HISTOGRAM_COUNTS_10000(UmaPrefix() + ".MediaTimelineDelta",
                                 rtp_timestamp_delta);
  }
  last_presented_frame_rtp_timestamp_ = current_frame_rtp_timestamp_;

  if (current_frame_receive_time_) {
    base::TimeDelta frame_receive_to_display =
        frame_displayed_time - *current_frame_receive_time_;
    LOCAL_HISTOGRAM_TIMES(UmaPrefix() + ".FrameReceivedToDisplayedTime",
                          frame_receive_to_display);
  }
}

void WebMediaPlayerMSCompositor::PutCurrentFrame() {
  DVLOG(3) << __func__;
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  current_frame_rendered_ = true;
  RecordFrameDisplayedStats(base::TimeTicks::Now());
}

base::TimeDelta WebMediaPlayerMSCompositor::GetPreferredRenderInterval() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  if (!rendering_frame_buffer_) {
    DCHECK_GE(last_render_length_, base::TimeDelta());
    return last_render_length_;
  }

  DCHECK_GE(rendering_frame_buffer_->average_frame_duration(),
            base::TimeDelta());
  return rendering_frame_buffer_->average_frame_duration();
}

void WebMediaPlayerMSCompositor::OnContextLost() {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  // current_frame_'s resource in the context has been lost, so current_frame_
  // is not valid any more. current_frame_ should be reset. Now the compositor
  // has no concept of resetting current_frame_, so a black frame is set.
  base::AutoLock auto_lock(current_frame_lock_);
  if (!current_frame_ || (!current_frame_->HasSharedImage() &&
                          !current_frame_->HasMappableGpuBuffer())) {
    return;
  }
  scoped_refptr<media::VideoFrame> black_frame =
      media::VideoFrame::CreateBlackFrame(current_frame_->natural_size());
  SetCurrentFrame(std::move(black_frame), false, std::nullopt);
}

void WebMediaPlayerMSCompositor::StartRendering() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  {
    base::AutoLock auto_lock(current_frame_lock_);
    render_started_ = true;
  }
  PostCrossThreadTask(
      *video_frame_compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebMediaPlayerMSCompositor::StartRenderingInternal,
                          weak_this_));
}

void WebMediaPlayerMSCompositor::StopRendering() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  PostCrossThreadTask(
      *video_frame_compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebMediaPlayerMSCompositor::StopRenderingInternal,
                          weak_this_));
}

bool WebMediaPlayerMSCompositor::MapTimestampsToRenderTimeTicks(
    const std::vector<base::TimeDelta>& timestamps,
    std::vector<base::TimeTicks>* wall_clock_times) {
#if DCHECK_IS_ON()
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread() ||
         thread_checker_.CalledOnValidThread() ||
         video_task_runner_->RunsTasksInCurrentSequence());
#endif
  // Note: The mapping code below is not ideal, but WebRTC doesn't expose the
  // audio clock in a way we can map timestamps continuously.
  for (const base::TimeDelta& timestamp : timestamps) {
    base::TimeTicks reference_time;
    base::TimeDelta min_delta = base::TimeDelta::Max();
    for (const auto& pf : pending_frames_info_) {
      if (pf.timestamp == timestamp) {
        reference_time = pf.reference_time;
        min_delta = base::TimeDelta();
        break;
      }
      auto delta = timestamp - pf.timestamp;
      if (delta.is_positive() && delta < min_delta) {
        min_delta = delta;
        reference_time = pf.reference_time;
      }
    }

    // If we don't have a reference time a different algorithm should have been
    // used by this point.
    DCHECK(!reference_time.is_null());

    // No exact reference time was found, so calculate an estimated one using
    // the nearest known timestamp.
    if (min_delta.is_positive()) {
      reference_time =
          reference_time + (min_delta / (timestamp + min_delta)) *
                               (reference_time - base::TimeTicks());
    }

    wall_clock_times->push_back(reference_time);
  }
  return true;
}

void WebMediaPlayerMSCompositor::RenderUsingAlgorithm(
    base::TimeTicks deadline_min,
    base::TimeTicks deadline_max) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  current_frame_lock_.AssertAcquired();

  size_t frames_dropped = 0;
  scoped_refptr<media::VideoFrame> frame = rendering_frame_buffer_->Render(
      deadline_min, deadline_max, &frames_dropped);
  dropped_frame_count_ += frames_dropped;

  // There is a chance we get a null |frame| here:
  // When the player gets paused, we reset |rendering_frame_buffer_|;
  // When the player gets resumed, it is possible that render gets called before
  // we get a new frame. In that case continue to render the |current_frame_|.
  if (!frame || frame == current_frame_)
    return;

  // Walk |pending_frames_info_| to find |is_copy| value for the frame.
  bool is_copy = false;
  for (const auto& pf : pending_frames_info_) {
    if (pf.unique_id == frame->unique_id()) {
      is_copy = pf.is_copy;
      break;
    }
  }

  // Erase frames no longer held by the rendering buffer. Note: The algorithm
  // will continue to hold the current rendered frame until the next Render().
  while (pending_frames_info_.size() !=
         rendering_frame_buffer_->frames_queued()) {
    pending_frames_info_.pop_front();
  }

  SetCurrentFrame(std::move(frame), is_copy, deadline_min);
}

void WebMediaPlayerMSCompositor::RenderWithoutAlgorithm(
    scoped_refptr<media::VideoFrame> frame,
    bool is_copy) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  PostCrossThreadTask(
      *video_frame_compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &WebMediaPlayerMSCompositor::RenderWithoutAlgorithmOnCompositor,
          weak_this_, std::move(frame), is_copy));
}

void WebMediaPlayerMSCompositor::RenderWithoutAlgorithmOnCompositor(
    scoped_refptr<media::VideoFrame> frame,
    bool is_copy) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  {
    base::AutoLock auto_lock(current_frame_lock_);
    // Last timestamp in the stream might not have timestamp.
    if (current_frame_ && !frame->timestamp().is_zero() &&
        frame->timestamp() > current_frame_->timestamp()) {
      last_render_length_ = frame->timestamp() - current_frame_->timestamp();
    }

    // Trace events to help with debugging frame presentation times.
    const base::TimeTicks now = base::TimeTicks::Now();
    base::TimeDelta diff_from_deadline_min = now - last_deadline_min_;
    base::TimeDelta diff_from_deadline_max = now - last_deadline_max_;
    TRACE_EVENT_INSTANT2("media",
                         "RenderWithoutAlgorithm Difference From Deadline",
                         TRACE_EVENT_SCOPE_THREAD, "diff_from_deadline_min",
                         diff_from_deadline_min, "diff_from_deadline_max",
                         diff_from_deadline_max);
    SetCurrentFrame(std::move(frame), is_copy, last_deadline_max_);
  }
  if (video_frame_provider_client_)
    video_frame_provider_client_->DidReceiveFrame();
}

void WebMediaPlayerMSCompositor::SetCurrentFrame(
    scoped_refptr<media::VideoFrame> frame,
    bool is_copy,
    std::optional<base::TimeTicks> expected_display_time) {
  DCHECK(video_frame_compositor_task_runner_->BelongsToCurrentThread());
  current_frame_lock_.AssertAcquired();
  TRACE_EVENT_INSTANT1("media", "WebMediaPlayerMSCompositor::SetCurrentFrame",
                       TRACE_EVENT_SCOPE_THREAD, "Timestamp",
                       frame->timestamp().InMicroseconds());

  if (!current_frame_rendered_)
    ++dropped_frame_count_;
  current_frame_rendered_ = false;

  // Compare current frame with |frame|. Initialize values as if there is no
  // current frame.
  bool is_first_frame = true;
  bool has_frame_size_changed = false;

  std::optional<media::VideoTransformation> new_transform =
      media::kNoTransformation;
  if (frame->metadata().transformation)
    new_transform = frame->metadata().transformation;

  std::optional<bool> new_opacity;
  new_opacity = media::IsOpaque(frame->format());

  if (current_frame_) {
    // We have a current frame, so determine what has changed.
    is_first_frame = false;

    auto current_video_transform =
        current_frame_->metadata().transformation.value_or(
            media::kNoTransformation);
    has_frame_size_changed =
        RotationAdjustedSize(new_transform->rotation, frame->natural_size()) !=
        RotationAdjustedSize(current
"""


```