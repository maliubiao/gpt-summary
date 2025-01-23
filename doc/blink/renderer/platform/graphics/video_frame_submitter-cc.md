Response:
My thought process for analyzing the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for the functionality of the `VideoFrameSubmitter` class in Chromium's Blink engine. It also wants connections to JavaScript/HTML/CSS, logical deductions with input/output, common errors, and a summary of its function.

2. **Initial Scan for Key Information:** I'll first scan the code for important keywords and class names to get a high-level overview. I see:
    * `VideoFrameSubmitter` (the main class)
    * `cc::VideoFrameProvider` (the source of video frames)
    * `viz::mojom::blink::CompositorFrameSink` (the interface for submitting frames to the compositor)
    * `media::VideoFrame` (the video frame data)
    * `viz::SurfaceId`, `viz::LocalSurfaceId` (identifiers for surfaces in the compositor)
    * `base::FeatureList` (for enabling experimental features)
    * `VideoFrameSinkBundle` (for optimizing frame submission)
    * Methods like `SubmitCompositorFrame`, `SetNeedsBeginFrame`, `DidReceiveCompositorFrameAck`, `OnBeginFrame`.

3. **Identify Core Responsibilities:** Based on the keywords and methods, I can infer the core responsibilities:
    * **Receiving video frames:**  It takes video frames from a `VideoFrameProvider`.
    * **Preparing frames for the compositor:** It transforms the `media::VideoFrame` into a `viz::CompositorFrame`.
    * **Submitting frames to the compositor:** It uses the `CompositorFrameSink` interface to send frames to Viz.
    * **Managing frame lifecycle:** It handles acknowledgments (`DidReceiveCompositorFrameAck`) and informs the provider about frame presentation.
    * **Optimizing submission:** It uses `VideoFrameSinkBundle` to batch submissions.
    * **Handling context loss:**  It reacts to GPU context loss and re-initializes.
    * **Managing visibility and rendering state:** It controls when to start and stop rendering and frame submission based on visibility and other factors.

4. **Relate to Web Technologies (JavaScript/HTML/CSS):**  Now, I'll think about how these functionalities connect to the user-facing web technologies:
    * **HTML `<video>` element:** The `VideoFrameSubmitter` is directly involved in rendering the content of a `<video>` element. It takes the decoded video frames and sends them to the compositor for display.
    * **JavaScript Media API:** JavaScript uses APIs like `requestVideoFrameCallback` to interact with video. While this code doesn't directly *implement* that API, it's part of the rendering pipeline that makes it work. When JavaScript provides a new frame or triggers a redraw, the `VideoFrameSubmitter` handles the submission.
    * **CSS Transformations and Opacity:**  CSS properties like `transform` and `opacity` applied to the `<video>` element or its ancestors influence how the compositor renders the video frame. The `VideoFrameSubmitter` needs to communicate opacity changes to the compositor. The `transform_` member suggests it also handles video transformations.

5. **Logical Deductions (Input/Output):**  I'll try to think of scenarios and what the class does:
    * **Input:** A `media::VideoFrame` from the `VideoFrameProvider`. The `viz::BeginFrameArgs` from the compositor.
    * **Output:** A `viz::CompositorFrame` sent to the compositor. Signals sent to the `VideoFrameProvider` (e.g., when a frame is presented or dropped). Calls to `SetNeedsBeginFrame` to control the compositor's frame generation.

6. **Common Usage Errors:**  I'll consider how a developer or the system might misuse this:
    * **Not calling `Initialize`:**  The `VideoFrameProvider` needs to be set up.
    * **Submitting frames without a valid `SurfaceId`:** The compositor needs to know where to render the frame.
    * **Context loss not handled:** If the GPU context is lost, the submission needs to be reset gracefully.
    * **Race conditions:**  Although not directly exposed to developers, internal race conditions could occur if the different threads interacting with this class are not properly synchronized.

7. **Synthesize a Summary:** Finally, I'll combine my understanding into a concise summary of the `VideoFrameSubmitter`'s role. It's essentially the bridge between the decoded video frames and the compositor, responsible for efficiently and correctly displaying video content.

8. **Structure the Answer:**  I'll organize my findings into the categories requested by the prompt: Functionality, Relationship to Web Technologies, Logical Deductions, Common Errors, and Summary. I will use clear and concise language.

**(Self-Correction/Refinement):** While analyzing, I might realize some initial assumptions were slightly off. For example,  the `VideoFrameSubmitter` doesn't directly decode the video, that's the role of other components. It *receives* decoded frames. I will refine my understanding based on the code details. The `FrameSinkBundleProxy` is a key optimization, and I need to understand its purpose in reducing IPC traffic. I also noted the handling of `force_begin_frames_` and `force_submit_`, indicating mechanisms for specific scenarios like Picture-in-Picture. These nuances should be included in the description.
这是 `blink/renderer/platform/graphics/video_frame_submitter.cc` 文件的第一部分，主要负责将解码后的视频帧提交到 Chromium 的合成器 (Compositor) 进行渲染。以下是对其功能的归纳和分析：

**功能归纳 (Part 1):**

* **视频帧提交的核心逻辑:**  该类是视频渲染管道中的关键组件，负责接收来自 `cc::VideoFrameProvider` 的视频帧，并将其转换为合成器能够理解和渲染的 `viz::CompositorFrame`。
* **与合成器通信:** 它通过 `viz::mojom::blink::CompositorFrameSink` 接口与合成器进行通信，发送合成帧、接收帧的确认信息 (ack) 以及处理资源回收。
* **帧同步和调度:**  它参与合成器的帧调度机制，通过 `SetNeedsBeginFrame` 通知合成器是否需要开始新的帧，并处理合成器发来的 `BeginFrame` 事件。
* **资源管理:** 它与 `VideoFrameResourceProvider` 协同工作，管理视频帧相关的 GPU 纹理资源，包括创建、上传和回收。
* **优化策略 (VideoFrameSinkBundle):**  引入了 `VideoFrameSinkBundle` 特性，用于在同一线程和父 FrameSinkId 下的多个 `VideoFrameSubmitter` 之间共享 `FrameSinkBundle`，以减少 IPC 通信量，提高性能。
* **处理视频属性变化:** 能够处理视频帧大小、变换 (transform) 和透明度 (opacity) 的变化，并将其同步到合成器。
* **处理上下文丢失:**  实现了 `ContextLostObserver` 和 `GpuChannelObserver` 接口，以便在 GPU 上下文丢失或 GPU 通道断开时进行清理和重新初始化。
* **性能监控:** 使用 `cc::VideoPlaybackRoughnessReporter` 收集和上报视频播放的流畅度指标。
* **空帧提交:**  在不需要渲染实际视频帧时 (例如，视频不可见时)，可以提交空帧以释放 GPU 资源。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML `<video>` 标签:** 当 HTML 中存在 `<video>` 标签时，Blink 引擎会创建相应的渲染对象和 `VideoFrameProvider` 来获取解码后的视频帧。`VideoFrameSubmitter` 则负责将这些帧提交到合成器，最终显示在 `<video>` 标签对应的页面区域。
* **JavaScript Media API:**  JavaScript 可以通过 Media API 控制视频的播放、暂停、seek 等操作。这些操作可能会导致 `VideoFrameProvider` 提供的视频帧发生变化，从而触发 `VideoFrameSubmitter` 提交新的帧。例如，调用 `video.play()` 可能会启动视频帧的提交过程。
* **CSS 样式:**  应用于 `<video>` 标签或其父元素的 CSS 样式，例如 `transform` (旋转、缩放) 和 `opacity`，会影响视频的渲染效果。`VideoFrameSubmitter` 中的 `SetTransform` 方法接收 `media::VideoTransformation` 信息，而 Opacity 的变化也会通知到合成器，确保 CSS 样式能够正确应用于视频帧。
    * **举例:**  假设 CSS 中设置了 `video { transform: rotate(90deg); opacity: 0.5; }`。当 `VideoFrameSubmitter` 提交视频帧时，它会根据 `rotate(90deg)` 计算出相应的 `media::VideoTransformation` 并传递给合成器。同时，`opacity: 0.5` 会导致 `VideoFrameSubmitter` 通知合成器视频的透明度为 0.5。

**逻辑推理 (假设输入与输出):**

假设输入：

1. **`video_frame_provider_` 提供了一个新的 `media::VideoFrame` 对象，其 `natural_size` 为 1920x1080。**
2. **当前 `frame_size_` 为空 (首次提交帧)。**
3. **`is_rendering_` 为 true。**
4. **`ShouldSubmit()` 返回 true (例如，视频可见且没有被强制停止提交)。**
5. **`waiting_for_compositor_ack_` 为 0。**

逻辑推理：

* 由于 `frame_size_` 为空，且新的视频帧大小为 1920x1080，`frame_size_changed` 将为 true。
* `frame_size_` 将被更新为 1920x1080。
* 由于是首次提交帧，会生成新的 `LocalSurfaceId`。
* `CreateCompositorFrame` 方法将被调用，将 `media::VideoFrame` 转换为 `viz::CompositorFrame`。
* `SubmitCompositorFrame` 方法将被调用，将生成的 `viz::CompositorFrame` 提交到合成器。
* `waiting_for_compositor_ack_` 的值将增加 1。

输出：

* 一个包含 1920x1080 视频内容的 `viz::CompositorFrame` 被发送到合成器。
* `frame_size_` 被更新为 1920x1080。
* `waiting_for_compositor_ack_` 的值为 1。

**用户或编程常见的使用错误举例说明:**

* **未调用 `Initialize` 或传入空的 `cc::VideoFrameProvider`:** 如果没有正确初始化 `VideoFrameSubmitter` 并提供视频帧源，那么它将无法提交任何帧，导致视频无法显示。
* **在 `EnableSubmission` 之前尝试提交帧:** `EnableSubmission` 方法负责关联 `VideoFrameSubmitter` 和合成器的 `SurfaceId`。如果在调用 `EnableSubmission` 之前就尝试提交帧，将无法找到目标合成器表面。
* **在 GPU 上下文丢失后未进行适当的清理和重置:**  GPU 上下文丢失是一个常见的问题。如果开发者没有正确处理 `OnContextLost` 事件，可能会导致程序崩溃或渲染错误。例如，如果在上下文丢失后仍然尝试使用之前创建的 GPU 资源，会导致程序出错。
* **在错误的时机调用 `StopUsingProvider`:**  `StopUsingProvider` 会停止使用当前的 `VideoFrameProvider`。如果在需要继续播放视频时错误地调用此方法，会导致视频停止更新。
* **假设 `DidReceiveCompositorFrameAck` 会立即被调用:**  帧的确认信息是异步的。如果在提交帧后立即假设收到了 ack 并进行依赖 ack 的操作，可能会导致逻辑错误。

**功能归纳 (Part 1 总括):**

总而言之，`blink/renderer/platform/graphics/video_frame_submitter.cc` (第一部分) 的核心功能是作为 Blink 渲染引擎中视频渲染管道的关键环节，负责接收解码后的视频帧，将其转换为合成器可以处理的格式，并通过与合成器的通信机制，确保视频内容能够高效、正确地渲染到屏幕上。它还涉及资源管理、帧同步和一些性能优化策略。

### 提示词
```
这是目录为blink/renderer/platform/graphics/video_frame_submitter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/video_frame_submitter.h"

#include <optional>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "cc/metrics/video_playback_roughness_reporter.h"
#include "components/viz/common/features.h"
#include "components/viz/common/resources/resource_id.h"
#include "components/viz/common/resources/returned_resource.h"
#include "components/viz/common/surfaces/frame_sink_bundle_id.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/ipc/client/client_shared_image_interface.h"
#include "gpu/ipc/client/gpu_channel_host.h"
#include "media/base/video_frame.h"
#include "media/base/video_types.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/viz/public/cpp/gpu/context_provider_command_buffer.h"
#include "services/viz/public/mojom/compositing/compositor_frame_sink.mojom-blink.h"
#include "services/viz/public/mojom/compositing/frame_sink_bundle.mojom-blink.h"
#include "services/viz/public/mojom/compositing/layer_context.mojom-blink.h"
#include "services/viz/public/mojom/hit_test/hit_test_region_list.mojom-blink.h"
#include "third_party/abseil-cpp/absl/cleanup/cleanup.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/frame_sinks/embedded_frame_sink.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_sink_bundle.h"
#include "ui/gfx/presentation_feedback.h"

namespace blink {

namespace {

// If enabled, every VideoFrameSubmitter will share a FrameSinkBundle with every
// other VideoFrameSubmitter living on the same thread with the same parent
// FrameSinkId. This is used to aggregate Viz communication and substantially
// reduce IPC traffic when many VideoFrameSubmitters are active within a frame.
BASE_FEATURE(kUseVideoFrameSinkBundle,
             "UseVideoFrameSinkBundle",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Builds a cc::FrameInfo representing a video frame, which is considered
// Compositor-only.
cc::FrameInfo CreateFrameInfo(cc::FrameInfo::FrameFinalState final_state) {
  cc::FrameInfo frame_info;
  frame_info.final_state = final_state;
  frame_info.smooth_thread = cc::FrameInfo::SmoothThread::kSmoothCompositor;
  frame_info.main_thread_response = cc::FrameInfo::MainThreadResponse::kMissing;
  return frame_info;
}

// Helper method for creating manual ack with damage and prefered frame
// interval.
viz::BeginFrameAck CreateManualAckWithDamageAndPreferredFrameInterval(
    cc::VideoFrameProvider* video_frame_provider) {
  auto begin_frame_ack = viz::BeginFrameAck::CreateManualAckWithDamage();
  begin_frame_ack.preferred_frame_interval =
      video_frame_provider ? video_frame_provider->GetPreferredRenderInterval()
                           : viz::BeginFrameArgs::MinInterval();
  return begin_frame_ack;
}

void RecordUmaPreSubmitBufferingDelay(bool is_media_stream,
                                      base::TimeDelta delay) {
  if (is_media_stream) {
    base::UmaHistogramTimes("Media.VideoFrameSubmitter.Rtc.PreSubmitBuffering",
                            delay);
  } else {
    base::UmaHistogramTimes(
        "Media.VideoFrameSubmitter.Video.PreSubmitBuffering", delay);
  }
}

}  // namespace

// Helper CompositorFrameSink implementation which sits locally between a
// VideoFrameSubmitter and a thread-local FrameSinkBundle connection to Viz.
// This queues outgoing messages so they can be delivered in batches. With
// many active VideoFrameSubmitters in the same frame, this can significantly
// reduce Viz communication overhead.
class VideoFrameSubmitter::FrameSinkBundleProxy
    : public viz::mojom::blink::CompositorFrameSink {
 public:
  FrameSinkBundleProxy(base::WeakPtr<VideoFrameSinkBundle> bundle,
                       const viz::FrameSinkId& frame_sink_id)
      : bundle_(std::move(bundle)),
        bundle_id_(bundle_->bundle_id()),
        frame_sink_id_(frame_sink_id) {}
  FrameSinkBundleProxy(const FrameSinkBundleProxy&) = delete;
  FrameSinkBundleProxy& operator=(const FrameSinkBundleProxy&) = delete;

  ~FrameSinkBundleProxy() override {
    if (bundle_) {
      bundle_->RemoveClient(frame_sink_id_);
    }
  }

  // viz::mojom::Blink::CompositorFrameSink:
  void SetNeedsBeginFrame(bool needs_begin_frame) override {
    if (!bundle_) {
      return;
    }

    bundle_->SetNeedsBeginFrame(frame_sink_id_.sink_id(), needs_begin_frame);
  }

  void SetWantsBeginFrameAcks() override {
    if (!bundle_) {
      return;
    }

    bundle_->SetWantsBeginFrameAcks(frame_sink_id_.sink_id());
  }

  // Not used by VideoFrameSubmitter.
  void SetWantsAnimateOnlyBeginFrames() override { NOTREACHED(); }
  void SetAutoNeedsBeginFrame() override { NOTREACHED(); }

  void SubmitCompositorFrame(
      const viz::LocalSurfaceId& local_surface_id,
      viz::CompositorFrame frame,
      std::optional<viz::HitTestRegionList> hit_test_region_list,
      uint64_t submit_time) override {
    if (!bundle_) {
      return;
    }

    bundle_->SubmitCompositorFrame(
        frame_sink_id_.sink_id(), local_surface_id, std::move(frame),
        std::move(hit_test_region_list), submit_time);
  }

  // Not used by VideoFrameSubmitter.
  void SubmitCompositorFrameSync(
      const viz::LocalSurfaceId& local_surface_id,
      viz::CompositorFrame frame,
      std::optional<viz::HitTestRegionList> hit_test_region_list,
      uint64_t submit_time,
      SubmitCompositorFrameSyncCallback callback) override {
    NOTREACHED();
  }

  void DidNotProduceFrame(const viz::BeginFrameAck& ack) override {
    if (!bundle_) {
      return;
    }
    bundle_->DidNotProduceFrame(frame_sink_id_.sink_id(), ack);
  }

  void DidAllocateSharedBitmap(base::ReadOnlySharedMemoryRegion region,
                               const viz::SharedBitmapId& id) override {
    if (!bundle_) {
      return;
    }
    bundle_->DidAllocateSharedBitmap(frame_sink_id_.sink_id(),
                                     std::move(region), id);
  }

  void DidDeleteSharedBitmap(const viz::SharedBitmapId& id) override {
    if (!bundle_) {
      return;
    }
    bundle_->DidDeleteSharedBitmap(frame_sink_id_.sink_id(), id);
  }

  void InitializeCompositorFrameSinkType(
      viz::mojom::blink::CompositorFrameSinkType type) override {
    if (!bundle_) {
      return;
    }
    bundle_->InitializeCompositorFrameSinkType(frame_sink_id_.sink_id(), type);
  }

  void BindLayerContext(
      viz::mojom::blink::PendingLayerContextPtr context) override {}

#if BUILDFLAG(IS_ANDROID)
  void SetThreads(const WTF::Vector<viz::Thread>& threads) override {
    bundle_->SetThreads(frame_sink_id_.sink_id(), threads);
  }
#endif

 private:
  const base::WeakPtr<VideoFrameSinkBundle> bundle_;
  const viz::FrameSinkBundleId bundle_id_;
  const viz::FrameSinkId frame_sink_id_;
};

VideoFrameSubmitter::VideoFrameSubmitter(
    WebContextProviderCallback context_provider_callback,
    cc::VideoPlaybackRoughnessReporter::ReportingCallback
        roughness_reporting_callback,
    std::unique_ptr<VideoFrameResourceProvider> resource_provider)
    : context_provider_callback_(context_provider_callback),
      resource_provider_(std::move(resource_provider)),
      roughness_reporter_(std::make_unique<cc::VideoPlaybackRoughnessReporter>(
          std::move(roughness_reporting_callback))),
      frame_trackers_(false, nullptr),
      frame_sorter_(base::BindRepeating(
          &cc::FrameSequenceTrackerCollection::AddSortedFrame,
          base::Unretained(&frame_trackers_))) {
  DETACH_FROM_THREAD(thread_checker_);
}

VideoFrameSubmitter::~VideoFrameSubmitter() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (context_provider_)
    context_provider_->RemoveObserver(this);

  if (shared_image_interface_) {
    shared_image_interface_->gpu_channel()->RemoveObserver(this);
  }

  // Release VideoFrameResourceProvider early since its destruction will make
  // calls back into this class via the viz::SharedBitmapReporter interface.
  resource_provider_.reset();
}

void VideoFrameSubmitter::StopUsingProvider() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (is_rendering_)
    StopRendering();
  video_frame_provider_ = nullptr;
}

void VideoFrameSubmitter::StartRendering() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!is_rendering_);
  is_rendering_ = true;

  if (compositor_frame_sink_) {
    compositor_frame_sink_->SetNeedsBeginFrame(IsDrivingFrameUpdates());
  }

  frame_trackers_.StartSequence(cc::FrameSequenceTrackerType::kVideo);
}

void VideoFrameSubmitter::StopRendering() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(is_rendering_);
  DCHECK(video_frame_provider_);

  is_rendering_ = false;

  frame_trackers_.StopSequence(cc::FrameSequenceTrackerType::kVideo);
  frame_sorter_.Reset();

  UpdateSubmissionState();
}

void VideoFrameSubmitter::DidReceiveFrame() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(video_frame_provider_);
  SubmitSingleFrame();
}

bool VideoFrameSubmitter::IsDrivingFrameUpdates() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // We drive frame updates only when we believe that something is consuming
  // them.  This is different than VideoLayer, which drives updates any time
  // they're in the layer tree.
  return (is_rendering_ && ShouldSubmit()) || force_begin_frames_;
}

void VideoFrameSubmitter::Initialize(cc::VideoFrameProvider* provider,
                                     bool is_media_stream) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!provider)
    return;

  DCHECK(!video_frame_provider_);
  video_frame_provider_ = provider;
  is_media_stream_ = is_media_stream;
  roughness_reporter_->set_is_media_stream(is_media_stream_);

  task_runner_ = base::SingleThreadTaskRunner::GetCurrentDefault();
  context_provider_callback_.Run(
      nullptr, base::BindOnce(&VideoFrameSubmitter::OnReceivedContextProvider,
                              weak_ptr_factory_.GetWeakPtr()));
}

void VideoFrameSubmitter::SetTransform(media::VideoTransformation transform) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  transform_ = transform;
}

void VideoFrameSubmitter::EnableSubmission(viz::SurfaceId surface_id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // TODO(lethalantidote): Set these fields earlier in the constructor. Will
  // need to construct VideoFrameSubmitter later in order to do this.
  frame_sink_id_ = surface_id.frame_sink_id();
  child_local_surface_id_allocator_.UpdateFromParent(
      surface_id.local_surface_id());
  if (resource_provider_->IsInitialized())
    StartSubmitting();
}

void VideoFrameSubmitter::SetIsSurfaceVisible(bool is_visible) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  is_surface_visible_ = is_visible;
  UpdateSubmissionState();
}

void VideoFrameSubmitter::SetIsPageVisible(bool is_visible) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  is_page_visible_ = is_visible;
  UpdateSubmissionState();
}

void VideoFrameSubmitter::SetForceBeginFrames(bool force_begin_frames) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  force_begin_frames_ = force_begin_frames;
  UpdateSubmissionState();
}

void VideoFrameSubmitter::SetForceSubmit(bool force_submit) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  force_submit_ = force_submit;
  UpdateSubmissionState();
}

void VideoFrameSubmitter::OnContextLost() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  receiver_.reset();

  if (context_provider_)
    context_provider_->RemoveObserver(this);

  if (shared_image_interface_) {
    shared_image_interface_->gpu_channel()->RemoveObserver(this);
    shared_image_interface_.reset();
  }

  waiting_for_compositor_ack_ = 0;
  last_frame_id_.reset();

  if (video_frame_provider_)
    video_frame_provider_->OnContextLost();

  resource_provider_->OnContextLost();

  // NOTE: These objects should be reset last; and if `bundle_proxy`_ is set, it
  // should be reset after `remote_frame_sink_`.
  compositor_frame_sink_ = nullptr;
  remote_frame_sink_.reset();
  bundle_proxy_.reset();

  context_provider_callback_.Run(
      context_provider_,
      base::BindOnce(&VideoFrameSubmitter::OnReceivedContextProvider,
                     weak_ptr_factory_.GetWeakPtr()));
}

void VideoFrameSubmitter::OnGpuChannelLost() {
  // GpuChannel lost is notified on the IO thread. Forward it to the
  // VideoFrameCompositor thread.
  if (base::SingleThreadTaskRunner::GetCurrentDefault() != task_runner_) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&VideoFrameSubmitter::OnGpuChannelLost,
                                  weak_ptr_factory_.GetWeakPtr()));
    return;
  }

  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!shared_image_interface_) {
    return;
  }

  // The Observable removes all observers after completing GpuChannelLost
  // notification. No need to RemoveObserver(). Call RemoveObserver during
  // notification will cause deadlock.
  shared_image_interface_.reset();

  OnContextLost();
}

void VideoFrameSubmitter::DidReceiveCompositorFrameAck(
    WTF::Vector<viz::ReturnedResource> resources) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  ReclaimResources(std::move(resources));

  // `waiting_for_compositor_ack_` may be set to zero during SubmitEmptyFrame()
  // or upon ContextLost().
  if (waiting_for_compositor_ack_ == 0) {
    return;
  }

  --waiting_for_compositor_ack_;
}

void VideoFrameSubmitter::OnBeginFrame(
    const viz::BeginFrameArgs& args,
    const WTF::HashMap<uint32_t, viz::FrameTimingDetails>& timing_details,
    bool frame_ack,
    WTF::Vector<viz::ReturnedResource> resources) {
  if (features::IsOnBeginFrameAcksEnabled()) {
    if (frame_ack) {
      DidReceiveCompositorFrameAck(std::move(resources));
    } else if (!resources.empty()) {
      ReclaimResources(std::move(resources));
    }
  }

  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  TRACE_EVENT0("media", "VideoFrameSubmitter::OnBeginFrame");

  last_begin_frame_args_ = args;

  WTF::Vector<uint32_t> frame_tokens;
  for (const auto& id : timing_details.Keys())
    frame_tokens.push_back(id);
  std::sort(frame_tokens.begin(), frame_tokens.end());

  for (const auto& frame_token : frame_tokens) {
    if (viz::FrameTokenGT(frame_token, *next_frame_token_))
      continue;

    auto& details = timing_details.find(frame_token)->value;
    auto& feedback = details.presentation_feedback;

#if BUILDFLAG(IS_LINUX)
    // TODO: On Linux failure flag is unreliable, and perfectly rendered frames
    // are reported as failures all the time.
    bool presentation_failure = false;
#else
    bool presentation_failure =
        feedback.flags & gfx::PresentationFeedback::kFailure;
#endif
    cc::FrameInfo::FrameFinalState final_state =
        cc::FrameInfo::FrameFinalState::kNoUpdateDesired;
    if (ignorable_submitted_frames_.contains(frame_token)) {
      ignorable_submitted_frames_.erase(frame_token);
    } else {
      if (presentation_failure) {
        final_state = cc::FrameInfo::FrameFinalState::kDropped;
      } else {
        final_state = cc::FrameInfo::FrameFinalState::kPresentedAll;

        // We assume that presentation feedback is reliable if
        // 1. (kHWCompletion) OS told us that the frame was shown at that time
        //  or
        // 2. (kVSync) at least presentation time is aligned with vsyncs
        // intervals
        uint32_t reliable_feedback_mask =
            gfx::PresentationFeedback::kHWCompletion |
            gfx::PresentationFeedback::kVSync;
        bool reliable_timestamp = feedback.flags & reliable_feedback_mask;
        roughness_reporter_->FramePresented(frame_token, feedback.timestamp,
                                            reliable_timestamp);
        // Compute the delta between the time the frame was received by the
        // compositor and when it was presented.
        auto delta_between_receive_and_present =
            details.presentation_feedback.timestamp -
            details.received_compositor_frame_timestamp;

        // We compute the average delta between frames being received at the
        // compositor to them being presented using an exponential moving
        // average with a smoothing factor
        // emea_smoothing_factor_for_average_delta_ which defaults to 0.2.
        // The exponential moving average formula for reference is as below:
        // EMEA_Delta = (Delta_New * smoothing_factor) +
        //     (EMEA_PreviousDelta * (1 - smoothing_factor)
        if (average_delta_between_receive_and_present_.is_zero()) {
          average_delta_between_receive_and_present_ =
              delta_between_receive_and_present;
        } else {
          // Smoothing factor for the exponential moving average for the delta.
          constexpr double emea_smoothing_factor_for_average_delta = 0.2;

          average_delta_between_receive_and_present_ =
              delta_between_receive_and_present *
                  emea_smoothing_factor_for_average_delta +
              average_delta_between_receive_and_present_ *
                  (1 - emea_smoothing_factor_for_average_delta);
        }
      }
      if (pending_frames_.contains(frame_token)) {
        frame_sorter_.AddFrameResult(pending_frames_[frame_token],
                                     CreateFrameInfo(final_state));
        pending_frames_.erase(frame_token);
      }
    }

    TRACE_EVENT_NESTABLE_ASYNC_END_WITH_TIMESTAMP0(
        "media", "VideoFrameSubmitter",
        TRACE_ID_WITH_SCOPE("VideoFrameSubmitter", frame_token),
        feedback.timestamp);
  }

  base::TimeTicks deadline_min = args.frame_time + args.interval;
  base::TimeTicks deadline_max = args.frame_time + 2 * args.interval;
  // The default value for the expected display time of the frame is the
  // same as the deadline_max.
  base::TimeTicks frame_expected_display_time = deadline_max;
  // The expected display time of a frame can be computed from the average delta
  // between the frame arriving at the compositor and being presented. We
  // use the average delta computed above and add it to the current time, which
  // gives us an approximate time for when we can expect the frame to actually
  // be presented.
  if (!average_delta_between_receive_and_present_.is_zero()) {
    frame_expected_display_time =
        base::TimeTicks::Now() + average_delta_between_receive_and_present_;
  }

  TRACE_EVENT_INSTANT1("media", "FrameExpectedDisplayTime",
                       TRACE_EVENT_SCOPE_THREAD, "frame_expected_display_time",
                       frame_expected_display_time);

  frame_trackers_.NotifyBeginImplFrame(args);
  frame_sorter_.AddNewFrame(args);

  absl::Cleanup end_frame = [this, &args] {
    frame_trackers_.NotifyFrameEnd(args, args);
  };
  absl::Cleanup roughness_processing = [this] {
    roughness_reporter_->ProcessFrameWindow();
  };

  // Don't call UpdateCurrentFrame() for MISSED BeginFrames. Also don't call it
  // after StopRendering() has been called (forbidden by API contract).
  viz::BeginFrameAck current_begin_frame_ack(args, false);
  current_begin_frame_ack.preferred_frame_interval =
      video_frame_provider_
          ? video_frame_provider_->GetPreferredRenderInterval()
          : viz::BeginFrameArgs::MinInterval();
  if (args.type == viz::BeginFrameArgs::MISSED || !is_rendering_) {
    compositor_frame_sink_->DidNotProduceFrame(current_begin_frame_ack);
    frame_sorter_.AddFrameResult(
        args,
        CreateFrameInfo(cc::FrameInfo::FrameFinalState::kNoUpdateDesired));
    return;
  }

  // Update the current frame, even if we haven't gotten an ack for a previous
  // frame yet. That probably signals a dropped frame, and this will let the
  // provider know that it happened, since we won't PutCurrentFrame this one.
  // Note that we should DidNotProduceFrame with or without the ack.
  if (!video_frame_provider_ ||
      !video_frame_provider_->UpdateCurrentFrame(deadline_min, deadline_max)) {
    compositor_frame_sink_->DidNotProduceFrame(current_begin_frame_ack);
    frame_sorter_.AddFrameResult(
        args,
        CreateFrameInfo(cc::FrameInfo::FrameFinalState::kNoUpdateDesired));
    return;
  }

  // We do have a new frame that we could display.  See if we're supposed to
  // actually submit a frame or not, and try to submit one.
  auto video_frame = video_frame_provider_->GetCurrentFrame();
  if (!SubmitFrame(current_begin_frame_ack, std::move(video_frame))) {
    compositor_frame_sink_->DidNotProduceFrame(current_begin_frame_ack);
    frame_sorter_.AddFrameResult(
        args,
        CreateFrameInfo(cc::FrameInfo::FrameFinalState::kNoUpdateDesired));
    return;
  }

  // We submitted a frame!

  // We still signal PutCurrentFrame here, rather than on the ack, so that it
  // lines up with the correct frame.  Otherwise, any intervening calls to
  // OnBeginFrame => UpdateCurrentFrame will cause the put to signal that the
  // later frame was displayed.
  video_frame_provider_->PutCurrentFrame();
}

void VideoFrameSubmitter::ReclaimResources(
    WTF::Vector<viz::ReturnedResource> resources) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  resource_provider_->ReceiveReturnsFromParent(std::move(resources));
}

void VideoFrameSubmitter::DidAllocateSharedBitmap(
    base::ReadOnlySharedMemoryRegion region,
    const viz::SharedBitmapId& id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(compositor_frame_sink_);
  compositor_frame_sink_->DidAllocateSharedBitmap(std::move(region), id);
}

void VideoFrameSubmitter::DidDeleteSharedBitmap(const viz::SharedBitmapId& id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(compositor_frame_sink_);
  compositor_frame_sink_->DidDeleteSharedBitmap(id);
}

void VideoFrameSubmitter::OnReceivedContextProvider(
    bool use_gpu_compositing,
    scoped_refptr<viz::RasterContextProvider> context_provider,
    scoped_refptr<gpu::ClientSharedImageInterface> shared_image_interface) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!use_gpu_compositing) {
    shared_image_interface_ = std::move(shared_image_interface);
    if (shared_image_interface_) {
      shared_image_interface_->gpu_channel()->AddObserver(this);
    }
    resource_provider_->Initialize(nullptr, this, shared_image_interface_);
    if (frame_sink_id_.is_valid()) {
      StartSubmitting();
    }
    return;
  }

  if (!MaybeAcceptContextProvider(std::move(context_provider))) {
    constexpr base::TimeDelta kGetContextProviderRetryTimeout =
        base::Milliseconds(150);
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(
            context_provider_callback_, context_provider_,
            base::BindOnce(&VideoFrameSubmitter::OnReceivedContextProvider,
                           weak_ptr_factory_.GetWeakPtr())),
        kGetContextProviderRetryTimeout);
    return;
  }

  context_provider_->AddObserver(this);
  resource_provider_->Initialize(context_provider_.get(), nullptr,
                                 /*shared_image_interface*/ nullptr);

  if (frame_sink_id_.is_valid())
    StartSubmitting();
}

bool VideoFrameSubmitter::MaybeAcceptContextProvider(
    scoped_refptr<viz::RasterContextProvider> context_provider) {
  if (!context_provider) {
    return false;
  }

  context_provider_ = std::move(context_provider);
  if (context_provider_->BindToCurrentSequence() !=
      gpu::ContextResult::kSuccess) {
    return false;
  }

  return context_provider_->RasterInterface()->GetGraphicsResetStatusKHR() ==
         GL_NO_ERROR;
}

void VideoFrameSubmitter::StartSubmitting() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(frame_sink_id_.is_valid());

  mojo::Remote<mojom::blink::EmbeddedFrameSinkProvider> provider;
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      provider.BindNewPipeAndPassReceiver());
  if (base::FeatureList::IsEnabled(kUseVideoFrameSinkBundle)) {
    auto& bundle = VideoFrameSinkBundle::GetOrCreateSharedInstance(
        frame_sink_id_.client_id());
    auto weak_bundle = bundle.AddClient(frame_sink_id_, this, provider,
                                        receiver_, remote_frame_sink_);
    bundle_proxy_ = std::make_unique<FrameSinkBundleProxy>(
        std::move(weak_bundle), frame_sink_id_);
    compositor_frame_sink_ = bundle_proxy_.get();
  } else {
    provider->CreateCompositorFrameSink(
        frame_sink_id_, receiver_.BindNewPipeAndPassRemote(),
        remote_frame_sink_.BindNewPipeAndPassReceiver());
    compositor_frame_sink_ = remote_frame_sink_.get();
  }
  compositor_frame_sink_->SetWantsBeginFrameAcks();

  if (!surface_embedder_.is_bound()) {
    provider->ConnectToEmbedder(frame_sink_id_,
                                surface_embedder_.BindNewPipeAndPassReceiver());
  } else {
    GenerateNewSurfaceId();
  }

  remote_frame_sink_.set_disconnect_handler(base::BindOnce(
      &VideoFrameSubmitter::OnContextLost, base::Unretained(this)));

  compositor_frame_sink_->InitializeCompositorFrameSinkType(
      is_media_stream_ ? viz::mojom::CompositorFrameSinkType::kMediaStream
                       : viz::mojom::CompositorFrameSinkType::kVideo);

#if BUILDFLAG(IS_ANDROID)
  WTF::Vector<viz::Thread> threads;
  threads.push_back(viz::Thread{base::PlatformThread::CurrentId(),
                                viz::Thread::Type::kVideo});
  threads.push_back(viz::Thread{Platform::Current()->GetIOThreadId(),
                                viz::Thread::Type::kIO});
  compositor_frame_sink_->SetThreads(threads);
#endif

  UpdateSubmissionState();
}

void VideoFrameSubmitter::UpdateSubmissionState() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!compositor_frame_sink_)
    return;
  const auto is_driving_frame_updates = IsDrivingFrameUpdates();
  compositor_frame_sink_->SetNeedsBeginFrame(is_driving_frame_updates);
  // If we're not driving frame updates, then we're paused / off-screen / etc.
  // Roughness reporting should stop until we resume.  Since the current frame
  // might be on-screen for a long time, we also discard the current window.
  if (!is_driving_frame_updates) {
    roughness_reporter_->Reset();
  }

  // These two calls are very important; they are responsible for significant
  // memory savings when content is off-screen.
  //
  // While off-screen, we do not submit frames (unless |force_submit_| is true),
  // which prevents GPU resource creation and accumulation on the remote side.
  // During the transition to off-screen we further send an empty frame with the
  // intent to evict any resources held for the previous frame. Combined these
  // optimizations save 30-50% in cc:: resource memory usage.
  //
  // See https://crbug.com/829813 and https://crbug.com/829565.
  if (ShouldSubmit()) {
    // Submit even if we're rendering, otherwise we may display an empty frame
    // before the next OnBeginFrame() which can cause a visible flash.
    SubmitSingleFrame();
  } else {
    // Post a delayed task to submit an empty frame. We don't do this here,
    // since there is a race between when we're notified that the player is not
    // visible, and when auto-PiP starts. In PiP, we'll be set to force submit,
    // but we're notified after we find out that the page is hidden.  If we
    // submit an empty frame now, then there will be a flicker in the video
    // when the empty frame is displayed. By delaying the empty frame, we give
    // the auto-PiP a chance to start. Note that the empty frame isn't required
    // for visual correctness; it's just for resource cleanup. We can delay
    // resource cleanup a little.
    //
    // If there are any in-flight empty frame requests, this cancels them. We
    // want to wait until any group of state changes stabilizes.
    empty_frame_timer_.Start(
        FROM_HERE, base::Milliseconds(500),
        base::BindOnce(&VideoFrameSubmitter::SubmitEmptyFrameIfNeeded,
                       base::Unretained(this)));
  }
}

void VideoFrameSubmitter::SubmitEmptyFrameIfNeeded() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!compositor_frame_sink_)
    return;

  // If we are allowed to submit real frames, then don't send a blank frame
  // since the last real frame might actually be visible.
  //
  // We do not actually submit a real frame here, though; that should be done
  // (if desired) by whatever switched us to ShouldSubmit() mode.
  if (ShouldSubmit())
    return;

  // If we don't have a frame size, then we can't send a blank frame.
  if (frame_size_.IsEmpty())
    return;

  SubmitEmptyFrame();
}

bool VideoFrameSubmitter::SubmitFrame(
    const viz::BeginFrameAck& begin_frame_ack,
    scoped_refptr<media::VideoFrame> video_frame) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(video_frame);
  TRACE_EVENT1("media", "VideoFrameSubmitter::SubmitFrame", "frame",
               video_frame->AsHumanReadableString());

  if (!compositor_frame_sink_ || !ShouldSubmit()) {
    return false;
  }

  // Not submitting a frame when waiting for a previous ack saves memory by
  // not building up unused remote side resources. See https://crbug.com/830828.
  //
  // Similarly we don't submit the same frame multiple times.
  if (last_frame_id_ == video_frame->unique_id()) {
    return false;
  }

  gfx::Size frame_size(video_frame->natural_size());

  // Prefer the frame level transform if set.
  auto transform = video_frame->metadata().transformation.value_or(transform_);
  if (transform.rotation == media::VIDEO_ROTATION_90 ||
      transform.rotation == media::VIDEO_ROTATION_270) {
    frame_size = gfx::Size(frame_size.height(), frame_size.width());
  }

  if (frame_size.IsEmpty()) {
    // We're not supposed to get 0x0 frames.  For now, just ignore it until we
    // track down where they're coming from.  Creating a CompositorFrame with an
    // empty output rectangle isn't allowed.
    // crbug.com/979564
    return false;
  }

  bool frame_size_changed = false;
  if (frame_size_ != frame_size) {
    if (!frame_size_.IsEmpty())
      GenerateNewSurfaceId();
    frame_size_ = frame_size;
    frame_size_changed = true;
  }

  // We can't delay frame size changes even if we have a pending compositor ACK
  // because a relayout signal is already in flight on the main thread.
  if (waiting_for_compositor_ack_ > 0 && !frame_size_changed) {
    return false;
  }

  last_frame_id_ = video_frame->unique_id();

  Opacity new_opacity = media::IsOpaque(video_frame->format())
                            ? Opacity::kIsOpaque
                            : Opacity::kIsNotOpaque;

  auto frame_token = ++next_frame_token_;
  auto source_id = begin_frame_ack.frame_id.source_id;
  if (source_id != viz::BeginFrameArgs::kManualSourceId) {
    // Roughness reporter only cares about true video frames.
    roughness_reporter_->FrameSubmitted(frame_token, *video_frame.get(),
                                        last_begin_frame_args_.interval);
  }
  auto compositor_frame = CreateCompositorFrame(
      frame_token, begin_frame_ack, std::move(video_frame), transform);

  WebVector<viz::ResourceId> resources;
  const auto& quad_list = compositor_frame.render_pass_list.back()->quad_list;
  if (!quad_list.empty()) {
    DCHECK_EQ(quad_list.size(), 1u);
    auto resource_id = quad_list.front()->resource_id;
    if (resource_id != viz::kInvalidResourceId) {
      resources.push_back(resource_id);
    }
  }

  WebVector<viz::TransferableResource> resource_list;
  resource_provider_->PrepareSendToParent(resources, &resource_list);
  compositor_frame.resource_list = resource_list.ReleaseVector();

  // We can pass nullptr for the HitTestData as the CompositorFram will not
  // contain any SurfaceDrawQuads.
  compositor_frame_sink_->SubmitCompositorFrame(
      child_local_surface_id_allocator_.GetCurrentLocalSurfaceId(),
      std::move(compositor_frame), std::nullopt, 0);
  resource_provider_->ReleaseFrameResources();

  NotifyOpacityIfNeeded(new_opacity);

  ++waiting_for_compositor_ack_;
  return true;
}

void VideoFrameSubmitter::SubmitEmptyFrame() {
  DCHECK_CALLED_ON_VALID_THREAD(thre
```