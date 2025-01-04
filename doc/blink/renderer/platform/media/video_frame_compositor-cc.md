Response: Let's break down the thought process to analyze the `VideoFrameCompositor.cc` file.

1. **Understand the Core Purpose:** The file name itself, `video_frame_compositor.cc`, strongly suggests its primary function: managing and composing video frames for rendering. The "compositor" part hints at potentially handling multiple sources or preparing frames for display.

2. **Identify Key Dependencies and Headers:**  Look at the `#include` directives. These reveal the fundamental components the class interacts with:
    * `<memory>`: For smart pointers (like `std::unique_ptr`, `scoped_refptr`).
    * `base/`:  This indicates usage of Chromium's base library, including threading (`SingleThreadTaskRunner`), time (`TimeTicks`, `TimeDelta`), synchronization (`WaitableEvent`, `AutoLock`), and callbacks (`BindRepeating`, `BindOnce`). The presence of `trace_event` suggests performance monitoring.
    * `components/viz/`:  Interaction with the Viz compositor, specifically `BeginFrameArgs` and `SurfaceId`, points to the class's role in the rendering pipeline.
    * `media/base/`:  The core media library is heavily used, as expected. Key classes like `VideoFrame` and `VideoRendererSink` are present.
    * `third_party/blink/public/platform/`: Interaction with Blink's platform abstraction layer, specifically `WebVideoFrameSubmitter`, signals that this class is bridging the gap between the media pipeline and the Blink rendering engine.

3. **Analyze the Class Structure and Members:** Examine the class declaration and its member variables:
    * `task_runner_`:  Confirms the class operates on a specific thread.
    * `submitter_`: A `WebVideoFrameSubmitter`, likely responsible for pushing the rendered frames to the compositor.
    * `callback_`: A `RenderCallback`, likely used to request new frames from the media pipeline.
    * `current_frame_`: Holds the most recently processed video frame.
    * Timers (`background_rendering_timer_`, `force_begin_frames_timer_`): Indicate scheduled actions for background rendering and forcing frame submissions.
    * Locks (`current_frame_lock_`, `callback_lock_`):  Suggest shared mutable state and the need for thread safety.
    * Callbacks (`new_processed_frame_cb_`, `new_presented_frame_cb_`): Indicate mechanisms for informing other parts of the system about frame processing and presentation.

4. **Scrutinize Key Methods:** Focus on the public and important private methods:
    * `EnableSubmission()`:  Connects the compositor to a specific rendering surface.
    * `UpdateCurrentFrame()`:  Triggers the process of obtaining and rendering a new frame.
    * `GetCurrentFrame()`:  Provides access to the currently held frame.
    * `Start()` and `Stop()`:  Control the frame processing lifecycle.
    * `PaintSingleFrame()`:  Allows rendering of a specific frame.
    * `BackgroundRender()`:  Manages background frame rendering.
    * `ProcessNewFrame()`:  The core logic for handling incoming video frames.
    * `SetIsSurfaceVisible()`, `SetIsPageVisible()`, `SetForceSubmit()`: Methods to influence the submission behavior based on external factors.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Think about how video rendering in a web browser works:
    * **HTML `<video>` element:** The starting point for embedding video. The `VideoFrameCompositor` is part of the underlying machinery that makes `<video>` work.
    * **JavaScript Media APIs:**  JavaScript uses APIs like `HTMLMediaElement` to control video playback. This class interacts with the media pipeline that those APIs control. Events like `requestVideoFrameCallback` are relevant.
    * **CSS transformations:** The `transform` parameter in `EnableSubmission()` suggests that CSS transformations applied to the `<video>` element need to be considered during frame composition.
    * **Canvas and WebGL:**  The `GetCurrentFrameOnAnyThread()` method and the handling of external consumers highlight the scenario where video frames are rendered on a canvas or using WebGL.

6. **Look for Logical Reasoning and Assumptions:**
    * **Background Rendering:** The timers and related logic strongly suggest an optimization where frames are rendered in the background to avoid jank or delays when the main rendering thread is busy. The timeout values (250ms) are a key assumption.
    * **Frame Dropping:** The code explicitly handles cases where frames might be dropped due to performance constraints or when in background rendering mode.
    * **Thread Safety:** The extensive use of locks indicates an awareness of multi-threading and the need to protect shared resources.

7. **Identify Potential Usage Errors:**
    * **Calling methods from the wrong thread:** The `DCHECK(task_runner_->BelongsToCurrentThread())` calls highlight this as a critical error.
    * **Incorrectly managing the `RenderCallback`:** The locking around `callback_` suggests that its lifecycle needs careful management by the calling code.
    * **Not handling `OnContextLost()`:** The code handles context loss by displaying a black frame. Developers need to be aware that GPU context loss can occur and that the video rendering might be temporarily interrupted.

8. **Structure the Analysis:**  Organize the findings into logical categories: Functionality, Relationship to Web Technologies, Logic and Assumptions, and Potential Errors. Use clear and concise language. Provide specific examples where possible.

9. **Refine and Review:** Read through the analysis to ensure accuracy, completeness, and clarity. Check for any logical inconsistencies or areas that could be explained better. For instance, initially, I might just say "handles video frames," but refining it to "manages the acquisition, processing, and submission of video frames to the rendering pipeline" is more precise. Similarly, simply stating "uses timers" isn't as informative as explaining the purpose of each timer (background rendering, forcing begin frames).

This iterative process of examining the code, understanding its context within the Chromium architecture, and connecting it to web technologies and potential pitfalls leads to a comprehensive analysis of the `VideoFrameCompositor.cc` file.
这个文件是 Chromium Blink 渲染引擎中的 `video_frame_compositor.cc`， 它的主要功能是**管理和合成视频帧，并将其提交到渲染流水线进行显示**。它充当了视频解码器输出的原始视频帧和最终在屏幕上渲染的帧之间的桥梁。

下面详细列举其功能，并解释与 JavaScript、HTML 和 CSS 的关系：

**功能列表:**

1. **接收和存储视频帧:**  从视频解码器或其他来源接收解码后的 `media::VideoFrame` 对象，并将其存储为当前帧 (`current_frame_`)。
2. **管理帧的生命周期:**  跟踪当前帧是否已经被渲染，以及何时应该更新为新的帧。
3. **帧合成和处理:**  虽然文件名包含 "compositor"，但在这个文件中，主要的合成逻辑可能委托给了 `WebVideoFrameSubmitter`。`VideoFrameCompositor` 更多地负责**选择和准备**要提交的帧。
4. **与渲染管道交互:**  通过 `WebVideoFrameSubmitter` 将准备好的视频帧提交到 Chromium 的合成器（Compositor），以便最终在屏幕上渲染。
5. **处理渲染回调:**  接收来自渲染管道的渲染回调，例如 `UpdateCurrentFrame()`，以触发新的帧的获取和提交。
6. **后台渲染:**  为了保持渲染的流畅性，即使在没有立即需要新帧的情况下，也会定期进行后台渲染 (`BackgroundRender()`)。
7. **处理页面可见性变化:**  当页面可见性改变时 (`SetIsPageVisible()`)，通知 `WebVideoFrameSubmitter`，这可能会影响帧的提交策略。
8. **处理强制提交:**  允许强制提交帧 (`SetForceSubmit()`)，这在某些场景下很有用，例如，确保在视频播放开始时立即显示第一帧。
9. **提供帧元数据:**  提供关于最近渲染的帧的元数据，例如呈现时间、预期显示时间、帧率等 (`GetLastPresentedFrameMetadata()`)。
10. **处理上下文丢失:** 当 GPU 上下文丢失时 (`OnContextLost()`)，会切换到渲染黑帧。
11. **同步:** 使用锁 (`current_frame_lock_`, `callback_lock_`) 来保护对共享状态的访问，确保线程安全。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`VideoFrameCompositor` 本身不直接处理 JavaScript, HTML 或 CSS。它位于渲染引擎的较低层，负责处理视频帧的底层操作。然而，它的功能对于在 Web 页面上正确显示视频至关重要，因此与这三种技术存在间接但重要的关系。

* **HTML (`<video>` 元素):**
    * **功能关系:**  当 HTML 中包含 `<video>` 元素并且开始播放时，Blink 渲染引擎会创建一个媒体播放器对象，该对象最终会使用 `VideoFrameCompositor` 来管理视频帧的渲染。
    * **举例说明:**  当浏览器解析到 `<video src="myvideo.mp4"></video>` 时，用户点击播放按钮，视频解码开始，解码后的帧会被传递到 `VideoFrameCompositor` 进行处理和提交渲染。

* **JavaScript (Media APIs, Canvas, WebGL):**
    * **功能关系:**
        * **Media APIs (如 `HTMLMediaElement`):** JavaScript 通过 `HTMLMediaElement` 接口控制视频的播放、暂停、seek 等操作。这些操作会间接影响 `VideoFrameCompositor` 的行为，例如，seek 操作可能导致需要立即渲染一个新的帧。
        * **Canvas 和 WebGL:**  JavaScript 可以使用 Canvas 或 WebGL 来绘制视频帧。`VideoFrameCompositor` 提供了 `GetCurrentFrameOnAnyThread()` 方法，允许在其他线程上安全地获取当前帧的数据，以便在 Canvas 或 WebGL 上进行渲染。
    * **举例说明:**
        * **Media APIs:**  JavaScript 代码 `videoElement.play()` 会启动视频播放，导致 `VideoFrameCompositor` 开始接收和提交帧。
        * **Canvas:**  JavaScript 代码可以获取视频的当前帧并在 Canvas 上绘制：
          ```javascript
          const video = document.getElementById('myVideo');
          const canvas = document.getElementById('myCanvas');
          const ctx = canvas.getContext('2d');

          function drawFrame() {
            requestAnimationFrame(drawFrame);
            const frame = video.requestVideoFrameCallback(); // 这可能需要通过其他机制获取帧数据，但概念类似
            ctx.drawImage(frame, 0, 0);
          }
          drawFrame();
          ```
        * **WebGL:**  类似地，WebGL 可以使用视频帧作为纹理进行渲染。

* **CSS (视频元素的样式和变换):**
    * **功能关系:**  CSS 可以用于设置 `<video>` 元素的样式，例如大小、位置、旋转等。`VideoFrameCompositor` 在提交帧进行渲染时，需要考虑这些 CSS 变换，以确保视频在屏幕上以正确的样式显示。`EnableSubmission()` 方法中的 `media::VideoTransformation transform` 参数就体现了这一点。
    * **举例说明:**  如果 CSS 设置了 `video { transform: rotate(45deg); }`，那么 `VideoFrameCompositor` 提交的帧需要经过相应的旋转变换，才能在屏幕上正确显示旋转后的视频。

**逻辑推理的假设输入与输出:**

假设输入：

1. **新的解码后的视频帧:**  `scoped_refptr<media::VideoFrame> frame`。
2. **渲染回调触发:**  来自 Compositor 的 `UpdateCurrentFrame(deadline_min, deadline_max)` 调用。
3. **页面变为可见:**  调用 `SetIsPageVisible(true)`。

假设输出：

1. **新帧被存储:**  `current_frame_` 更新为新的 `frame`。
2. **帧被提交渲染:**  `WebVideoFrameSubmitter::SubmitFrame()` 被调用，将 `current_frame_` 提交到 Compositor。
3. **开始正常渲染:**  当页面变为可见时，`WebVideoFrameSubmitter` 会收到通知，并可能调整帧的提交策略，开始积极渲染帧。

**用户或编程常见的使用错误举例说明:**

1. **在错误的线程上调用方法:**  `VideoFrameCompositor` 的许多方法都必须在特定的线程（通常是 Compositor 线程）上调用。如果在错误的线程上调用，会导致 `DCHECK` 失败并可能引发崩溃。
   * **错误示例:**  在非 Compositor 线程上直接调用 `UpdateCurrentFrame()`。

2. **不正确地管理 `RenderCallback` 的生命周期:**  `RenderCallback` 用于从媒体管道获取新的视频帧。如果 `RenderCallback` 在 `VideoFrameCompositor` 仍然需要它的时候被销毁，会导致程序崩溃或无法正常渲染视频。
   * **错误示例:**  过早地释放传递给 `Start()` 方法的 `RenderCallback` 对象。

3. **假设 `GetCurrentFrame()` 返回的帧始终有效:**  获取到的 `VideoFrame` 对象可能在其生命周期结束时变为无效。用户代码需要注意管理 `scoped_refptr`，避免在帧被释放后继续访问。
   * **错误示例:**  在另一个线程上长时间持有 `GetCurrentFrame()` 返回的 `VideoFrame`，而原始的 `VideoFrame` 已经被释放。

4. **忽略 `OnContextLost()` 事件的影响:**  当 GPU 上下文丢失时，之前渲染的纹理可能失效。如果用户代码没有处理这种情况，可能会导致渲染错误或崩溃。
   * **错误示例:**  在 `OnContextLost()` 发生后，仍然尝试使用之前渲染的视频帧纹理。

总而言之，`VideoFrameCompositor` 是 Blink 渲染引擎中一个核心的视频处理组件，它隐藏了许多复杂的底层操作，确保视频帧能够高效、正确地渲染到屏幕上。虽然开发者通常不需要直接与此类交互，但理解其功能有助于理解 Web 浏览器如何处理视频内容，并可以帮助诊断与视频渲染相关的问题。

Prompt: 
```
这是目录为blink/renderer/platform/media/video_frame_compositor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/platform/media/video_frame_compositor.h"

#include <memory>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/bind_post_task.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "media/base/media_switches.h"
#include "media/base/video_frame.h"
#include "third_party/blink/public/platform/web_video_frame_submitter.h"

namespace blink {

using RenderingMode = ::media::VideoRendererSink::RenderCallback::RenderingMode;

// Amount of time to wait between UpdateCurrentFrame() callbacks before starting
// background rendering to keep the Render() callbacks moving.
const int kBackgroundRenderingTimeoutMs = 250;
const int kForceBeginFramesTimeoutMs = 1000;

// static
constexpr const char VideoFrameCompositor::kTracingCategory[];

VideoFrameCompositor::VideoFrameCompositor(
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
    std::unique_ptr<WebVideoFrameSubmitter> submitter)
    : task_runner_(task_runner),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      background_rendering_timer_(
          FROM_HERE,
          base::Milliseconds(kBackgroundRenderingTimeoutMs),
          base::BindRepeating(&VideoFrameCompositor::BackgroundRender,
                              base::Unretained(this),
                              RenderingMode::kBackground)),
      force_begin_frames_timer_(
          FROM_HERE,
          base::Milliseconds(kForceBeginFramesTimeoutMs),
          base::BindRepeating(&VideoFrameCompositor::StopForceBeginFrames,
                              base::Unretained(this))),
      submitter_(std::move(submitter)) {
  if (submitter_) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&VideoFrameCompositor::InitializeSubmitter,
                                  weak_ptr_factory_.GetWeakPtr()));
    update_submission_state_callback_ = base::BindPostTask(
        task_runner_,
        base::BindRepeating(&VideoFrameCompositor::SetIsSurfaceVisible,
                            weak_ptr_factory_.GetWeakPtr()));
  }
}

cc::UpdateSubmissionStateCB
VideoFrameCompositor::GetUpdateSubmissionStateCallback() {
  return update_submission_state_callback_;
}

void VideoFrameCompositor::SetIsSurfaceVisible(
    bool is_visible,
    base::WaitableEvent* done_event) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  submitter_->SetIsSurfaceVisible(is_visible);
  if (done_event)
    done_event->Signal();
}

void VideoFrameCompositor::InitializeSubmitter() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  submitter_->Initialize(this, /* is_media_stream = */ false);
}

VideoFrameCompositor::~VideoFrameCompositor() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(!callback_);
  DCHECK(!rendering_);
  if (client_)
    client_->StopUsingProvider();
}

void VideoFrameCompositor::EnableSubmission(
    const viz::SurfaceId& id,
    media::VideoTransformation transform,
    bool force_submit) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  // If we're switching to |submitter_| from some other client, then tell it.
  if (client_ && client_ != submitter_.get())
    client_->StopUsingProvider();

  submitter_->SetTransform(transform);
  submitter_->SetForceSubmit(force_submit);
  submitter_->EnableSubmission(id);
  client_ = submitter_.get();
  if (rendering_)
    client_->StartRendering();
}

bool VideoFrameCompositor::IsClientSinkAvailable() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  return client_;
}

void VideoFrameCompositor::OnRendererStateUpdate(bool new_state) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK_NE(rendering_, new_state);
  rendering_ = new_state;

  if (!auto_open_close_) {
    auto_open_close_ = std::make_unique<
        base::trace_event::AutoOpenCloseEvent<kTracingCategory>>(
        base::trace_event::AutoOpenCloseEvent<kTracingCategory>::Type::kAsync,
        "VideoPlayback");
  }

  if (rendering_) {
    auto_open_close_->Begin();
  } else {
    new_processed_frame_cb_.Reset();
    auto_open_close_->End();
  }

  if (rendering_) {
    // Always start playback in background rendering mode, if |client_| kicks
    // in right away it's okay.
    BackgroundRender(RenderingMode::kStartup);
  } else if (background_rendering_enabled_) {
    background_rendering_timer_.Stop();
  } else {
    DCHECK(!background_rendering_timer_.IsRunning());
  }

  if (!IsClientSinkAvailable())
    return;

  if (rendering_)
    client_->StartRendering();
  else
    client_->StopRendering();
}

void VideoFrameCompositor::SetVideoFrameProviderClient(
    cc::VideoFrameProvider::Client* client) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (client_)
    client_->StopUsingProvider();
  client_ = client;

  // |client_| may now be null, so verify before calling it.
  if (rendering_ && client_)
    client_->StartRendering();
}

scoped_refptr<media::VideoFrame> VideoFrameCompositor::GetCurrentFrame() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  return current_frame_;
}

scoped_refptr<media::VideoFrame>
VideoFrameCompositor::GetCurrentFrameOnAnyThread() {
  base::AutoLock lock(current_frame_lock_);

  // Treat frames vended to external consumers as being rendered. This ensures
  // that hidden elements that are being driven by WebGL/WebGPU/Canvas rendering
  // don't mark all frames as dropped.
  rendered_last_frame_ = true;

  return current_frame_;
}

void VideoFrameCompositor::SetCurrentFrame_Locked(
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks expected_display_time) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_EVENT1("media", "VideoFrameCompositor::SetCurrentFrame", "frame",
               frame->AsHumanReadableString());
  current_frame_lock_.AssertAcquired();
  current_frame_ = std::move(frame);
  last_presentation_time_ = tick_clock_->NowTicks();
  last_expected_display_time_ = expected_display_time;
  ++presentation_counter_;
}

void VideoFrameCompositor::PutCurrentFrame() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  base::AutoLock lock(current_frame_lock_);
  rendered_last_frame_ = true;
}

bool VideoFrameCompositor::UpdateCurrentFrame(base::TimeTicks deadline_min,
                                              base::TimeTicks deadline_max) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_EVENT2("media", "VideoFrameCompositor::UpdateCurrentFrame",
               "deadline_min", deadline_min, "deadline_max", deadline_max);
  return CallRender(deadline_min, deadline_max, RenderingMode::kNormal);
}

bool VideoFrameCompositor::HasCurrentFrame() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  return static_cast<bool>(GetCurrentFrame());
}

base::TimeDelta VideoFrameCompositor::GetPreferredRenderInterval() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  base::AutoLock lock(callback_lock_);

  if (!callback_)
    return viz::BeginFrameArgs::MinInterval();
  return callback_->GetPreferredRenderInterval();
}

void VideoFrameCompositor::Start(RenderCallback* callback) {
  // Called from the media thread, so acquire the callback under lock before
  // returning in case a Stop() call comes in before the PostTask is processed.
  base::AutoLock lock(callback_lock_);
  DCHECK(!callback_);
  callback_ = callback;
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&VideoFrameCompositor::OnRendererStateUpdate,
                                weak_ptr_factory_.GetWeakPtr(), true));
}

void VideoFrameCompositor::Stop() {
  // Called from the media thread, so release the callback under lock before
  // returning to avoid a pending UpdateCurrentFrame() call occurring before
  // the PostTask is processed.
  base::AutoLock lock(callback_lock_);
  DCHECK(callback_);
  callback_ = nullptr;
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&VideoFrameCompositor::OnRendererStateUpdate,
                                weak_ptr_factory_.GetWeakPtr(), false));
}

void VideoFrameCompositor::PaintSingleFrame(
    scoped_refptr<media::VideoFrame> frame,
    bool repaint_duplicate_frame) {
  if (!task_runner_->BelongsToCurrentThread()) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&VideoFrameCompositor::PaintSingleFrame,
                                  weak_ptr_factory_.GetWeakPtr(),
                                  std::move(frame), repaint_duplicate_frame));
    return;
  }
  if (ProcessNewFrame(std::move(frame), tick_clock_->NowTicks(),
                      repaint_duplicate_frame) &&
      IsClientSinkAvailable()) {
    client_->DidReceiveFrame();
  }
}

void VideoFrameCompositor::UpdateCurrentFrameIfStale(UpdateType type) {
  TRACE_EVENT0("media", "VideoFrameCompositor::UpdateCurrentFrameIfStale");
  DCHECK(task_runner_->BelongsToCurrentThread());

  // If we're not rendering, then the frame can't be stale.
  if (!rendering_ || !is_background_rendering_)
    return;

  // If we have a client, and it is currently rendering, then it's not stale
  // since the client is driving the frame updates at the proper rate.
  if (type != UpdateType::kBypassClient && IsClientSinkAvailable() &&
      client_->IsDrivingFrameUpdates()) {
    return;
  }

  // We're rendering, but the client isn't driving the updates.  See if the
  // frame is stale, and update it.

  DCHECK(!last_background_render_.is_null());

  const base::TimeTicks now = tick_clock_->NowTicks();
  const base::TimeDelta interval = now - last_background_render_;

  // Cap updates to 250Hz which should be more than enough for everyone.
  if (interval < base::Milliseconds(4))
    return;

  {
    base::AutoLock lock(callback_lock_);
    // Update the interval based on the time between calls and call background
    // render which will give this information to the client.
    last_interval_ = interval;
  }
  BackgroundRender();
}

void VideoFrameCompositor::SetOnNewProcessedFrameCallback(
    OnNewProcessedFrameCB cb) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  new_processed_frame_cb_ = std::move(cb);
}

void VideoFrameCompositor::SetOnFramePresentedCallback(
    OnNewFramePresentedCB present_cb) {
  base::AutoLock lock(current_frame_lock_);
  new_presented_frame_cb_ = std::move(present_cb);

  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&VideoFrameCompositor::StartForceBeginFrames,
                                weak_ptr_factory_.GetWeakPtr()));
}

void VideoFrameCompositor::StartForceBeginFrames() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (!submitter_)
    return;

  submitter_->SetForceBeginFrames(true);
  force_begin_frames_timer_.Reset();
}

void VideoFrameCompositor::StopForceBeginFrames() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  submitter_->SetForceBeginFrames(false);
}

std::unique_ptr<WebMediaPlayer::VideoFramePresentationMetadata>
VideoFrameCompositor::GetLastPresentedFrameMetadata() {
  auto frame_metadata =
      std::make_unique<WebMediaPlayer::VideoFramePresentationMetadata>();

  scoped_refptr<media::VideoFrame> last_frame;
  {
    // Manually acquire the lock instead of calling GetCurrentFrameOnAnyThread()
    // to also fetch the other frame dependent properties.
    base::AutoLock lock(current_frame_lock_);
    last_frame = current_frame_;
    frame_metadata->presentation_time = last_presentation_time_;
    frame_metadata->expected_display_time = last_expected_display_time_;
    frame_metadata->presented_frames = presentation_counter_;
  }

  if (last_frame) {
    frame_metadata->width = last_frame->visible_rect().width();
    frame_metadata->height = last_frame->visible_rect().height();
    frame_metadata->media_time = last_frame->timestamp();
    frame_metadata->metadata.MergeMetadataFrom(last_frame->metadata());
  }

  {
    base::AutoLock lock(callback_lock_);
    if (callback_) {
      frame_metadata->average_frame_duration =
          callback_->GetPreferredRenderInterval();
    } else if (last_frame && last_frame->metadata().frame_duration) {
      frame_metadata->average_frame_duration =
          *last_frame->metadata().frame_duration;
    }
    frame_metadata->rendering_interval = last_interval_;
  }

  return frame_metadata;
}

bool VideoFrameCompositor::ProcessNewFrame(
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks presentation_time,
    bool repaint_duplicate_frame) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  if (!frame || (GetCurrentFrame() && !repaint_duplicate_frame &&
                 frame->unique_id() == GetCurrentFrame()->unique_id())) {
    return false;
  }

  // TODO(crbug.com/1447318): Add other cases where the frame is not readable.
  bool is_frame_readable = !frame->metadata().dcomp_surface;

  // Copy to a local variable to avoid potential deadlock when executing the
  // callback.
  OnNewFramePresentedCB frame_presented_cb;
  {
    base::AutoLock lock(current_frame_lock_);

    // Set the flag indicating that the current frame is unrendered, if we get a
    // subsequent PutCurrentFrame() call it will mark it as rendered.
    rendered_last_frame_ = false;

    SetCurrentFrame_Locked(std::move(frame), presentation_time);
    frame_presented_cb = std::move(new_presented_frame_cb_);
  }

  if (new_processed_frame_cb_) {
    std::move(new_processed_frame_cb_)
        .Run(tick_clock_->NowTicks(), is_frame_readable);
  }

  if (frame_presented_cb) {
    std::move(frame_presented_cb).Run();
  }

  return true;
}

void VideoFrameCompositor::SetIsPageVisible(bool is_visible) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  if (submitter_)
    submitter_->SetIsPageVisible(is_visible);
}

void VideoFrameCompositor::SetForceSubmit(bool force_submit) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  // The `submitter_` can be null in tests.
  if (submitter_)
    submitter_->SetForceSubmit(force_submit);
}

base::TimeDelta VideoFrameCompositor::GetLastIntervalWithoutLock()
    NO_THREAD_SAFETY_ANALYSIS {
  DCHECK(task_runner_->BelongsToCurrentThread());
  // |last_interval_| is only updated on the compositor thread, so it's safe to
  // return it without acquiring |callback_lock_|
  return last_interval_;
}

void VideoFrameCompositor::BackgroundRender(RenderingMode mode) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  const base::TimeTicks now = tick_clock_->NowTicks();
  last_background_render_ = now;
  bool new_frame = CallRender(now, now + GetLastIntervalWithoutLock(), mode);
  if (new_frame && IsClientSinkAvailable())
    client_->DidReceiveFrame();
}

bool VideoFrameCompositor::CallRender(base::TimeTicks deadline_min,
                                      base::TimeTicks deadline_max,
                                      RenderingMode mode) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  bool have_unseen_frame;
  {
    base::AutoLock lock(current_frame_lock_);
    have_unseen_frame = !rendered_last_frame_ && HasCurrentFrame();
  }

  base::AutoLock lock(callback_lock_);

  if (!callback_) {
    // Even if we no longer have a callback, return true if we have a frame
    // which |client_| hasn't seen before.
    return have_unseen_frame;
  }

  DCHECK(rendering_);

  // If the previous frame was never rendered and we're in the normal rendering
  // mode and haven't just exited background rendering, let the client know.
  //
  // We don't signal for mode == kBackground since we expect to drop frames. We
  // also don't signal for mode == kStartup since UpdateCurrentFrame() may occur
  // before the PutCurrentFrame() for the kStartup induced CallRender().
  const bool was_background_rendering = is_background_rendering_;
  if (have_unseen_frame && mode == RenderingMode::kNormal &&
      !was_background_rendering) {
    callback_->OnFrameDropped();
  }

  const bool new_frame = ProcessNewFrame(
      callback_->Render(deadline_min, deadline_max, mode), deadline_min, false);

  // In cases where mode == kStartup we still want to treat it like background
  // rendering mode since CallRender() wasn't generated by UpdateCurrentFrame().
  is_background_rendering_ = mode != RenderingMode::kNormal;
  last_interval_ = deadline_max - deadline_min;

  // We may create a new frame here with background rendering, but the provider
  // has no way of knowing that a new frame had been processed, so keep track of
  // the new frame, and return true on the next call to |CallRender|.
  const bool had_new_background_frame = new_background_frame_;
  new_background_frame_ = is_background_rendering_ && new_frame;

  // Restart the background rendering timer whether we're background rendering
  // or not; in either case we should wait for |kBackgroundRenderingTimeoutMs|.
  if (background_rendering_enabled_)
    background_rendering_timer_.Reset();
  return new_frame || had_new_background_frame;
}

void VideoFrameCompositor::OnContextLost() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  // current_frame_'s resource in the context has been lost, so current_frame_
  // is not valid any more. current_frame_ should be reset. Now the compositor
  // has no concept of resetting current_frame_, so a black frame is set.
  base::AutoLock lock(current_frame_lock_);
  if (!current_frame_ || (!current_frame_->HasSharedImage() &&
                          !current_frame_->HasMappableGpuBuffer())) {
    return;
  }
  scoped_refptr<media::VideoFrame> black_frame =
      media::VideoFrame::CreateBlackFrame(current_frame_->natural_size());
  SetCurrentFrame_Locked(std::move(black_frame), tick_clock_->NowTicks());
}

}  // namespace blink

"""

```