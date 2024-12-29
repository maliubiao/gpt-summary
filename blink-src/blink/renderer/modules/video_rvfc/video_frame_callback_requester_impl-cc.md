Response:
Let's break down the thought process to analyze the `VideoFrameCallbackRequesterImpl.cc` file.

1. **Understand the Goal:** The primary goal is to understand the *purpose* and *functionality* of this specific Chromium Blink file. We need to connect it to web technologies (JavaScript, HTML, CSS) if possible, explore potential use cases, identify potential errors, and understand how a user's actions might lead to this code being executed.

2. **Initial Code Scan (Keywords and Structure):**  Start by skimming the code for important keywords and structural elements:

    * `#include`:  This tells us about dependencies. Look for familiar Blink/Chromium terms like `HTMLVideoElement`, `Document`, `ScriptedAnimationController`, `Performance`, `XRSystem`, and bindings-related headers. The presence of `third_party/blink` confirms this is indeed Blink code.
    * `namespace blink`: Confirms the Blink namespace.
    * Class definition: `VideoFrameCallbackRequesterImpl`. The "Impl" suffix often suggests this is a concrete implementation of an interface (likely `VideoFrameCallbackRequester`).
    * Methods: `requestVideoFrameCallback`, `cancelVideoFrameCallback`, `OnWebMediaPlayerCreated`, `OnWebMediaPlayerCleared`, `ScheduleWindowRaf`, `ScheduleExecution`, `OnImmersiveSessionStart`, `OnImmersiveSessionEnd`, `OnImmersiveFrame`, `ExecuteVideoFrameCallbacks`, `OnExecution`. These are the core actions the class performs.
    * Members: `callback_collection_`, `weak_factory_`, `pending_execution_`, `in_immersive_session_`, `observing_immersive_session_`, `last_presented_frames_`, `consecutive_stale_frames_`, `cross_origin_isolated_capability_`. These are the internal state variables.
    * Static methods: `From`, `requestVideoFrameCallback`, `cancelVideoFrameCallback`, `GetClampedTimeInMillis`, `GetCoarseClampedTimeInSeconds`. These suggest utility or entry point functions.
    * Trace events: `TRACE_EVENT*`. This indicates logging/debugging capabilities.

3. **Infer Core Functionality from Method Names:**  Based on the names, try to deduce the main purpose of each method:

    * `requestVideoFrameCallback`:  Likely registers a callback function to be executed when a new video frame is available. This strongly suggests a mechanism for synchronizing script execution with video rendering.
    * `cancelVideoFrameCallback`: Unregisters a previously registered callback.
    * `OnWebMediaPlayerCreated`/`OnWebMediaPlayerCleared`:  These seem to manage the lifecycle of the underlying video player.
    * `ScheduleWindowRaf`:  "RAF" often stands for "RequestAnimationFrame". This hints at integrating with the browser's rendering pipeline.
    * `ScheduleExecution`:  A higher-level function that decides how to schedule the callback execution.
    * `OnImmersiveSessionStart`/`OnImmersiveSessionEnd`/`OnImmersiveFrame`:  Clearly related to WebXR (Virtual/Augmented Reality).
    * `ExecuteVideoFrameCallbacks`: Actually calls the registered JavaScript callbacks, providing frame metadata.
    * `OnExecution`: The core logic triggered by the scheduler, deciding if a new frame is available and executing callbacks.

4. **Analyze Member Variables:** Understand the state managed by the class:

    * `callback_collection_`:  Holds the list of registered callbacks.
    * `weak_factory_`:  Used for managing weak pointers, likely to avoid dangling pointers when objects are destroyed.
    * `pending_execution_`:  A flag to prevent redundant scheduling.
    * `in_immersive_session_`/`observing_immersive_session_`: Track the state of WebXR sessions.
    * `last_presented_frames_`/`consecutive_stale_frames_`: Used to detect if a new video frame has been presented. This is crucial for avoiding unnecessary callback executions.
    * `cross_origin_isolated_capability_`: Relates to security and timing precision.

5. **Connect to Web Technologies:**  Now, connect the dots to JavaScript, HTML, and CSS:

    * **JavaScript:** The `requestVideoFrameCallback` method directly corresponds to the JavaScript API of the same name on the `HTMLVideoElement`. The callbacks registered here are JavaScript functions. The metadata passed to the callbacks (`VideoFrameCallbackMetadata`) is exposed to JavaScript.
    * **HTML:**  This code operates on `HTMLVideoElement`. The user interacts with the `<video>` tag in HTML.
    * **CSS:** While not directly interacting, CSS styling can affect the rendering and visibility of the `<video>` element, which indirectly influences when frames are rendered and thus when callbacks might be triggered.

6. **Logical Reasoning and Examples:**  Think about scenarios and provide concrete examples:

    * **Scenario:** A game using `<video>` as a texture source. The `requestVideoFrameCallback` is used to update the game scene whenever a new video frame arrives.
    * **Input/Output:**  Imagine a video playing at 30fps. The input is the browser's rendering loop triggering `OnExecution`. The output is the JavaScript callback being invoked with metadata about the latest frame.
    * **Error:**  Forgetting to `cancelVideoFrameCallback` can lead to memory leaks or unexpected behavior if the video element is removed but the callbacks are still registered.

7. **User Actions and Debugging:** Trace the path from user interaction to this code:

    * The user loads an HTML page containing a `<video>` element.
    * JavaScript code on the page calls `videoElement.requestVideoFrameCallback(...)`.
    * The browser's rendering engine (Blink) eventually creates a `VideoFrameCallbackRequesterImpl` instance associated with the video element.
    * When the video player has a new frame available, it signals the `VideoFrameCallbackRequesterImpl`.
    * The logic in this file schedules and executes the registered JavaScript callbacks.

8. **Refine and Organize:** Structure the analysis clearly, using headings and bullet points to make it easy to read and understand. Explain the technical terms used.

9. **Self-Correction/Review:**  Read through the analysis. Are there any inconsistencies?  Are the explanations clear?  Have all parts of the request been addressed? For instance, initially, I might focus too much on the XR aspects. A review would highlight the need to equally emphasize the core video frame callback mechanism. Also, double-check the relationship between the C++ code and the JavaScript API.

By following these steps, we can systematically analyze the code and generate a comprehensive explanation of its functionality and context. The key is to move from a high-level understanding to a more detailed examination of the code's structure and logic, and finally, to connect it back to the user's experience and common web development practices.
好的，这是对 `blink/renderer/modules/video_rvfc/video_frame_callback_requester_impl.cc` 文件的功能进行分析：

**主要功能：**

该文件的核心功能是实现 `VideoFrameCallbackRequesterImpl` 类，这个类负责管理和执行视频帧回调（Video Frame Callbacks），允许 JavaScript 代码在视频帧准备好进行渲染时得到通知。这为开发者提供了在视频的渲染管道中同步执行 JavaScript 代码的能力，常用于实现自定义的视频处理、动画同步、以及与 WebXR 等技术的集成。

**功能拆解：**

1. **注册和取消回调:**
   - `requestVideoFrameCallback(HTMLVideoElement& element, V8VideoFrameRequestCallback* callback)`:  静态方法，用于为指定的 `HTMLVideoElement` 注册一个 JavaScript 回调函数 (`V8VideoFrameRequestCallback`)。每当新的视频帧准备好时，这个回调函数将被调用。
   - `cancelVideoFrameCallback(HTMLVideoElement& element, int callback_id)`: 静态方法，用于取消之前注册的具有特定 `callback_id` 的回调函数。

2. **生命周期管理:**
   - `OnWebMediaPlayerCreated()`: 当底层的 WebMediaPlayer 对象被创建时调用。如果存在待处理的回调，则会请求视频帧回调。
   - `OnWebMediaPlayerCleared()`: 当底层的 WebMediaPlayer 对象被清除时调用。会清理与之前的媒体相关的状态，例如取消待执行的回调，重置帧计数器等。

3. **回调调度:**
   - `ScheduleWindowRaf()`:  使用浏览器的 requestAnimationFrame 机制来调度回调的执行。这确保了回调会在浏览器的渲染循环中执行，以实现同步。
   - `ScheduleExecution()`:  负责决定如何调度回调的执行。它会检查是否正在进行沉浸式 WebXR 会话，如果是，则尝试使用 WebXR 的机制进行调度；否则，使用 `ScheduleWindowRaf()`。
   - `TryScheduleImmersiveXRSessionRaf()`:  尝试利用 WebXR 的机制来调度视频帧回调，以实现与 XR 内容的同步渲染。
   - `OnImmersiveSessionStart()`: 当进入沉浸式 WebXR 会话时调用，会尝试使用 WebXR 机制调度回调。
   - `OnImmersiveSessionEnd()`: 当退出沉浸式 WebXR 会话时调用，会切换回使用浏览器的 requestAnimationFrame 机制调度回调。

4. **回调执行:**
   - `OnRequestVideoFrameCallback()`: 当底层 WebMediaPlayer 通知有新的视频帧准备好时调用。它会触发 `ScheduleExecution()` 来安排回调的执行。
   - `ExecuteVideoFrameCallbacks(double high_res_now_ms, std::unique_ptr<WebMediaPlayer::VideoFramePresentationMetadata> frame_metadata)`: 实际执行已注册的 JavaScript 回调函数。它会创建 `VideoFrameCallbackMetadata` 对象，包含关于当前视频帧的信息（例如，显示时间、帧率、时间戳等），并传递给回调函数。
   - `OnExecution(double high_res_now_ms)`:  在渲染步骤中被调用，负责检查是否有新的视频帧，并决定是否执行回调。它会比较上次呈现的帧数和当前帧数，以避免在没有新帧时执行回调。

5. **WebXR 集成:**
   - 文件中包含对 WebXR API 的引用（例如 `XRFrameProvider`, `XRSession`, `XRSystem`），表明该功能可以与 WebXR 内容进行集成，允许在沉浸式 XR 环境中同步视频渲染和 JavaScript 代码执行。
   - `OnImmersiveFrame()`: 当处于沉浸式会话中时，每当 XR 设备准备好新帧时调用，用于更新可能过时的视频帧。

6. **性能优化:**
   - 使用 `requestAnimationFrame` 可以避免不必要的渲染和回调执行，提高性能。
   - 检查帧是否更新 (`last_presented_frames_`) 可以避免在视频暂停或没有新帧时触发回调。
   - 对于高帧率视频，会更频繁地调度回调，以确保 JavaScript 代码能及时处理每一帧。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** 该文件直接暴露了 JavaScript API `requestVideoFrameCallback` 和 `cancelVideoFrameCallback` 给开发者使用。开发者可以通过 JavaScript 调用这些方法来注册和取消回调函数。当视频帧准备好时，注册的 JavaScript 函数会被调用，并接收包含帧信息的 `VideoFrameCallbackMetadata` 对象。

   **举例说明:**

   ```javascript
   const video = document.querySelector('video');

   function onVideoFrame(now, metadata) {
     console.log('New video frame available at:', metadata.presentationTime);
     // 在这里可以进行基于视频帧的处理，例如绘制到 Canvas
     video.requestVideoFrameCallback(onVideoFrame); // 注册下一个回调
   }

   video.requestVideoFrameCallback(onVideoFrame);
   ```

* **HTML:** 该功能是针对 HTML 的 `<video>` 元素实现的。开发者需要在 HTML 中嵌入 `<video>` 标签才能使用此功能。

   **举例说明:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <title>Video Frame Callback Example</title>
   </head>
   <body>
     <video id="myVideo" src="my-video.mp4" controls></video>
     <script src="script.js"></script>
   </body>
   </html>
   ```

* **CSS:** CSS 可以用来控制 `<video>` 元素的样式和布局，但 `VideoFrameCallbackRequesterImpl` 的核心功能与 CSS 的行为没有直接的逻辑关系。CSS 的更改可能会影响视频的渲染方式，但不会直接影响回调的触发和执行机制。

**逻辑推理、假设输入与输出：**

**假设输入：**

1. 用户加载包含 `<video>` 元素的网页。
2. JavaScript 代码调用 `videoElement.requestVideoFrameCallback(callback)` 来注册一个回调函数。
3. 视频开始播放并且新的视频帧被解码和准备好进行渲染。

**逻辑推理过程：**

1. 底层的 WebMediaPlayer 通知 `VideoFrameCallbackRequesterImpl` 有新的帧可用。
2. `OnRequestVideoFrameCallback()` 被调用。
3. `ScheduleExecution()` 被调用，根据当前状态（是否在 WebXR 会话中）决定调度方式。
4. 如果不在 WebXR 会话中，`ScheduleWindowRaf()` 被调用，将回调放入浏览器的 requestAnimationFrame 队列。
5. 在浏览器的下一次渲染循环中，`OnExecution()` 被调用。
6. `OnExecution()` 检查 `last_presented_frames_` 与当前帧的 `presented_frames` 是否一致。
7. 如果帧数不同（表示是新帧），则 `ExecuteVideoFrameCallbacks()` 被调用。
8. `ExecuteVideoFrameCallbacks()` 创建包含帧元数据的 `VideoFrameCallbackMetadata` 对象。
9. 注册的 JavaScript 回调函数 (`callback`) 被调用，并接收当前高精度时间戳和帧元数据对象作为参数。

**输出：**

注册的 JavaScript 回调函数被调用，并接收包含当前视频帧信息的 `metadata` 对象。开发者可以在回调函数中访问这些信息，例如 `metadata.presentationTime`。

**用户或编程常见的使用错误：**

1. **忘记取消回调：** 如果注册了 `requestVideoFrameCallback` 但没有在不需要时调用 `cancelVideoFrameCallback`，即使视频停止播放或元素被移除，回调函数仍然可能被执行，导致资源浪费或意外行为。

   **举例：**

   ```javascript
   let callbackId;

   video.onplay = () => {
     callbackId = video.requestVideoFrameCallback(onVideoFrame);
   };

   video.onended = () => {
     // 错误：忘记取消回调
     // video.cancelVideoFrameCallback(callbackId);
   };
   ```

2. **在回调函数中执行耗时操作：** `requestVideoFrameCallback` 的目的是与视频渲染同步执行轻量级的操作。如果在回调函数中执行过于耗时的操作，可能会导致视频卡顿或掉帧。

   **举例：**

   ```javascript
   function onVideoFrame(now, metadata) {
     // 错误：执行了耗时的同步操作
     for (let i = 0; i < 1000000; i++) {
       // ... 一些计算 ...
     }
     video.requestVideoFrameCallback(onVideoFrame);
   }
   ```

3. **不理解回调执行的时机：** 开发者可能会误以为回调会在视频帧 *解码完成* 后立即执行，但实际上它是在视频帧 *准备好进行渲染* 时执行的。这可能导致在处理解码后的帧数据时出现时序问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户加载包含 `<video>` 标签的网页。** 这是最开始的触发点。浏览器会解析 HTML 并创建对应的 DOM 元素。
2. **JavaScript 代码执行并获取到 `<video>` 元素的引用。** 例如，使用 `document.querySelector('video')`。
3. **JavaScript 代码调用 `videoElement.requestVideoFrameCallback(callback)`。**  这会在 Blink 引擎中调用到 `VideoFrameCallbackRequesterImpl::requestVideoFrameCallback` 静态方法，注册回调函数。
4. **用户触发视频播放。** 例如，点击视频的播放按钮或调用 `videoElement.play()`。
5. **底层的 WebMediaPlayer 开始解码和渲染视频帧。**
6. **当 WebMediaPlayer 准备好新的视频帧进行渲染时，它会通知 `VideoFrameCallbackRequesterImpl`。**
7. **`VideoFrameCallbackRequesterImpl` 按照其内部逻辑调度和执行已注册的 JavaScript 回调函数。**  可以通过在 `OnRequestVideoFrameCallback`, `ScheduleExecution`, `OnExecution`, `ExecuteVideoFrameCallbacks` 等方法中设置断点来跟踪执行流程。
8. **在 JavaScript 回调函数中，开发者可以访问 `metadata` 对象，其中包含了帧的详细信息。**

**调试线索：**

* **检查 JavaScript 代码中 `requestVideoFrameCallback` 的调用是否正确，回调函数是否定义，以及是否在合适的时机调用。**
* **使用浏览器的开发者工具查看 `video` 元素的事件监听器，确认 `requestVideoFrameCallback` 是否被注册。**
* **在 `VideoFrameCallbackRequesterImpl` 的关键方法中设置断点，例如 `OnRequestVideoFrameCallback` 和 `ExecuteVideoFrameCallbacks`，以观察回调的调度和执行流程。**
* **检查 `VideoFrameRequestCallbackCollection` 的状态，确认回调是否被正确注册和取消。**
* **如果涉及到 WebXR，需要检查 WebXR 会话的状态以及相关的 API 调用。**
* **查看浏览器的控制台输出，看是否有相关的错误或警告信息。**
* **使用 Chromium 的 tracing 工具 (chrome://tracing) 可以捕获更底层的事件，例如渲染步骤和回调执行的时间线，帮助分析性能问题。**

总而言之，`VideoFrameCallbackRequesterImpl.cc` 文件是 Blink 引擎中实现视频帧回调功能的核心组件，它连接了底层的视频渲染管道和上层的 JavaScript 代码，为开发者提供了强大的视频处理和同步能力。理解其工作原理对于调试和优化与视频相关的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/video_rvfc/video_frame_callback_requester_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/video_rvfc/video_frame_callback_requester_impl.h"

#include <memory>
#include <utility>

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_callback_metadata.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/scripted_animation_controller.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/time_clamper.h"
#include "third_party/blink/renderer/modules/video_rvfc/video_frame_request_callback_collection.h"
#include "third_party/blink/renderer/modules/xr/xr_frame_provider.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_system.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {
// Returns whether or not a video's frame rate is close to the browser's frame
// rate, as measured by their rendering intervals. For example, on a 60hz
// screen, this should return false for a 25fps video and true for a 60fps
// video. On a 144hz screen, both videos would return false.
static bool IsFrameRateRelativelyHigh(base::TimeDelta rendering_interval,
                                      base::TimeDelta average_frame_duration) {
  if (average_frame_duration.is_zero())
    return false;

  constexpr double kThreshold = 0.05;
  return kThreshold >
         std::abs(1.0 - (rendering_interval / average_frame_duration));
}

}  // namespace

VideoFrameCallbackRequesterImpl::VideoFrameCallbackRequesterImpl(
    HTMLVideoElement& element)
    : VideoFrameCallbackRequester(element),
      callback_collection_(
          MakeGarbageCollected<VideoFrameRequestCallbackCollection>(
              element.GetExecutionContext())) {
  cross_origin_isolated_capability_ =
      element.GetExecutionContext()
          ? element.GetExecutionContext()->CrossOriginIsolatedCapability()
          : false;
}

VideoFrameCallbackRequesterImpl::~VideoFrameCallbackRequesterImpl() = default;

// static
VideoFrameCallbackRequesterImpl& VideoFrameCallbackRequesterImpl::From(
    HTMLVideoElement& element) {
  VideoFrameCallbackRequesterImpl* supplement =
      Supplement<HTMLVideoElement>::From<VideoFrameCallbackRequesterImpl>(
          element);
  if (!supplement) {
    supplement = MakeGarbageCollected<VideoFrameCallbackRequesterImpl>(element);
    Supplement<HTMLVideoElement>::ProvideTo(element, supplement);
  }

  return *supplement;
}

// static
int VideoFrameCallbackRequesterImpl::requestVideoFrameCallback(
    HTMLVideoElement& element,
    V8VideoFrameRequestCallback* callback) {
  return VideoFrameCallbackRequesterImpl::From(element)
      .requestVideoFrameCallback(callback);
}

// static
void VideoFrameCallbackRequesterImpl::cancelVideoFrameCallback(
    HTMLVideoElement& element,
    int callback_id) {
  VideoFrameCallbackRequesterImpl::From(element).cancelVideoFrameCallback(
      callback_id);
}

void VideoFrameCallbackRequesterImpl::OnWebMediaPlayerCreated() {
  if (!callback_collection_->IsEmpty())
    GetSupplementable()->GetWebMediaPlayer()->RequestVideoFrameCallback();
}

void VideoFrameCallbackRequesterImpl::OnWebMediaPlayerCleared() {
  // Clear existing issued weak pointers from the factory, so that
  // pending ScheduleVideoFrameCallbacksExecution are cancelled.
  weak_factory_.Invalidate();

  // If the HTMLVideoElement changes sources, we need to reset this flag.
  // This allows the first frame of the new media player (requested in
  // OnWebMediaPlayerCreated()) to restart the rVFC loop.
  pending_execution_ = false;

  // If we don't reset |last_presented_frames_|, the first frame from video B
  // will appear stale, if we switched away from video A after exactly 1
  // presented frame. This would result in rVFC calls not being executed, and
  // |consecutive_stale_frames_| being incremented instead.
  last_presented_frames_ = 0;
  consecutive_stale_frames_ = 0;
}

void VideoFrameCallbackRequesterImpl::ScheduleWindowRaf() {
  GetSupplementable()
      ->GetDocument()
      .GetScriptedAnimationController()
      .ScheduleVideoFrameCallbacksExecution(
          WTF::BindOnce(&VideoFrameCallbackRequesterImpl::OnExecution,
                        WrapPersistent(weak_factory_.GetWeakCell())));
}

void VideoFrameCallbackRequesterImpl::ScheduleExecution() {
  TRACE_EVENT1("blink", "VideoFrameCallbackRequesterImpl::ScheduleExecution",
               "did_schedule", !pending_execution_);

  if (pending_execution_)
    return;

  pending_execution_ = true;

  if (TryScheduleImmersiveXRSessionRaf())
    return;

  ScheduleWindowRaf();
}

void VideoFrameCallbackRequesterImpl::OnImmersiveSessionStart() {
  in_immersive_session_ = true;

  if (pending_execution_ && !callback_collection_->IsEmpty())
    TryScheduleImmersiveXRSessionRaf();
}

void VideoFrameCallbackRequesterImpl::OnImmersiveSessionEnd() {
  in_immersive_session_ = false;

  if (pending_execution_ && !callback_collection_->IsEmpty())
    ScheduleWindowRaf();
}

void VideoFrameCallbackRequesterImpl::OnImmersiveFrame() {
  if (callback_collection_->IsEmpty())
    return;

  if (auto* player = GetSupplementable()->GetWebMediaPlayer())
    player->UpdateFrameIfStale();
}

XRFrameProvider* VideoFrameCallbackRequesterImpl::GetXRFrameProvider() {
  // Do not force the lazy creation of the XRSystem.
  // If it doesn't exist already exist, the webpage isn't using XR.
  auto* system = XRSystem::FromIfExists(GetSupplementable()->GetDocument());
  return system ? system->frameProvider() : nullptr;
}

bool VideoFrameCallbackRequesterImpl::TryScheduleImmersiveXRSessionRaf() {
  // Nothing to do here, we will be notified via OnImmersiveSessionStart() when
  // a new immersive session starts.
  if (observing_immersive_session_ && !in_immersive_session_)
    return false;

  auto* frame_provider = GetXRFrameProvider();

  if (!frame_provider)
    return false;

  if (!observing_immersive_session_) {
    frame_provider->AddImmersiveSessionObserver(this);
    observing_immersive_session_ = true;
  }

  XRSession* session = frame_provider->immersive_session();

  in_immersive_session_ = session && !session->ended();

  if (!in_immersive_session_)
    return false;

  session->ScheduleVideoFrameCallbacksExecution(
      WTF::BindOnce(&VideoFrameCallbackRequesterImpl::OnExecution,
                    WrapPersistent(weak_factory_.GetWeakCell())));

  return true;
}

void VideoFrameCallbackRequesterImpl::OnRequestVideoFrameCallback() {
  TRACE_EVENT1("blink",
               "VideoFrameCallbackRequesterImpl::OnRequestVideoFrameCallback",
               "has_callbacks", !callback_collection_->IsEmpty());

  // Skip this work if there are no registered callbacks.
  if (callback_collection_->IsEmpty())
    return;

  ScheduleExecution();
}

void VideoFrameCallbackRequesterImpl::ExecuteVideoFrameCallbacks(
    double high_res_now_ms,
    std::unique_ptr<WebMediaPlayer::VideoFramePresentationMetadata>
        frame_metadata) {
  TRACE_EVENT0("blink",
               "VideoFrameCallbackRequesterImpl::ExecuteVideoFrameCallbacks");

  last_presented_frames_ = frame_metadata->presented_frames;

  auto* metadata = VideoFrameCallbackMetadata::Create();
  auto& time_converter =
      GetSupplementable()->GetDocument().Loader()->GetTiming();

  metadata->setPresentationTime(GetClampedTimeInMillis(
      time_converter.MonotonicTimeToZeroBasedDocumentTime(
          frame_metadata->presentation_time),
      cross_origin_isolated_capability_));

  metadata->setExpectedDisplayTime(GetClampedTimeInMillis(
      time_converter.MonotonicTimeToZeroBasedDocumentTime(
          frame_metadata->expected_display_time),
      cross_origin_isolated_capability_));

  metadata->setPresentedFrames(frame_metadata->presented_frames);

  metadata->setWidth(frame_metadata->width);
  metadata->setHeight(frame_metadata->height);

  metadata->setMediaTime(frame_metadata->media_time.InSecondsF());

  if (frame_metadata->metadata.processing_time) {
    metadata->setProcessingDuration(GetCoarseClampedTimeInSeconds(
        *frame_metadata->metadata.processing_time));
  }

  if (frame_metadata->metadata.capture_begin_time) {
    metadata->setCaptureTime(GetClampedTimeInMillis(
        time_converter.MonotonicTimeToZeroBasedDocumentTime(
            *frame_metadata->metadata.capture_begin_time),
        cross_origin_isolated_capability_));
  }

  if (frame_metadata->metadata.receive_time) {
    metadata->setReceiveTime(GetClampedTimeInMillis(
        time_converter.MonotonicTimeToZeroBasedDocumentTime(
            *frame_metadata->metadata.receive_time),
        cross_origin_isolated_capability_));
  }

  if (frame_metadata->metadata.rtp_timestamp) {
    double rtp_timestamp = *frame_metadata->metadata.rtp_timestamp;
    base::CheckedNumeric<uint32_t> uint_rtp_timestamp = rtp_timestamp;
    if (uint_rtp_timestamp.IsValid())
      metadata->setRtpTimestamp(rtp_timestamp);
  }

  callback_collection_->ExecuteFrameCallbacks(high_res_now_ms, metadata);
}

void VideoFrameCallbackRequesterImpl::OnExecution(double high_res_now_ms) {
  TRACE_EVENT1("blink", "VideoFrameCallbackRequesterImpl::OnRenderingSteps",
               "has_callbacks", !callback_collection_->IsEmpty());
  pending_execution_ = false;

  // Callbacks could have been canceled from the time we scheduled their
  // execution.
  // We could also be executing a leftover callback scheduled through the
  // ScriptedAnimationController, right after exiting an immersive XR session.
  if (callback_collection_->IsEmpty())
    return;

  auto* player = GetSupplementable()->GetWebMediaPlayer();
  if (!player)
    return;

  auto metadata = player->GetVideoFramePresentationMetadata();

  const bool is_hfr = IsFrameRateRelativelyHigh(
      metadata->rendering_interval, metadata->average_frame_duration);

  // Check if we have a new frame or not.
  if (last_presented_frames_ == metadata->presented_frames) {
    ++consecutive_stale_frames_;
  } else {
    consecutive_stale_frames_ = 0;
    ExecuteVideoFrameCallbacks(high_res_now_ms, std::move(metadata));
  }

  // If the video's frame rate is relatively close to the screen's refresh rate
  // (or brower's current frame rate), schedule ourselves immediately.
  // Otherwise, jittering and thread hopping means that the call to
  // OnRequestVideoFrameCallback() would barely miss the rendering steps, and we
  // would miss a frame.
  // Also check |consecutive_stale_frames_| to make sure we don't schedule
  // executions when paused, or in other scenarios where potentially scheduling
  // extra rendering steps would be wasteful.
  if (is_hfr && !callback_collection_->IsEmpty() &&
      consecutive_stale_frames_ < 2) {
    ScheduleExecution();
  }
}

// static
double VideoFrameCallbackRequesterImpl::GetClampedTimeInMillis(
    base::TimeDelta time,
    bool cross_origin_isolated_capability) {
  return Performance::ClampTimeResolution(time,
                                          cross_origin_isolated_capability);
}

// static
double VideoFrameCallbackRequesterImpl::GetCoarseClampedTimeInSeconds(
    base::TimeDelta time) {
  constexpr auto kCoarseResolution = base::Microseconds(100);
  // Add this assert, in case TimeClamper's resolution were to change to be
  // stricter.
  static_assert(
      kCoarseResolution >=
          base::Microseconds(TimeClamper::kCoarseResolutionMicroseconds),
      "kCoarseResolution should be at least as coarse as other clock "
      "resolutions");

  return time.FloorToMultiple(kCoarseResolution).InSecondsF();
}

int VideoFrameCallbackRequesterImpl::requestVideoFrameCallback(
    V8VideoFrameRequestCallback* callback) {
  TRACE_EVENT0("blink",
               "VideoFrameCallbackRequesterImpl::requestVideoFrameCallback");

  if (auto* player = GetSupplementable()->GetWebMediaPlayer())
    player->RequestVideoFrameCallback();

  auto* frame_callback = MakeGarbageCollected<
      VideoFrameRequestCallbackCollection::V8VideoFrameCallback>(callback);

  return callback_collection_->RegisterFrameCallback(frame_callback);
}

void VideoFrameCallbackRequesterImpl::RegisterCallbackForTest(
    VideoFrameRequestCallbackCollection::VideoFrameCallback* callback) {
  pending_execution_ = true;

  callback_collection_->RegisterFrameCallback(callback);
}

void VideoFrameCallbackRequesterImpl::cancelVideoFrameCallback(int id) {
  callback_collection_->CancelFrameCallback(id);
}

void VideoFrameCallbackRequesterImpl::Trace(Visitor* visitor) const {
  visitor->Trace(callback_collection_);
  visitor->Trace(weak_factory_);
  VideoFrameCallbackRequester::Trace(visitor);
}

}  // namespace blink

"""

```