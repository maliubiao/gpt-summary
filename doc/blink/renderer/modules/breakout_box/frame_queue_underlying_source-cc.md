Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for a functional description of the C++ file, its relation to web technologies, logical reasoning examples, common errors, and debugging tips.

2. **Identify the Core Class:** The filename `frame_queue_underlying_source.cc` and the class definition `FrameQueueUnderlyingSource` are key. The `<NativeFrameType>` suggests this is a template class, meaning it can work with different types of frames (likely video and audio).

3. **Analyze the Includes:**  The included headers provide crucial context:
    * `third_party/blink/renderer/...`: This confirms it's part of the Blink rendering engine.
    * `base/...`:  Indicates use of Chromium's base library for features like feature flags, task scheduling, and time.
    * `third_party/blink/renderer/bindings/core/v8/...`:  Points to interaction with JavaScript via V8.
    * `third_party/blink/renderer/core/dom/...`:  Suggests interaction with the DOM.
    * `third_party/blink/renderer/core/streams/...`:  Crucially links this class to the Streams API. This is a strong indicator of its connection to JavaScript.
    * `third_party/blink/renderer/modules/webcodecs/...`:  Confirms that this class deals with WebCodecs API, specifically `VideoFrame` and `AudioData`. This further strengthens the connection to JavaScript.
    * `third_party/webrtc/api/...`: Shows interaction with WebRTC, further suggesting media handling.

4. **Examine the Constructor(s):** The constructors reveal key parameters:
    * `max_queue_size`:  Indicates this class manages a queue of frames with a maximum size.
    * `device_id`:  Suggests this is related to media devices (like cameras or microphones).
    * `frame_pool_size`: Implies a mechanism for managing a pool of frames, potentially for performance or resource management.
    * Copy constructor taking `other_source`: This enables transferring ownership or control of the frame queue.

5. **Analyze Public Methods:**  These define the core functionality:
    * `Pull()`: This method is characteristic of a `ReadableStream` underlying source. It's responsible for providing data to the stream.
    * `Start()`:  Another standard `ReadableStream` method, likely used for initialization.
    * `Cancel()`:  Standard `ReadableStream` method for canceling the stream.
    * `ContextDestroyed()`:  A Blink lifecycle method, suggesting cleanup when the context is destroyed.
    * `MaxQueueSize()`:  Getter for the maximum queue size.
    * `Close()`:  Method for explicitly closing the source and potentially the associated stream.
    * `QueueFrame()`:  The primary method for adding new frames to the internal queue. This is where external components likely feed data into the system.
    * `TransferSource()`:  Allows transferring the frame queue to another instance.

6. **Analyze Private/Protected Methods:**  These provide implementation details:
    * `MaybeSendFrameFromQueueToStream()`:  Handles dequeuing frames and sending them to the stream controller. The "Maybe" suggests conditional execution.
    * `EnqueueBlinkFrame()`:  Specifically enqueues a Blink-specific frame object into the stream controller.
    * `MustUseMonitor()`:  A conditional flag related to the `device_id`. This likely controls whether additional monitoring/synchronization logic is applied.
    * `GetMonitorLock()`, `MaybeMonitorPopFrameId()`, `MonitorPopFrameLocked()`, `MonitorPushFrameLocked()`, `AnalyzeNewFrameLocked()`: These methods strongly suggest a monitoring mechanism for managing frame usage and preventing over-allocation, especially when dealing with shared resources. The locking indicates thread safety considerations.
    * `MakeBlinkFrame()`:  Converts the native frame type (`media::VideoFrame` or `media::AudioBuffer`) into a Blink-specific wrapper (`VideoFrame` or `AudioData`). This is a crucial step for interaction with the JavaScript Streams API.

7. **Examine the Template Specializations:** The specializations for `media::VideoFrame` and `media::AudioBuffer` highlight the two primary types of data this class handles. The `MakeBlinkFrame` specialization shows the creation of `VideoFrame` and `AudioData` objects. The `MustUseMonitor()` specialization shows that monitoring is disabled for audio buffers.

8. **Identify Feature Flags:**  The `BASE_FEATURE` macros indicate configurable behavior:
    * `kBreakoutBoxEnqueueInSeparateTask`:  Addresses potential UI freezes by enqueuing frames in a separate task.
    * `kBreakoutBoxPreferCaptureTimestampInVideoFrames`:  Suggests a preference for using the capture timestamp in video frames.
    * `kBreakoutBoxInsertVideoCaptureTimestamp`:  Indicates the possibility of inserting capture timestamps.

9. **Connect to Web Technologies:** Based on the analysis, the connections to JavaScript, HTML, and CSS become clear:
    * **JavaScript:**  The class is directly used by JavaScript's Readable Streams API, particularly when dealing with media streams obtained from sources like cameras (using `getUserMedia`) or when decoding media. The `Pull()` method is central to the pull-based nature of readable streams. The interaction with `VideoFrame` and `AudioData` further strengthens this link.
    * **HTML:**  HTML elements like `<video>` or `<audio>` might be the eventual destinations for the frames processed by this class.
    * **CSS:** While less direct, CSS could influence the rendering of video frames once they reach the `<video>` element.

10. **Construct Logical Reasoning Examples:**  Think about the core functionality (`QueueFrame`, `Pull`) and how data flows. Consider scenarios with different queue states (empty, full).

11. **Identify Potential User/Programming Errors:** Focus on common pitfalls when working with asynchronous operations, resource management (queue size), and external dependencies.

12. **Trace User Operations:**  Think about the user actions that would lead to this code being executed. Starting a media stream in JavaScript is a prime example.

13. **Structure the Output:** Organize the findings into the requested categories: Functionality, Relation to Web Technologies, Logical Reasoning, Common Errors, and Debugging. Use clear and concise language, providing specific examples where possible.

14. **Review and Refine:**  Read through the generated output to ensure accuracy, clarity, and completeness. Correct any mistakes or areas that could be explained better. For example, initially, I might have overlooked the significance of the template specializations. A review would catch this. Similarly, elaborating on *why* certain feature flags exist (like the separate task enqueueing) adds valuable context.
This C++ file, `frame_queue_underlying_source.cc`, within the Chromium Blink engine, defines a template class `FrameQueueUnderlyingSource`. This class serves as the **underlying source for a ReadableStream** that queues media frames (either video or audio). It acts as an intermediary, receiving native media frames from a source (like a video capture device or a decoder) and making them available to JavaScript through the Streams API.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Manages a Frame Queue:** It internally maintains a queue (`frame_queue_handle_`) to store incoming media frames. The size of this queue is configurable (`max_queue_size`).
2. **Acts as a ReadableStream Source:** It implements the `UnderlyingSource` interface required by the JavaScript ReadableStream API. This involves providing `start()`, `pull()`, and `cancel()` methods.
3. **Receives and Queues Frames:** The `QueueFrame()` method is the primary way to add new media frames (of type `NativeFrameType`, which can be `media::VideoFrame` or `media::AudioBuffer`) to the internal queue.
4. **Provides Frames to the Stream:** The `pull()` method is invoked by the ReadableStream when it needs more data. `FrameQueueUnderlyingSource` then attempts to dequeue a frame and pass it to the stream's controller for consumption by JavaScript.
5. **Handles Backpressure:** The `max_queue_size` helps manage backpressure. If the queue is full, new frames might be dropped or the source might be signaled to slow down.
6. **Supports Frame Pooling (for Video):**  When dealing with video frames and a `device_id` is provided, it integrates with `VideoFrameMonitor`. This allows for more efficient management of video frame resources, potentially dropping older, unreferenced frames to make space for new ones. This is related to the `frame_pool_size_`.
7. **Handles Stream Lifecycle:** The `start()` and `cancel()` methods manage the lifecycle of the underlying media source and the ReadableStream.
8. **Thread Safety:** It uses locks (`lock_`) to protect shared resources and ensure thread safety, as frames might be queued from a different thread than where the stream is being consumed.
9. **Context Management:** The `ContextDestroyed()` method handles cleanup when the associated browsing context is destroyed.
10. **Frame Transfer:** The `TransferSource()` method allows transferring the ownership of the frame queue to another `FrameQueueUnderlyingSource` instance.

**Relationship with JavaScript, HTML, and CSS:**

This C++ code is a crucial part of the plumbing that connects native media processing within the browser to JavaScript APIs.

* **JavaScript:**
    * **ReadableStream API:** This class directly implements the `UnderlyingSource` interface for a ReadableStream. JavaScript code would create a `ReadableStream` and provide an instance of `FrameQueueUnderlyingSource` as its source.
    * **WebCodecs API:**  The `NativeFrameType` can be `media::VideoFrame` or `media::AudioBuffer`, which are the native representations of data handled by the WebCodecs API (like `VideoFrame` and `AudioData` JavaScript objects). The `MakeBlinkFrame` method converts these native types into their JavaScript counterparts.
    * **`getUserMedia()` API:** When accessing a camera or microphone using `getUserMedia()`, the resulting media tracks often use a `FrameQueueUnderlyingSource` (or something similar) to pipe the captured frames to the JavaScript stream.

    **Example:**

    ```javascript
    // Assume 'videoTrack' is a MediaStreamTrack obtained from getUserMedia()
    const reader = videoTrack.readable.getReader();

    async function readFrames() {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        // 'value' will be a VideoFrame object (or AudioData for audio tracks)
        console.log("Received a frame:", value);
        // You can then draw this VideoFrame to a <canvas> or process the AudioData.
        if (value instanceof VideoFrame) {
          const canvas = document.getElementById('myCanvas');
          canvas.getContext('2d').drawImage(value, 0, 0);
          value.close(); // Important to release resources
        }
      }
    }

    readFrames();
    ```

* **HTML:**
    * The `<video>` and `<audio>` elements are the ultimate consumers of the media data flowing through these streams. JavaScript code might take the `VideoFrame` objects from the stream and render them on a `<canvas>` element or use them with the `HTMLVideoElement.requestVideoFrameCallback()` API.

* **CSS:**
    * CSS can style the `<video>` element, affecting its size, position, and appearance. However, CSS doesn't directly interact with the `FrameQueueUnderlyingSource` or the underlying stream processing logic.

**Logical Reasoning Examples:**

Let's consider the `QueueFrame` and `Pull` methods:

**Scenario 1: Video Frame Queuing without Monitor**

* **Assumption (Input):** `MustUseMonitor()` returns `false`. The queue is initially empty, and `num_pending_pulls_` (number of outstanding `pull()` requests) is greater than 0. A new `media::VideoFrame` arrives in `QueueFrame`.
* **Logic:**
    1. The lock is acquired.
    2. `transferred_source_` is checked (assume it's null).
    3. `should_send_frame_to_stream` is true because `num_pending_pulls_ > 0`.
    4. The video frame is pushed onto the `frame_queue_handle_`.
    5. A task is posted to `realm_task_runner_` to execute `MaybeSendFrameFromQueueToStream`.
* **Output:** The video frame is added to the queue, and eventually, `MaybeSendFrameFromQueueToStream` will be called to dequeue and enqueue it to the JavaScript stream.

**Scenario 2: Video Frame Queuing with Monitor and Full Queue**

* **Assumption (Input):** `MustUseMonitor()` returns `true`. The queue is full (`max_queue_size` reached). `frame_pool_size_` is smaller than `max_queue_size`. `AnalyzeNewFrameLocked` determines that the oldest frame can be replaced (e.g., it's not actively being used elsewhere).
* **Logic:**
    1. Locks are acquired for the queue and the monitor.
    2. `AnalyzeNewFrameLocked` returns `NewFrameAction::kReplace`.
    3. `MonitorPushFrameLocked` is called for the new frame.
    4. `MonitorPopFrameLocked` is called for the oldest frame.
    5. The oldest frame is explicitly popped from the queue.
    6. The new frame is pushed onto the queue.
    7. A task might be posted to `MaybeSendFrameFromQueueToStream` depending on `num_pending_pulls_`.
* **Output:** The oldest frame in the queue is replaced by the new frame, and resource monitoring is updated.

**Common Usage Errors:**

1. **Not Closing `VideoFrame` Objects in JavaScript:** When a `VideoFrame` object is received in JavaScript, it holds onto native resources. Failing to call `videoFrame.close()` after use will lead to memory leaks and potentially performance issues, especially when the `FrameQueueUnderlyingSource` uses frame pooling.
2. **Incorrectly Configuring Queue Size:** Setting `max_queue_size` too low can lead to frames being dropped prematurely if the consumer in JavaScript can't keep up. Setting it too high might consume excessive memory.
3. **Not Handling Backpressure:**  If the JavaScript consumer doesn't handle the stream properly (e.g., by using a `ReadableStreamDefaultReader`), backpressure might not be correctly applied, potentially leading to the queue growing indefinitely (up to its max size) and consuming resources.
4. **Trying to Use the Stream After Closing:** Once the `FrameQueueUnderlyingSource` is closed (either explicitly or due to context destruction), attempting to `pull()` from the associated ReadableStream will result in an error.
5. **Concurrency Issues (if manipulating the queue directly from outside):** While the class itself has internal locking, if external code tries to interact with the underlying queue structure directly (which shouldn't be done in most cases), it can lead to race conditions and data corruption.

**User Operations Leading Here (Debugging Clues):**

1. **Accessing Camera/Microphone:**
   - A user grants permission for a website to access their camera or microphone.
   - JavaScript code calls `navigator.mediaDevices.getUserMedia({ video: true })` or similar.
   - The browser internally sets up the media capture pipeline.
   - A `FrameQueueUnderlyingSource` (or a similar class) is often created to handle the stream of captured video or audio frames.
   - As frames are captured by the device, they are enqueued into the `FrameQueueUnderlyingSource`.
   - When JavaScript reads from the `readable` property of the `MediaStreamTrack`, the `pull()` method of `FrameQueueUnderlyingSource` is invoked.

2. **Decoding Media (e.g., using WebCodecs):**
   - A website might be decoding video or audio data using the WebCodecs API.
   - The decoder outputs `media::VideoFrame` or `media::AudioBuffer` objects.
   - These decoded frames are often fed into a `FrameQueueUnderlyingSource` to be consumed by JavaScript.

3. **Using MediaRecorder API:**
   - When recording media using the `MediaRecorder` API, the captured frames might pass through a similar queuing mechanism.

**Debugging Steps to Reach This Code:**

1. **Set Breakpoints in JavaScript:** Start by setting breakpoints in the JavaScript code that's consuming the media stream (e.g., within the `reader.read()` loop).
2. **Trace Stream Creation:** If you suspect issues with stream setup, try to trace how the `ReadableStream` is being created and how the underlying source is being associated with it. Look for the creation of `MediaStreamTrack` objects.
3. **Inspect Native Media Pipeline (if possible):** Chromium's internal debugging tools (like `chrome://webrtc-internals/`) can provide insights into the native media pipeline and might indicate if frames are being dropped or if there are issues at the source.
4. **Set Breakpoints in C++:** If you need to dive deeper, set breakpoints within the `frame_queue_underlying_source.cc` file in methods like `QueueFrame`, `Pull`, `MaybeSendFrameFromQueueToStream`, and the monitor-related methods (if applicable). You'll need a Chromium development environment for this.
5. **Check Feature Flags:** The file mentions feature flags like `kBreakoutBoxEnqueueInSeparateTask`. Ensure these flags are enabled or disabled as expected for your debugging scenario.
6. **Analyze Logs:** Look for relevant logging output within Chromium's console or using tracing mechanisms. The `TRACE_EVENT` macro in `MakeBlinkFrame` suggests that tracing information about frame timestamps is available.

By understanding the role of `FrameQueueUnderlyingSource` and how it interacts with JavaScript and the underlying media pipeline, developers can effectively debug issues related to media streaming and processing within the browser.

Prompt: 
```
这是目录为blink/renderer/modules/breakout_box/frame_queue_underlying_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/breakout_box/frame_queue_underlying_source.h"

#include "base/feature_list.h"
#include "base/task/bind_post_task.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_monitor.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/webrtc/api/frame_transformer_interface.h"

namespace blink {

BASE_FEATURE(kBreakoutBoxEnqueueInSeparateTask,
             "BreakoutBoxEnqueueInSeparateTask",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kBreakoutBoxPreferCaptureTimestampInVideoFrames,
             "BreakoutBoxPreferCaptureTimestampInVideoFrames",
             base::FEATURE_ENABLED_BY_DEFAULT);

BASE_FEATURE(kBreakoutBoxInsertVideoCaptureTimestamp,
             "BreakoutBoxInsertVideoCaptureTimestamp",
             base::FEATURE_DISABLED_BY_DEFAULT);

namespace {

media::VideoFrame::ID GetFrameId(
    const scoped_refptr<media::VideoFrame>& video_frame) {
  return video_frame->unique_id();
}

media::VideoFrame::ID GetFrameId(const scoped_refptr<media::AudioBuffer>&) {
  NOTREACHED();
}

}  // namespace

template <typename NativeFrameType>
FrameQueueUnderlyingSource<NativeFrameType>::FrameQueueUnderlyingSource(
    ScriptState* script_state,
    wtf_size_t max_queue_size,
    std::string device_id,
    wtf_size_t frame_pool_size)
    : UnderlyingSourceBase(script_state),
      realm_task_runner_(ExecutionContext::From(script_state)
                             ->GetTaskRunner(TaskType::kInternalMediaRealTime)),
      frame_queue_handle_(
          base::MakeRefCounted<FrameQueue<NativeFrameType>>(max_queue_size)),
      device_id_(std::move(device_id)),
      frame_pool_size_(frame_pool_size) {
  DCHECK(device_id_.empty() || frame_pool_size_ > 0);
}

template <typename NativeFrameType>
FrameQueueUnderlyingSource<NativeFrameType>::FrameQueueUnderlyingSource(
    ScriptState* script_state,
    wtf_size_t max_queue_size)
    : FrameQueueUnderlyingSource(script_state,
                                 max_queue_size,
                                 std::string(),
                                 /*frame_pool_size=*/0) {}

template <typename NativeFrameType>
FrameQueueUnderlyingSource<NativeFrameType>::FrameQueueUnderlyingSource(
    ScriptState* script_state,
    FrameQueueUnderlyingSource<NativeFrameType>* other_source)
    : UnderlyingSourceBase(script_state),
      realm_task_runner_(ExecutionContext::From(script_state)
                             ->GetTaskRunner(TaskType::kInternalMediaRealTime)),
      frame_queue_handle_(other_source->frame_queue_handle_.Queue()),
      device_id_(other_source->device_id_),
      frame_pool_size_(other_source->frame_pool_size_) {
  DCHECK(device_id_.empty() || frame_pool_size_ > 0);
}

template <typename NativeFrameType>
ScriptPromise<IDLUndefined> FrameQueueUnderlyingSource<NativeFrameType>::Pull(
    ScriptState* script_state,
    ExceptionState&) {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  {
    base::AutoLock locker(lock_);
    num_pending_pulls_++;
  }
  auto frame_queue = frame_queue_handle_.Queue();
  if (!frame_queue)
    return ToResolvedUndefinedPromise(script_state);

  if (!frame_queue->IsEmpty()) {
    // Enqueuing the frame in the stream controller synchronously can lead to a
    // state where the JS code issuing and handling the read requests keeps
    // executing and prevents other tasks from executing. To avoid this, enqueue
    // the frame on another task. See https://crbug.com/1216445#c1
    realm_task_runner_->PostTask(
        FROM_HERE,
        WTF::BindOnce(&FrameQueueUnderlyingSource<
                          NativeFrameType>::MaybeSendFrameFromQueueToStream,
                      WrapPersistent(this)));
  }
  return ToResolvedUndefinedPromise(script_state);
}

template <typename NativeFrameType>
ScriptPromise<IDLUndefined> FrameQueueUnderlyingSource<NativeFrameType>::Start(
    ScriptState* script_state) {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  if (is_closed_) {
    // This was intended to be closed before Start() was called.
    CloseController();
  } else {
    if (!StartFrameDelivery()) {
      // There is only one way in which this can fail for now. Perhaps
      // implementations should return their own failure messages.
      V8ThrowDOMException::Throw(script_state->GetIsolate(),
                                 DOMExceptionCode::kInvalidStateError,
                                 "Invalid track");
      return EmptyPromise();
    }
  }

  return ToResolvedUndefinedPromise(script_state);
}

template <typename NativeFrameType>
ScriptPromise<IDLUndefined> FrameQueueUnderlyingSource<NativeFrameType>::Cancel(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState&) {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  Close();
  return ToResolvedUndefinedPromise(script_state);
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::ContextDestroyed() {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  Close();
  UnderlyingSourceBase::ContextDestroyed();
}

template <typename NativeFrameType>
wtf_size_t FrameQueueUnderlyingSource<NativeFrameType>::MaxQueueSize() const {
  auto queue = frame_queue_handle_.Queue();
  return queue ? queue->MaxSize() : 0;
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::Close() {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  if (is_closed_)
    return;

  is_closed_ = true;
  if (GetExecutionContext()) {
    StopFrameDelivery();
    CloseController();
  }
  bool should_clear_queue = true;
  {
    base::AutoLock locker(lock_);
    num_pending_pulls_ = 0;
    if (transferred_source_) {
      PostCrossThreadTask(
          *transferred_source_->GetRealmRunner(), FROM_HERE,
          CrossThreadBindOnce(
              &FrameQueueUnderlyingSource<NativeFrameType>::Close,
              WrapCrossThreadWeakPersistent(transferred_source_.Get())));
      // The queue will be cleared by |transferred_source_|.
      should_clear_queue = false;
    }
    transferred_source_.Clear();
  }
  auto frame_queue = frame_queue_handle_.Queue();
  if (frame_queue && should_clear_queue && MustUseMonitor()) {
    while (!frame_queue->IsEmpty()) {
      std::optional<NativeFrameType> popped_frame = frame_queue->Pop();
      base::AutoLock monitor_locker(GetMonitorLock());
      MonitorPopFrameLocked(popped_frame.value());
    }
  }
  // Invalidating will clear the queue in the non-monitoring case if there is
  // no transferred source.
  frame_queue_handle_.Invalidate();
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::QueueFrame(
    NativeFrameType media_frame) {
  bool should_send_frame_to_stream;
  {
    base::AutoLock locker(lock_);
    if (transferred_source_) {
      transferred_source_->QueueFrame(std::move(media_frame));
      return;
    }
    should_send_frame_to_stream = num_pending_pulls_ > 0;
  }

  auto frame_queue = frame_queue_handle_.Queue();
  if (!frame_queue)
    return;

  if (MustUseMonitor()) {
    base::AutoLock queue_locker(frame_queue->GetLock());
    base::AutoLock monitor_locker(GetMonitorLock());
    std::optional<NativeFrameType> oldest_frame = frame_queue->PeekLocked();
    NewFrameAction action = AnalyzeNewFrameLocked(media_frame, oldest_frame);
    switch (action) {
      case NewFrameAction::kPush: {
        MonitorPushFrameLocked(media_frame);
        std::optional<NativeFrameType> replaced_frame =
            frame_queue->PushLocked(std::move(media_frame));
        if (replaced_frame.has_value())
          MonitorPopFrameLocked(replaced_frame.value());
        break;
      }
      case NewFrameAction::kReplace:
        MonitorPushFrameLocked(media_frame);
        if (oldest_frame.has_value())
          MonitorPopFrameLocked(oldest_frame.value());
        // Explicitly pop the old frame and push the new one since the
        // |frame_pool_size_| limit has been reached and it may be smaller
        // than the maximum size of |frame_queue|.
        frame_queue->PopLocked();
        frame_queue->PushLocked(std::move(media_frame));
        break;
      case NewFrameAction::kDrop:
        // Drop |media_frame| by retuning without doing anything with it.
        return;
    }
  } else {
    frame_queue->Push(std::move(media_frame));
  }
  if (should_send_frame_to_stream) {
    PostCrossThreadTask(
        *realm_task_runner_, FROM_HERE,
        CrossThreadBindOnce(
            &FrameQueueUnderlyingSource<
                NativeFrameType>::MaybeSendFrameFromQueueToStream,
            WrapCrossThreadPersistent(this)));
  }
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::Trace(
    Visitor* visitor) const {
  UnderlyingSourceBase::Trace(visitor);
}

template <typename NativeFrameType>
int FrameQueueUnderlyingSource<NativeFrameType>::NumPendingPullsForTesting()
    const {
  base::AutoLock locker(lock_);
  return num_pending_pulls_;
}

template <typename NativeFrameType>
double FrameQueueUnderlyingSource<NativeFrameType>::DesiredSizeForTesting()
    const {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  return Controller()->DesiredSize();
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::TransferSource(
    CrossThreadPersistent<FrameQueueUnderlyingSource<NativeFrameType>>
        transferred_source) {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock locker(lock_);
  DCHECK(!transferred_source_);
  transferred_source_ = std::move(transferred_source);
  CloseController();
  frame_queue_handle_.Invalidate();
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::ClearTransferredSource() {
  base::AutoLock locker(lock_);
  transferred_source_.Clear();
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::CloseController() {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  // This can be called during stream construction while Controller() is still
  // false.
  if (Controller())
    Controller()->Close();
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<
    NativeFrameType>::MaybeSendFrameFromQueueToStream() {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  auto frame_queue = frame_queue_handle_.Queue();
  if (!frame_queue)
    return;

  {
    base::AutoLock locker(lock_);
    if (num_pending_pulls_ == 0)
      return;
  }
  while (true) {
    std::optional<NativeFrameType> media_frame = frame_queue->Pop();
    if (!media_frame.has_value())
      return;

    media::VideoFrame::ID frame_id = MustUseMonitor()
                                         ? GetFrameId(media_frame.value())
                                         : media::VideoFrame::ID();
    if (base::FeatureList::IsEnabled(kBreakoutBoxEnqueueInSeparateTask)) {
      // It has been observed that if the time between JS read() operations
      // is longer than the time between new frames, other tasks get delayed
      // and the page freezes. Enqueuing in a separate task avoids this problem.
      // See https://crbug.com/1490501
      realm_task_runner_->PostTask(
          FROM_HERE,
          WTF::BindOnce(
              &FrameQueueUnderlyingSource::EnqueueBlinkFrame,
              WrapPersistent(this),
              WrapPersistent(MakeBlinkFrame(std::move(media_frame.value())))));
    } else {
      Controller()->Enqueue(MakeBlinkFrame(std::move(media_frame.value())));
    }
    // Update the monitor after creating the Blink VideoFrame to avoid
    // temporarily removing the frame from the monitor.
    MaybeMonitorPopFrameId(frame_id);
    {
      base::AutoLock locker(lock_);
      if (--num_pending_pulls_ == 0)
        return;
    }
  }
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::EnqueueBlinkFrame(
    ScriptWrappable* blink_frame) const {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  if (GetExecutionContext() && !GetExecutionContext()->IsContextDestroyed()) {
    Controller()->Enqueue(blink_frame);
  }
}

template <typename NativeFrameType>
bool FrameQueueUnderlyingSource<NativeFrameType>::MustUseMonitor() const {
  return !device_id_.empty();
}

template <typename NativeFrameType>
base::Lock& FrameQueueUnderlyingSource<NativeFrameType>::GetMonitorLock() {
  DCHECK(MustUseMonitor());
  return VideoFrameMonitor::Instance().GetLock();
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::MaybeMonitorPopFrameId(
    media::VideoFrame::ID frame_id) {
  if (!MustUseMonitor())
    return;
  VideoFrameMonitor::Instance().OnCloseFrame(device_id_, frame_id);
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::MonitorPopFrameLocked(
    const NativeFrameType& media_frame) {
  DCHECK(MustUseMonitor());
  media::VideoFrame::ID frame_id = GetFrameId(media_frame);
  // Note: This is GetMonitorLock(), which is required, but the static checker
  // doesn't figure it out.
  VideoFrameMonitor::Instance().GetLock().AssertAcquired();
  VideoFrameMonitor::Instance().OnCloseFrameLocked(device_id_, frame_id);
}

template <typename NativeFrameType>
void FrameQueueUnderlyingSource<NativeFrameType>::MonitorPushFrameLocked(
    const NativeFrameType& media_frame) {
  DCHECK(MustUseMonitor());
  media::VideoFrame::ID frame_id = GetFrameId(media_frame);
  VideoFrameMonitor::Instance().GetLock().AssertAcquired();
  VideoFrameMonitor::Instance().OnOpenFrameLocked(device_id_, frame_id);
}

template <typename NativeFrameType>
typename FrameQueueUnderlyingSource<NativeFrameType>::NewFrameAction
FrameQueueUnderlyingSource<NativeFrameType>::AnalyzeNewFrameLocked(
    const NativeFrameType& new_frame,
    const std::optional<NativeFrameType>& oldest_frame) {
  DCHECK(MustUseMonitor());
  std::optional<media::VideoFrame::ID> oldest_frame_id;
  if (oldest_frame.has_value())
    oldest_frame_id = GetFrameId(oldest_frame.value());

  VideoFrameMonitor& monitor = VideoFrameMonitor::Instance();
  monitor.GetLock().AssertAcquired();
  wtf_size_t num_total_frames = monitor.NumFramesLocked(device_id_);
  if (num_total_frames < frame_pool_size_) {
    // The limit is not reached yet.
    return NewFrameAction::kPush;
  }

  media::VideoFrame::ID new_frame_id = GetFrameId(new_frame);
  if (monitor.NumRefsLocked(device_id_, new_frame_id) > 0) {
    // The new frame is already in another queue or exposed to JS, so adding
    // it to the queue would not count against the limit.
    return NewFrameAction::kPush;
  }

  if (!oldest_frame_id.has_value()) {
    // The limit has been reached and there is nothing that can be replaced.
    return NewFrameAction::kDrop;
  }

  if (monitor.NumRefsLocked(device_id_, oldest_frame_id.value()) == 1) {
    // The frame pool size limit has been reached. However, we can safely
    // replace the oldest frame in our queue, since it is not referenced
    // elsewhere.
    return NewFrameAction::kReplace;
  }

  return NewFrameAction::kDrop;
}

template <>
ScriptWrappable*
FrameQueueUnderlyingSource<scoped_refptr<media::VideoFrame>>::MakeBlinkFrame(
    scoped_refptr<media::VideoFrame> media_frame) {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  if (base::FeatureList::IsEnabled(kBreakoutBoxInsertVideoCaptureTimestamp)) {
    if (!first_frame_ticks_) {
      first_frame_ticks_ = base::TimeTicks::Now() - media_frame->timestamp();
    }

    if (!media_frame->metadata().capture_begin_time &&
        !media_frame->metadata().reference_time) {
      media_frame->metadata().capture_begin_time =
          *first_frame_ticks_ + media_frame->timestamp();
      media_frame->metadata().reference_time =
          *first_frame_ticks_ + media_frame->timestamp();
    }
  }
  TRACE_EVENT(
      "media", "FrameQueueUnderlyingSource::MakeBlinkFrame", "ts",
      media_frame->timestamp(), "rt",
      media_frame->metadata().reference_time.value_or(base::TimeTicks()), "cbt",
      media_frame->metadata().capture_begin_time.value_or(base::TimeTicks()));
  return MakeGarbageCollected<VideoFrame>(
      std::move(media_frame), GetExecutionContext(), device_id_,
      /*sk_image=*/nullptr,
      /*prefer_capture_timestamp=*/
      base::FeatureList::IsEnabled(
          kBreakoutBoxPreferCaptureTimestampInVideoFrames));
}

template <>
ScriptWrappable*
FrameQueueUnderlyingSource<scoped_refptr<media::AudioBuffer>>::MakeBlinkFrame(
    scoped_refptr<media::AudioBuffer> media_frame) {
  DCHECK(realm_task_runner_->RunsTasksInCurrentSequence());
  return MakeGarbageCollected<AudioData>(std::move(media_frame));
}

template <>
bool FrameQueueUnderlyingSource<
    scoped_refptr<media::AudioBuffer>>::MustUseMonitor() const {
  return false;
}

template class MODULES_TEMPLATE_EXPORT
    FrameQueueUnderlyingSource<scoped_refptr<media::AudioBuffer>>;
template class MODULES_TEMPLATE_EXPORT
    FrameQueueUnderlyingSource<scoped_refptr<media::VideoFrame>>;

}  // namespace blink

"""

```