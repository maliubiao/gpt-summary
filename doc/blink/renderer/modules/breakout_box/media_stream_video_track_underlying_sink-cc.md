Response:
Let's break down the thought process to analyze the C++ code and generate the explanation.

1. **Understand the Goal:** The request is to explain the functionality of the given C++ file (`media_stream_video_track_underlying_sink.cc`) within the Chromium Blink engine. The explanation should cover its purpose, relation to web technologies (JavaScript, HTML, CSS), logical reasoning with examples, common usage errors, and debugging clues related to user actions.

2. **Identify Key Components and Classes:**  The first step is to scan the code for the main class being defined. Here, it's clearly `MediaStreamVideoTrackUnderlyingSink`. We also note related classes and concepts:

    * `PushableMediaStreamVideoSource::Broker`:  This suggests an interaction with a video source. The "Broker" likely handles communication and control.
    * `VideoFrame`: This is central to the file's purpose – processing video frames. We see `blink::VideoFrame` and `media::VideoFrame`, implying some translation or interaction between Blink's representation and the lower-level media library's representation.
    * `WritableStreamDefaultController`: This points to the integration with the WHATWG Streams API.
    * `gpu::GpuMemoryBufferManager`:  GPU involvement for efficient memory management and potentially hardware acceleration.
    * `WebGraphicsContext3DVideoFramePool`: A pool for managing video frames in a GPU context, suggesting optimization.
    * Feature flags (`BASE_FEATURE`):  These indicate configurable behavior and experimental features. We should note their purpose.
    * `WritableStreamTransferringOptimizer`:  Related to optimizing data transfer within streams, potentially for worker threads.

3. **Determine the Primary Functionality:** Based on the class name and the methods (`start`, `write`, `abort`, `close`), it's evident this class acts as a *sink* for video frames within a `WritableStream`. This sink is specifically designed for media stream video tracks. The name "UnderlyingSink" suggests it's a lower-level implementation detail.

4. **Analyze Key Methods:**

    * `start()`:  Likely initializes the sink and connects it to the video source.
    * `write()`: The core function. It receives video frames (as `blink::VideoFrame`), likely converts them to a suitable internal format (`media::VideoFrame`), and then sends them to the `source_broker_`. The presence of `MaybeConvertToNV12GMBVideoFrame` is crucial and signals potential format conversion for optimization. The closing of the JavaScript `video_frame` is important to note for potential resource management implications.
    * `abort()` and `close()`:  Methods to terminate the stream.
    * `GetTransferringOptimizer()`:  Facilitates moving the sink's functionality to a worker thread.
    * `MaybeConvertToNV12GMBVideoFrame()` and `ConvertDone()`:  These handle the asynchronous conversion of video frames to the NV12 format using GPU memory buffers. The logic involving feature flags and checks for GPU support is important.

5. **Relate to Web Technologies:**

    * **JavaScript:** The `write()` method takes a `ScriptValue` representing a `VideoFrame`, which directly ties into the JavaScript `VideoFrame` API. This is how JavaScript code provides video data to the sink. The `WritableStream` API itself is a JavaScript concept.
    * **HTML:**  While this C++ code doesn't directly manipulate HTML, it's part of the pipeline that handles video from sources like `<video>` elements (via `captureStream()`), `<canvas>` elements (via `captureStream()`), or the `getUserMedia()` API, which are all HTML-related.
    * **CSS:** CSS doesn't directly interact with this code. However, CSS styling can affect the dimensions or visibility of video elements, which ultimately influence the video frames processed by this sink.

6. **Identify Logical Reasoning and Examples:**

    * **Format Conversion:**  The logic in `MaybeConvertToNV12GMBVideoFrame` is a key example of logical reasoning. It decides whether to convert a frame based on its format, GPU support, and sink preferences (via feature flags and broker signals). We can create hypothetical inputs (an RGB frame, a NV12 frame) and trace the execution to see the output.
    * **Capture Timestamp:** The logic related to `kBreakoutBoxWriteVideoFrameCaptureTimestamp` and how it infers whether to set the capture time based on timestamp differences is another example.

7. **Consider Common Usage Errors:**

    * **Closed Stream:**  Calling `write()` after the stream is closed is a common error. The code explicitly checks for this.
    * **Incorrect Frame Type:** Passing something other than a valid `VideoFrame` to `write()` will cause an error.
    * **Resource Leaks (indirectly):**  If the JavaScript `VideoFrame` isn't closed (though the C++ code handles this), it could lead to resource issues.

8. **Trace User Actions for Debugging:**  Think about the steps a user might take to end up using this code:

    * A user opens a web page.
    * The JavaScript code on the page obtains a video stream (e.g., from a camera or a `<canvas>` element).
    * The JavaScript code creates a `WritableStream` and gets its `WritableStreamDefaultWriter`.
    * The JavaScript code pipes the video stream to the writable stream's sink. This is where the `MediaStreamVideoTrackUnderlyingSink` comes into play.
    * The JavaScript code then uses the writer to write `VideoFrame` objects to the sink.

9. **Structure the Explanation:**  Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logical Reasoning, Usage Errors, and Debugging Clues. Use clear and concise language. Provide code snippets where helpful (though in this case, the provided code is the basis). Use bullet points and formatting to improve readability.

10. **Review and Refine:** Read through the explanation to ensure accuracy, clarity, and completeness. Check for any jargon that might need further explanation. Ensure the examples are helpful and the debugging steps are logical. For example, initially, I might have focused too much on the GPU details without clearly explaining the overall purpose as a `WritableStream` sink. Reviewing helps to correct such imbalances.
这个C++文件 `media_stream_video_track_underlying_sink.cc` 是 Chromium Blink 渲染引擎中 `breakout_box` 模块的一部分，主要功能是**作为视频帧数据的底层接收器 (Underlying Sink)，连接 JavaScript 中的 `WritableStream` 和底层的媒体管道 (Media Pipeline)**。  它负责接收来自 JavaScript 的 `VideoFrame` 对象，并将其传递给 Chromium 的媒体框架进行处理。

以下是该文件的功能详细说明：

**核心功能:**

1. **接收来自 JavaScript 的 VideoFrame:**  `MediaStreamVideoTrackUnderlyingSink` 实现了 `WritableStreamSink` 接口，特别是 `write()` 方法。这个方法接收来自 JavaScript `WritableStream` 的 `VideoFrame` 对象。这些 `VideoFrame` 通常是通过 `captureStream()` 方法从 HTML `<video>` 或 `<canvas>` 元素获取，或者由 JavaScript 代码创建（例如使用 WebCodecs API）。

2. **将 VideoFrame 传递给媒体管道:**  接收到的 `blink::VideoFrame` 对象会被转换为底层的 `media::VideoFrame` 对象，并通过 `PushableMediaStreamVideoSource::Broker` 传递给 Chromium 的媒体管道。这个 Broker 负责将帧数据进一步传递给视频编码器、解码器或其他媒体处理模块。

3. **管理资源和生命周期:**  该 Sink 负责管理与其关联的资源，例如在 `start()` 方法中通知 Broker 客户端已启动，在 `abort()` 和 `close()` 方法中断开连接，并在析构函数中清理资源。

4. **可选的 GPU 加速帧转换:** 文件中包含将接收到的 RGB 格式的视频帧转换为 NV12 格式的逻辑，并使用 GPU Memory Buffer (GMB) 进行存储。这可以提高视频处理的效率，尤其是在需要硬件编码的情况下。这个转换过程受一些 Feature Flags 控制，例如 `kBreakoutBoxEagerConversion` 和 `kBreakoutBoxConversionWithoutSinkSignal`。

5. **优化跨线程数据传输:**  使用了 `WritableStreamTransferringOptimizer`，允许在 Worker 线程中创建和使用这个 Sink，从而将视频处理操作移出主线程，提高应用的响应性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **连接 `WritableStream`:**  JavaScript 代码会创建一个 `WritableStream`，并将 `MediaStreamVideoTrackUnderlyingSink` 作为该流的 sink。
        ```javascript
        const videoTrack = /* ... 获取 MediaStreamTrack ... */;
        const writableStream = new WritableStream({
          start(controller) {
            // 这里不会直接创建 MediaStreamVideoTrackUnderlyingSink，
            // 而是通过 Chromium 内部机制关联
          },
          write(chunk, controller) {
            // chunk 就是 VideoFrame 对象
          },
          close() {},
          abort(reason) {}
        });

        // 获取 writableStream 的 sink，这会触发底层创建 MediaStreamVideoTrackUnderlyingSink
        const sink = writableStream.getWriter();

        // 从 VideoTrack 获取帧数据，并写入 writableStream
        const reader = videoTrack.getReader();
        async function pump() {
          while (true) {
            const { done, value } = await reader.read();
            if (done) {
              sink.close();
              break;
            }
            await sink.write(value); // 将 VideoFrame 传递给 C++ Sink
          }
        }
        pump();
        ```
    * **传递 `VideoFrame` 对象:**  JavaScript 代码使用 `sink.write(videoFrame)` 将 `VideoFrame` 对象传递给 C++ 的 `write()` 方法。这个 `VideoFrame` 对象可能来自 `<video>.captureStream()` 或 WebCodecs API。
        ```javascript
        const videoElement = document.getElementById('myVideo');
        const stream = videoElement.captureStream();
        const videoTrack = stream.getVideoTracks()[0];
        const reader = videoTrack.getReader();
        const writableStream = new WritableStream({
          // ...
        });
        const writer = writableStream.getWriter();

        async function pumpFrames() {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            await writer.write(value); // value 是一个 VideoFrame 对象
          }
        }
        pumpFrames();
        ```

* **HTML:**
    * **`<video>` 和 `<canvas>` 元素:**  通常，`MediaStreamVideoTrackUnderlyingSink` 处理的视频帧数据来源于 HTML 的 `<video>` 或 `<canvas>` 元素，通过 `captureStream()` 方法捕获。
        ```html
        <video id="myVideo" src="my-video.mp4"></video>
        <canvas id="myCanvas"></canvas>
        <script>
          const video = document.getElementById('myVideo');
          const videoStream = video.captureStream();
          const canvas = document.getElementById('myCanvas');
          const canvasStream = canvas.captureStream();
        </script>
        ```

* **CSS:**
    * **无直接关系:** CSS 主要负责样式和布局，与 `MediaStreamVideoTrackUnderlyingSink` 的功能没有直接的交互。但是，CSS 可能会影响 `<video>` 或 `<canvas>` 元素的渲染，从而间接影响捕获到的视频帧。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码通过 `captureStream()` 获取了一个 640x480 的 RGB 格式的视频帧，并将其作为 `VideoFrame` 对象传递给 `writableStream.getWriter().write(videoFrame)`。

* **假设输入:**  一个 `blink::VideoFrame` 对象，其内部包含了 640x480 的 RGB 视频帧数据，可能带有时间戳等元数据。
* **逻辑:** `MediaStreamVideoTrackUnderlyingSink::write()` 方法被调用，接收该 `blink::VideoFrame`。
    * 如果启用了 `kBreakoutBoxEagerConversion` 且满足转换条件（例如，GPU 支持 GMB 纹理读取，Broker 允许丢弃 Alpha 通道等），则尝试将 RGB 帧转换为 NV12 格式的 GMB 支持的帧。
    * 无论是否转换，最终都会将底层的 `media::VideoFrame` 对象通过 `source_broker_->PushFrame()` 传递给媒体管道。
* **假设输出:**  一个 `media::VideoFrame` 对象被成功传递到媒体管道。这个 `media::VideoFrame` 对象可能保持了原始的 RGB 格式，也可能被转换成了 NV12 格式，具体取决于 Feature Flags 和系统配置。同时，JavaScript 传递的 `blink::VideoFrame` 会被 `close()`，释放其持有的资源。

**用户或编程常见的使用错误:**

1. **在流关闭后尝试写入:**  如果 `WritableStream` 已经关闭或中止，JavaScript 代码仍然尝试调用 `writer.write()`，会导致错误。
    ```javascript
    const writer = writableStream.getWriter();
    writer.close();
    writer.write(someVideoFrame); // 错误：流已关闭
    ```
    **错误表现:** C++ 代码中 `source_broker_->IsRunning()` 返回 `false`，抛出 `DOMExceptionCode::kInvalidStateError`。

2. **传递无效的 `VideoFrame`:**  传递 `null` 或已关闭的 `VideoFrame` 对象给 `writer.write()`。
    ```javascript
    writer.write(null); // 错误：传递了 null
    const videoFrame = new VideoFrame(/* ... */);
    videoFrame.close();
    writer.write(videoFrame); // 错误：传递了已关闭的 VideoFrame
    ```
    **错误表现:** C++ 代码中 `V8VideoFrame::ToWrappable()` 返回 `nullptr`，抛出 `TypeError`。

3. **资源泄漏 (间接):** 虽然 C++ 代码会 `close()` JavaScript 传递的 `blink::VideoFrame` 来避免泄漏，但如果 JavaScript 代码没有正确管理 `VideoFrame` 的生命周期，可能会导致资源问题。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户打开一个包含视频或画布的网页:** 网页可能包含 `<video>` 元素播放视频，或者使用 `<canvas>` 元素进行动画或视频处理。

2. **网页 JavaScript 代码获取视频流:**  JavaScript 代码调用 `videoElement.captureStream()` 或 `canvasElement.captureStream()` 方法，从 HTML 元素获取 `MediaStream` 对象。

3. **创建 `WritableStream` 并连接到视频流:** JavaScript 代码创建一个 `WritableStream`，并可能将其 `sink` 连接到视频流的 `track`。  更常见的是，直接将视频 track 的 reader 的输出管道传输到 writable stream 的 writer。

4. **开始从视频流读取帧数据并写入 `WritableStream`:** JavaScript 代码使用 `MediaStreamTrack.getReader()` 获取帧读取器，然后循环读取帧数据，并将读取到的 `VideoFrame` 对象通过 `writableStream.getWriter().write(videoFrame)` 写入 `WritableStream`。

5. **`writableStream.getWriter().write(videoFrame)` 调用触发 C++ 代码:**  JavaScript 的 `write()` 操作最终会调用到 `MediaStreamVideoTrackUnderlyingSink::write()` 方法，将 `VideoFrame` 数据传递给 C++ 层处理。

**调试线索:**

* **检查 JavaScript 代码中 `captureStream()` 的使用:** 确认是否正确获取了视频流。
* **检查 `WritableStream` 的创建和连接:** 确认 `WritableStream` 的 `sink` 是否正确配置。
* **在 JavaScript 中检查 `writer.write()` 的调用:** 确认是否正确地将 `VideoFrame` 对象传递给了 `WritableStream`。
* **使用 Chrome 的开发者工具 (Performance 面板):**  可以查看视频帧的处理流程，是否有帧丢失或延迟。
* **在 C++ 代码中添加日志:** 在 `MediaStreamVideoTrackUnderlyingSink::write()` 方法中添加 `DLOG` 或 `DVLOG` 输出，查看是否接收到了预期的视频帧数据，以及是否成功传递给媒体管道。
* **检查 Feature Flags:** 确认影响帧转换逻辑的 Feature Flags (如 `kBreakoutBoxEagerConversion`) 是否处于预期的状态。

总而言之，`media_stream_video_track_underlying_sink.cc` 文件在 Chromium 中扮演着连接 JavaScript 视频数据和底层媒体处理的关键角色，它使得 Web 开发者能够利用 `WritableStream` API 将视频帧数据传递到 Chromium 的媒体管道进行进一步处理，例如编码、传输等。

### 提示词
```
这是目录为blink/renderer/modules/breakout_box/media_stream_video_track_underlying_sink.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/breakout_box/media_stream_video_track_underlying_sink.h"

#include "base/feature_list.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/time/time.h"
#include "gpu/command_buffer/client/gpu_memory_buffer_manager.h"
#include "media/base/video_types.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/modules/breakout_box/metrics.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_video_frame_pool.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

// Cannot be in the anonymous namespace because it is friended by
// MainThreadTaskRunnerRestricted.
MainThreadTaskRunnerRestricted AccessMainThreadForGpuMemoryBufferManager() {
  return {};
}

namespace {
// Enables conversion of input frames in RGB format to NV12 GMB-backed format
// if GMB readback from texture is supported.
BASE_FEATURE(kBreakoutBoxEagerConversion,
             "BreakoutBoxEagerConversion",
             base::FEATURE_ENABLED_BY_DEFAULT
);

// If BreakoutBoxEagerConversion is enabled, this feature enables frame
// conversion even if the sinks connected to the track backed by the
// MediaStreamVideoTrackUnderlyingSink have not sent the RequireMappedFrame
// signal.
// This feature has no effect if BreakoutBoxEagerConversion is disabled.
BASE_FEATURE(kBreakoutBoxConversionWithoutSinkSignal,
             "BreakoutBoxConversionWithoutSinkSignal",
             base::FEATURE_ENABLED_BY_DEFAULT);

// If BreakoutBoxWriteVideoFrameCaptureTimestamp is enabled, the timestamp from
// a blink::VideoFrame written to a MediaStreamVideoTrackUnderlyingSink is also
// set as the capture timestamp for its underlying media::VideoFrame.
// TODO(crbug.com/343870500): Remove this feature once WebCodec VideoFrames
// expose the capture time as metadata.
BASE_FEATURE(kBreakoutBoxWriteVideoFrameCaptureTimestamp,
             "BreakoutBoxWriteVideoFrameCaptureTimestamp",
             base::FEATURE_ENABLED_BY_DEFAULT);

class TransferringOptimizer : public WritableStreamTransferringOptimizer {
 public:
  explicit TransferringOptimizer(
      scoped_refptr<PushableMediaStreamVideoSource::Broker> source_broker,
      gpu::GpuMemoryBufferManager* gmb_manager)
      : source_broker_(std::move(source_broker)), gmb_manager_(gmb_manager) {}
  UnderlyingSinkBase* PerformInProcessOptimization(
      ScriptState* script_state) override {
    RecordBreakoutBoxUsage(BreakoutBoxUsage::kWritableVideoWorker);
    return MakeGarbageCollected<MediaStreamVideoTrackUnderlyingSink>(
        source_broker_, gmb_manager_);
  }

 private:
  const scoped_refptr<PushableMediaStreamVideoSource::Broker> source_broker_;
  const raw_ptr<gpu::GpuMemoryBufferManager> gmb_manager_ = nullptr;
};

gpu::GpuMemoryBufferManager* GetGmbManager() {
  if (!WebGraphicsContext3DVideoFramePool::
          IsGpuMemoryBufferReadbackFromTextureEnabled()) {
    return nullptr;
  }
  gpu::GpuMemoryBufferManager* gmb_manager = nullptr;
  if (IsMainThread()) {
    gmb_manager = Platform::Current()->GetGpuMemoryBufferManager();
  } else {
    // Get the GPU Buffer Manager by jumping to the main thread and blocking.
    // The purpose of blocking is to have the manager available by the time
    // the first frame arrives. This ensures all frames can be converted to
    // the appropriate format, which helps prevent a WebRTC sink from falling
    // back to software encoding due to frames in formats the hardware encoder
    // cannot handle.
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *Thread::MainThread()->GetTaskRunner(
            AccessMainThreadForGpuMemoryBufferManager()),
        FROM_HERE,
        CrossThreadBindOnce(
            [](base::WaitableEvent* event,
               gpu::GpuMemoryBufferManager** gmb_manager_ptr) {
              *gmb_manager_ptr =
                  Platform::Current()->GetGpuMemoryBufferManager();
              event->Signal();
            },
            CrossThreadUnretained(&waitable_event),
            CrossThreadUnretained(&gmb_manager)));
    waitable_event.Wait();
  }
  return gmb_manager;
}

}  // namespace

MediaStreamVideoTrackUnderlyingSink::MediaStreamVideoTrackUnderlyingSink(
    scoped_refptr<PushableMediaStreamVideoSource::Broker> source_broker,
    gpu::GpuMemoryBufferManager* gmb_manager)
    : source_broker_(std::move(source_broker)), gmb_manager_(gmb_manager) {
  RecordBreakoutBoxUsage(BreakoutBoxUsage::kWritableVideo);
}

MediaStreamVideoTrackUnderlyingSink::MediaStreamVideoTrackUnderlyingSink(
    scoped_refptr<PushableMediaStreamVideoSource::Broker> source_broker)
    : MediaStreamVideoTrackUnderlyingSink(std::move(source_broker),
                                          GetGmbManager()) {}

MediaStreamVideoTrackUnderlyingSink::~MediaStreamVideoTrackUnderlyingSink() =
    default;

ScriptPromise<IDLUndefined> MediaStreamVideoTrackUnderlyingSink::start(
    ScriptState* script_state,
    WritableStreamDefaultController* controller,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  source_broker_->OnClientStarted();
  is_connected_ = true;
  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> MediaStreamVideoTrackUnderlyingSink::write(
    ScriptState* script_state,
    ScriptValue chunk,
    WritableStreamDefaultController* controller,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  VideoFrame* video_frame =
      V8VideoFrame::ToWrappable(script_state->GetIsolate(), chunk.V8Value());
  if (!video_frame) {
    exception_state.ThrowTypeError("Null video frame.");
    return EmptyPromise();
  }

  auto media_frame = video_frame->frame();
  if (!media_frame) {
    exception_state.ThrowTypeError("Empty video frame.");
    return EmptyPromise();
  }

  static const base::TimeDelta kLongDelta = base::Minutes(1);
  base::TimeDelta now = base::TimeTicks::Now() - base::TimeTicks();
  if (base::FeatureList::IsEnabled(
          kBreakoutBoxWriteVideoFrameCaptureTimestamp) &&
      should_try_to_write_capture_time_ &&
      !media_frame->metadata().capture_begin_time && (now > kLongDelta)) {
    // If the difference between now and the frame's timestamp is large,
    // assume the stream is not using capture times as timestamps.
    if ((media_frame->timestamp() - now).magnitude() > kLongDelta) {
      should_try_to_write_capture_time_ = false;
    }

    if (should_try_to_write_capture_time_) {
      media_frame->metadata().capture_begin_time =
          base::TimeTicks() + video_frame->handle()->timestamp();
    }
  }

  // Invalidate the JS |video_frame|. Otherwise, the media frames might not be
  // released, which would leak resources and also cause some MediaStream
  // sources such as cameras to drop frames.
  video_frame->close();

  if (!source_broker_->IsRunning()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Stream closed");
    return EmptyPromise();
  }

  base::TimeTicks estimated_capture_time = base::TimeTicks::Now();

  // Try to convert to an NV12 GpuMemoryBuffer-backed frame if the encoder
  // prefers that format. Unfortunately, for the first few frames, we may not
  // receive feedback from the sink (CanDiscardAlpha and RequireMappedFrame), so
  // those frames will instead be converted immediately before encoding (by
  // WebRtcVideoFrameAdapter).
  auto opt_convert_promise = MaybeConvertToNV12GMBVideoFrame(
      script_state, media_frame, estimated_capture_time);
  if (opt_convert_promise) {
    return *opt_convert_promise;
  }

  source_broker_->PushFrame(std::move(media_frame), estimated_capture_time);

  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> MediaStreamVideoTrackUnderlyingSink::abort(
    ScriptState* script_state,
    ScriptValue reason,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  Disconnect();
  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<IDLUndefined> MediaStreamVideoTrackUnderlyingSink::close(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  Disconnect();
  return ToResolvedUndefinedPromise(script_state);
}

std::unique_ptr<WritableStreamTransferringOptimizer>
MediaStreamVideoTrackUnderlyingSink::GetTransferringOptimizer() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return std::make_unique<TransferringOptimizer>(source_broker_, gmb_manager_);
}

void MediaStreamVideoTrackUnderlyingSink::Disconnect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!is_connected_)
    return;

  source_broker_->OnClientStopped();
  is_connected_ = false;
}

void MediaStreamVideoTrackUnderlyingSink::CreateAcceleratedFramePool(
    gpu::GpuMemoryBufferManager* gmb_manager) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Here we need to use the SharedGpuContext as some of the images may have
  // been originated with other contextProvider, but we internally need a
  // context_provider that has a RasterInterface available.
  auto context_provider = SharedGpuContext::ContextProviderWrapper();
  if (context_provider && gmb_manager) {
    accelerated_frame_pool_ =
        std::make_unique<WebGraphicsContext3DVideoFramePool>(context_provider,
                                                             gmb_manager);
  } else {
    convert_to_nv12_gmb_failure_count_++;
  }
}

std::optional<ScriptPromise<IDLUndefined>>
MediaStreamVideoTrackUnderlyingSink::MaybeConvertToNV12GMBVideoFrame(
    ScriptState* script_state,
    scoped_refptr<media::VideoFrame> video_frame,
    base::TimeTicks estimated_capture_time) {
  static constexpr int kMaxFailures = 5;
  if (convert_to_nv12_gmb_failure_count_ > kMaxFailures) {
    return std::nullopt;
  }
  DCHECK(video_frame);
  auto format = video_frame->format();
  bool frame_is_rgb = (format == media::PIXEL_FORMAT_XBGR ||
                       format == media::PIXEL_FORMAT_ABGR ||
                       format == media::PIXEL_FORMAT_XRGB ||
                       format == media::PIXEL_FORMAT_ARGB);
  bool frame_can_be_converted =
      video_frame->HasSharedImage() &&
      (media::IsOpaque(format) || source_broker_->CanDiscardAlpha());
  bool sink_wants_mapped_frame =
      base::FeatureList::IsEnabled(kBreakoutBoxConversionWithoutSinkSignal) ||
      source_broker_->RequireMappedFrame();

  bool should_eagerly_convert =
      base::FeatureList::IsEnabled(kBreakoutBoxEagerConversion) &&
      WebGraphicsContext3DVideoFramePool::
          IsGpuMemoryBufferReadbackFromTextureEnabled() &&
      frame_is_rgb && frame_can_be_converted && sink_wants_mapped_frame;
  if (!should_eagerly_convert) {
    return std::nullopt;
  }

  if (!accelerated_frame_pool_) {
    gpu::GpuMemoryBufferManager* gmb_manager = GetGmbManager();
    if (!gmb_manager) {
      convert_to_nv12_gmb_failure_count_++;
      return std::nullopt;
    }

    CreateAcceleratedFramePool(gmb_manager);
    if (!accelerated_frame_pool_) {
      convert_to_nv12_gmb_failure_count_++;
      return std::nullopt;
    }
  }
  DCHECK(accelerated_frame_pool_);

  auto resolver = WrapPersistent(
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state));
  auto convert_done_callback = WTF::BindOnce(
      &MediaStreamVideoTrackUnderlyingSink::ConvertDone, WrapPersistent(this),
      resolver, video_frame, estimated_capture_time);
  const bool success = accelerated_frame_pool_->ConvertVideoFrame(
      video_frame, gfx::ColorSpace::CreateREC709(),
      std::move(convert_done_callback));
  if (success) {
    convert_to_nv12_gmb_failure_count_ = 0;
  } else {
    ConvertDone(resolver, video_frame, estimated_capture_time,
                /*converted_video_frame=*/nullptr);
    convert_to_nv12_gmb_failure_count_++;
  }
  return resolver->Promise();
}

void MediaStreamVideoTrackUnderlyingSink::ConvertDone(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    scoped_refptr<media::VideoFrame> orig_video_frame,
    base::TimeTicks estimated_capture_time,
    scoped_refptr<media::VideoFrame> converted_video_frame) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!source_broker_->IsRunning()) {
    // The MediaStreamTrack was stopped while write was pending.
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "Stream closed"));
    return;
  }
  if (converted_video_frame) {
    source_broker_->PushFrame(std::move(converted_video_frame),
                              estimated_capture_time);
  } else {
    source_broker_->PushFrame(std::move(orig_video_frame),
                              estimated_capture_time);
  }
  resolver->Resolve();
}

}  // namespace blink
```