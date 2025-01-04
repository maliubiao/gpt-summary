Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Understand the Goal:** The primary goal is to analyze a C++ test file for a Chromium Blink component and explain its functionality, its relation to web technologies (JavaScript, HTML, CSS), potential user errors, and debugging entry points.

2. **Identify the Core Component:** The file name `media_stream_video_track_underlying_source_test.cc` immediately points to the component being tested: `MediaStreamVideoTrackUnderlyingSource`. The `test.cc` suffix signifies it's a test file.

3. **Examine Includes:** The `#include` directives provide crucial information about the dependencies and the scope of the test. Key inclusions include:
    * The header file for the tested class: `media_stream_video_track_underlying_source.h`.
    * Media-related headers (`media/base/`, `media/capture/`).
    * Testing frameworks (`testing/gtest/`).
    * Blink-specific headers (`public/common/mediastream/`, `public/platform/modules/mediastream/`, `renderer/bindings/`, `renderer/core/`, `renderer/modules/`, `renderer/platform/`).

4. **Analyze the Test Fixture:** The `MediaStreamVideoTrackUnderlyingSourceTest` class, inheriting from `testing::Test`, is the foundation for the tests. Pay attention to its members:
    * `pushable_video_source_`:  This suggests the test setup involves a source that can have video frames pushed into it programmatically.
    * `media_stream_source_`: This is likely the underlying source for the MediaStreamTrack.
    * Helper methods like `CreateTrack`, `CreateSource`, and `PushFrame`. These are used to simplify test setup.

5. **Analyze Individual Tests:**  Go through each `TEST_F` function:
    * **Identify the Scenario:** What specific functionality or behavior is being tested?  The test names are usually good indicators (e.g., `VideoFrameFlowsThroughStreamAndCloses`, `CancelStreamDisconnectsFromTrack`).
    * **Follow the Test Logic:**  Understand the sequence of actions within the test:
        * Setup (creating tracks, sources, streams).
        * Actions (pushing frames, canceling streams, closing resources).
        * Assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`). These verify the expected outcomes.
    * **Look for Interactions:** How does the tested component interact with other parts of the system (e.g., `ReadableStream`, `MediaStreamTrack`, `VideoFrameMonitor`)?

6. **Relate to Web Technologies:** Consider how the tested component and its interactions manifest in the browser and interact with web technologies:
    * **JavaScript:**  Think about how JavaScript APIs like `getUserMedia`, `MediaStreamTrack`, and `ReadableStream` are related. The tests use Blink's internal representations of these concepts.
    * **HTML:**  Consider the `<video>` element and how it consumes media streams.
    * **CSS:** While less directly related for this specific component, think about CSS properties that might affect video rendering or layout.

7. **Identify Logical Inferences and Assumptions:**
    * **Assumptions:** The tests often make assumptions about the state of the system or the behavior of dependencies. For example, the frame limiter test assumes `max_frame_count` is 2.
    * **Inferences:**  Based on the test logic and assertions, infer the expected behavior of the component in various situations.

8. **Consider User/Programming Errors:** Think about common mistakes developers might make when working with media streams or when the underlying implementation might have issues:
    * Not handling stream closure correctly.
    * Issues with backpressure and queue management.
    * Incorrectly managing the lifecycle of media objects.

9. **Trace User Operations (Debugging Clues):** Imagine a user interacting with a web page that uses media streams. How might their actions lead to the execution paths tested in this file?  Consider scenarios like:
    * Granting camera/microphone permissions.
    * Starting/stopping video tracks.
    * Manipulating media streams using JavaScript.
    * Encountering errors during media capture or processing.

10. **Structure the Output:** Organize the findings into clear sections as requested:
    * Functionality Summary.
    * Relationship to JavaScript/HTML/CSS (with examples).
    * Logical Inferences (with input/output examples).
    * Common Errors (with examples).
    * User Operations (debugging clues).

11. **Refine and Elaborate:** Review the initial analysis and add more detail, clarity, and examples. For instance, when discussing the frame limiter, explain *why* it's needed (to manage memory and prevent excessive buffering).

**Self-Correction/Refinement Example during the process:**

* **Initial Thought:** "This test is just about the underlying source."
* **Correction:** "While it focuses on the underlying source, it also tests its interaction with `MediaStreamTrack` and `ReadableStream`. The tests show how data flows from the source through the track to the stream, and how closing or canceling the stream affects the track."

By following these steps, we can systematically analyze the C++ test file and generate a comprehensive explanation of its purpose and relevance.
这个文件 `media_stream_video_track_underlying_source_test.cc` 是 Chromium Blink 引擎中用于测试 `MediaStreamVideoTrackUnderlyingSource` 类的单元测试文件。 `MediaStreamVideoTrackUnderlyingSource`  是连接 `MediaStreamVideoTrack` 和 `ReadableStream` 的桥梁，它作为 `ReadableStream` 的底层数据源，负责从 `MediaStreamVideoTrack` 中获取视频帧数据，并将这些数据推送到 `ReadableStream` 中，供 JavaScript 代码消费。

以下是该文件的详细功能分解：

**主要功能：**

1. **测试 `MediaStreamVideoTrackUnderlyingSource` 的基本数据流：** 验证视频帧能否从 `MediaStreamVideoTrack` 正确地传递到由 `MediaStreamVideoTrackUnderlyingSource` 作为底层源的 `ReadableStream` 中。
2. **测试 `MediaStreamVideoTrackUnderlyingSource` 的生命周期管理：**  验证当 `ReadableStream` 被关闭或取消时，`MediaStreamVideoTrackUnderlyingSource` 是否能正确地断开与 `MediaStreamVideoTrack` 的连接，避免资源泄露。
3. **测试缓冲机制：** 验证当 `ReadableStream` 的读取速度慢于 `MediaStreamVideoTrack` 产生数据的速度时，`MediaStreamVideoTrackUnderlyingSource` 的缓冲行为，例如当队列满时丢弃旧帧。
4. **测试资源清理和垃圾回收：** 验证在不同的生命周期场景下，例如 `ExecutionContext` 被销毁后，`MediaStreamVideoTrackUnderlyingSource` 是否能正确地释放资源。
5. **测试设备监控相关的逻辑：** 验证对于某些类型的视频源（例如摄像头、屏幕共享），`MediaStreamVideoTrackUnderlyingSource` 如何获取设备 ID 和最大帧数用于监控。
6. **测试帧限制器（Frame Limiter）：** 验证当启用帧监控时，`MediaStreamVideoTrackUnderlyingSource` 如何限制流入 `ReadableStream` 的帧数，以避免过度占用内存。
7. **测试时间戳处理：** 验证 `MediaStreamVideoTrackUnderlyingSource` 如何处理视频帧中的时间戳，优先使用捕获时间戳。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件虽然是底层实现，但它直接关系到 Web API 中的 `MediaStreamTrack` 和 `ReadableStream`。

* **JavaScript `MediaStreamTrack`:**  JavaScript 代码可以通过 `getUserMedia()` 等 API 获取 `MediaStreamTrack` 对象，代表一个音视频轨道。`MediaStreamVideoTrackUnderlyingSource` 负责从这个轨道的底层实现 (`MediaStreamVideoTrack`) 中获取视频数据。
    * **示例：** JavaScript 代码可以使用 `track.getReader()` 获取一个 `ReadableStreamDefaultReader` 来读取视频帧数据，而这个 `ReadableStream` 的底层源就是 `MediaStreamVideoTrackUnderlyingSource`。

* **JavaScript `ReadableStream`:**  `ReadableStream` 是 JavaScript 中用于处理异步数据流的标准 API。通过将 `MediaStreamVideoTrackUnderlyingSource` 作为底层源，可以将视频帧数据以流的形式提供给 JavaScript 代码。
    * **示例：**
      ```javascript
      navigator.mediaDevices.getUserMedia({ video: true })
        .then(stream => {
          const videoTrack = stream.getVideoTracks()[0];
          const reader = videoTrack.getReader(); // 这里内部会创建基于 MediaStreamVideoTrackUnderlyingSource 的 ReadableStream
          function readFrame() {
            reader.read().then(({ done, value }) => {
              if (done) {
                console.log("Stream finished");
                return;
              }
              // value 是一个 VideoFrame 对象，包含了视频帧数据
              console.log("Received a video frame", value);
              readFrame();
            });
          }
          readFrame();
        });
      ```

* **HTML `<video>` 元素：**  虽然这个文件本身不直接操作 HTML 元素，但通过 JavaScript 获取的 `MediaStreamTrack` 可以赋值给 `<video>` 元素的 `srcObject` 属性来播放视频。 `MediaStreamVideoTrackUnderlyingSource` 负责将视频数据传递到渲染流水线，最终显示在 `<video>` 元素中。
    * **示例：**
      ```html
      <video id="myVideo" autoplay></video>
      <script>
        navigator.mediaDevices.getUserMedia({ video: true })
          .then(stream => {
            const video = document.getElementById('myVideo');
            video.srcObject = stream;
          });
      </script>
      ```

* **CSS：** CSS 可以用来控制 `<video>` 元素的样式，例如大小、位置等，但与 `MediaStreamVideoTrackUnderlyingSource` 的功能没有直接关系。

**逻辑推理和假设输入/输出：**

**测试用例：`VideoFrameFlowsThroughStreamAndCloses`**

* **假设输入：**
    1. 创建一个 `PushableMediaStreamVideoSource` 作为视频源。
    2. 基于该源创建一个 `MediaStreamTrack`。
    3. 基于该 `MediaStreamTrack` 创建一个 `MediaStreamVideoTrackUnderlyingSource`。
    4. 基于该 `MediaStreamVideoTrackUnderlyingSource` 创建一个 `ReadableStream`。
    5. 向 `PushableMediaStreamVideoSource` 推送一个视频帧。
* **预期输出：**
    1. `ReadableStream` 的 `reader.read()` Promise 会 resolve，返回包含推送的视频帧数据的 `VideoFrame` 对象。
    2. 当 `MediaStreamVideoTrackUnderlyingSource` 被关闭后，`ReadableStream` 也会关闭。

**测试用例：`DropOldFramesWhenQueueIsFull`**

* **假设输入：**
    1. 创建一个 `MediaStreamVideoTrackUnderlyingSource`，并设置较小的缓冲区大小（例如 5）。
    2. 连续推送多于缓冲区大小的视频帧。
* **预期输出：**
    1. 当读取 `ReadableStream` 时，最早推送的帧会被丢弃，只有最新的缓冲区大小数量的帧会被读取到。

**用户或编程常见的使用错误：**

1. **忘记关闭 `ReadableStream` 或其 reader：** 如果 JavaScript 代码获取了 `ReadableStream` 的 reader，但忘记在不再需要时关闭它，可能会导致 `MediaStreamVideoTrackUnderlyingSource` 无法及时断开与 `MediaStreamTrack` 的连接，造成资源占用。
    * **示例：**  一个 `readFrame` 的循环没有 `break` 或 `return` 条件，导致一直尝试读取数据。
2. **假设 `ReadableStream` 会无限缓存数据：**  开发者可能会错误地认为 `ReadableStream` 会缓存所有推送的数据，而没有考虑到底层源的缓冲限制。当读取速度慢于推送速度时，可能会丢失数据。
3. **错误地管理 `VideoFrame` 对象的生命周期：** 从 `ReadableStream` 读取到的 `VideoFrame` 对象需要在使用完毕后调用 `close()` 方法释放底层资源。忘记调用 `close()` 会导致内存泄漏，尤其是在高帧率的情况下。
    * **示例：**  从 `reader.read()` 获取 `value` 后直接使用，但没有在合适的时机调用 `value.close()`。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户打开一个使用摄像头或屏幕共享的网页。**
2. **网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 或 `navigator.mediaDevices.getDisplayMedia()` 获取一个 `MediaStream`。**
3. **从 `MediaStream` 中获取视频轨道 `MediaStreamTrack`。**
4. **网页代码可能通过 `track.getReader()` 获取一个 `ReadableStream` 来处理视频帧数据。**  此时，Blink 内部会创建 `MediaStreamVideoTrackUnderlyingSource` 对象作为该 `ReadableStream` 的底层源。
5. **摄像头或屏幕开始捕获视频帧，这些帧被传递到 `MediaStreamVideoTrack`。**
6. **`MediaStreamVideoTrackUnderlyingSource` 从 `MediaStreamVideoTrack` 中拉取视频帧。**
7. **`MediaStreamVideoTrackUnderlyingSource` 将视频帧数据推送到 `ReadableStream` 的队列中。**
8. **JavaScript 代码通过 `reader.read()` 从 `ReadableStream` 中消费视频帧数据。**

**调试线索：**

如果在浏览器开发过程中遇到与视频流处理相关的问题，例如：

* **视频帧数据丢失：** 可以检查 `MediaStreamVideoTrackUnderlyingSource` 的缓冲大小和丢帧逻辑。
* **内存泄漏：** 可以检查 `VideoFrame` 对象的生命周期管理，是否正确调用了 `close()` 方法，以及 `MediaStreamVideoTrackUnderlyingSource` 是否正确断开了与 `MediaStreamTrack` 的连接。
* **视频流无法正常启动或关闭：** 可以检查 `MediaStreamVideoTrackUnderlyingSource` 的启动和关闭逻辑，以及与 `MediaStreamTrack` 的连接状态。

这个测试文件提供了一系列针对 `MediaStreamVideoTrackUnderlyingSource` 关键功能的测试用例，可以帮助开发者理解其内部工作原理，并为调试相关问题提供线索。通过分析这些测试用例，可以了解在各种场景下 `MediaStreamVideoTrackUnderlyingSource` 的行为和预期结果。

Prompt: 
```
这是目录为blink/renderer/modules/breakout_box/media_stream_video_track_underlying_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/breakout_box/media_stream_video_track_underlying_source.h"

#include <optional>

#include "base/feature_list.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "base/time/time.h"
#include "media/base/video_frame_metadata.h"
#include "media/capture/video/video_capture_buffer_pool_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/mediastream/media_stream_request.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/modules/breakout_box/pushable_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/breakout_box/stream_test_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_monitor.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"

using testing::_;

namespace blink {

class MediaStreamVideoTrackUnderlyingSourceTest : public testing::Test {
 public:
  MediaStreamVideoTrackUnderlyingSourceTest()
      : pushable_video_source_(new PushableMediaStreamVideoSource(
            scheduler::GetSingleThreadTaskRunnerForTesting())),
        media_stream_source_(MakeGarbageCollected<MediaStreamSource>(
            "dummy_source_id",
            MediaStreamSource::kTypeVideo,
            "dummy_source_name",
            false /* remote */,
            base::WrapUnique(pushable_video_source_.get()))) {}

  ~MediaStreamVideoTrackUnderlyingSourceTest() override {
    RunIOUntilIdle();
    WebHeap::CollectAllGarbageForTesting();
  }

  MediaStreamTrack* CreateTrack(ExecutionContext* execution_context) {
    return MakeGarbageCollected<MediaStreamTrackImpl>(
        execution_context,
        MediaStreamVideoTrack::CreateVideoTrack(
            pushable_video_source_,
            MediaStreamVideoSource::ConstraintsOnceCallback(),
            /*enabled=*/true));
  }

  MediaStreamVideoTrackUnderlyingSource* CreateSource(ScriptState* script_state,
                                                      MediaStreamTrack* track,
                                                      wtf_size_t buffer_size) {
    return MakeGarbageCollected<MediaStreamVideoTrackUnderlyingSource>(
        script_state, track->Component(), nullptr, buffer_size);
  }

  MediaStreamVideoTrackUnderlyingSource* CreateSource(ScriptState* script_state,
                                                      MediaStreamTrack* track) {
    return CreateSource(script_state, track, 1u);
  }

 private:
  void RunIOUntilIdle() const {
    // Make sure that tasks on IO thread are completed before moving on.
    base::RunLoop run_loop;
    Platform::Current()->GetIOTaskRunner()->PostTaskAndReply(
        FROM_HERE, base::BindOnce([] {}), run_loop.QuitClosure());
    run_loop.Run();
    base::RunLoop().RunUntilIdle();
  }

 protected:
  void PushFrame(
      const std::optional<base::TimeDelta>& timestamp = std::nullopt) {
    const scoped_refptr<media::VideoFrame> frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(10, 5));
    if (timestamp) {
      frame->set_timestamp(*timestamp);
    }
    pushable_video_source_->PushFrame(frame, base::TimeTicks());
    RunIOUntilIdle();
  }

  static MediaStreamSource* CreateDevicePushableSource(
      const std::string& device_id) {
    auto pushable_video_source =
        std::make_unique<PushableMediaStreamVideoSource>(
            scheduler::GetSingleThreadTaskRunnerForTesting());
    PushableMediaStreamVideoSource* pushable_video_source_ptr =
        pushable_video_source.get();
    auto* media_stream_source = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        false /* remote */, std::move(pushable_video_source));
    MediaStreamDevice device(mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE,
                             device_id, "My window device");
    pushable_video_source_ptr->SetDevice(device);

    return media_stream_source;
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  const raw_ptr<PushableMediaStreamVideoSource> pushable_video_source_;
  const Persistent<MediaStreamSource> media_stream_source_;
};

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest,
       VideoFrameFlowsThroughStreamAndCloses) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(script_state, track);
  auto* stream =
      ReadableStream::CreateWithCountQueueingStrategy(script_state, source, 0);

  NonThrowableExceptionState exception_state;
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, exception_state);

  ScriptPromiseTester read_tester(script_state,
                                  reader->read(script_state, exception_state));
  EXPECT_FALSE(read_tester.IsFulfilled());
  PushFrame();
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsFulfilled());

  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest,
       CancelStreamDisconnectsFromTrack) {
  V8TestingScope v8_scope;
  MediaStreamTrack* track = CreateTrack(v8_scope.GetExecutionContext());
  MediaStreamVideoTrack* video_track =
      MediaStreamVideoTrack::From(track->Component());
  // Initially the track has no sinks.
  EXPECT_EQ(video_track->CountSinks(), 0u);

  auto* source = CreateSource(v8_scope.GetScriptState(), track);
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      v8_scope.GetScriptState(), source, 0);

  // The stream is a sink to the track.
  EXPECT_EQ(video_track->CountSinks(), 1u);

  NonThrowableExceptionState exception_state;
  stream->cancel(v8_scope.GetScriptState(), exception_state);

  // Canceling the stream disconnects it from the track.
  EXPECT_EQ(video_track->CountSinks(), 0u);
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest,
       DropOldFramesWhenQueueIsFull) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  const wtf_size_t buffer_size = 5;
  auto* source = CreateSource(script_state, track, buffer_size);
  EXPECT_EQ(source->MaxQueueSize(), buffer_size);
  auto* stream =
      ReadableStream::CreateWithCountQueueingStrategy(script_state, source, 0);

  // Add a sink to the track to make it possible to wait until a pushed frame
  // is delivered to sinks, including |source|, which is a sink of the track.
  MockMediaStreamVideoSink mock_sink;
  mock_sink.ConnectToTrack(WebMediaStreamTrack(source->Track()));
  auto push_frame_sync = [&mock_sink, this](const base::TimeDelta timestamp) {
    base::RunLoop sink_loop;
    EXPECT_CALL(mock_sink, OnVideoFrame(_))
        .WillOnce(base::test::RunOnceClosure(sink_loop.QuitClosure()));
    PushFrame(timestamp);
    sink_loop.Run();
  };

  for (wtf_size_t i = 0; i < buffer_size; ++i) {
    base::TimeDelta timestamp = base::Seconds(i);
    push_frame_sync(timestamp);
  }

  // Push another frame while the queue is full.
  // EXPECT_EQ(queue.size(), buffer_size);
  push_frame_sync(base::Seconds(buffer_size));

  // Since the queue was full, the oldest frame from the queue (timestamp 0)
  // should have been dropped.
  NonThrowableExceptionState exception_state;
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, exception_state);
  for (wtf_size_t i = 1; i <= buffer_size; ++i) {
    VideoFrame* video_frame =
        ReadObjectFromStream<VideoFrame>(v8_scope, reader);
    EXPECT_EQ(video_frame->frame()->timestamp(), base::Seconds(i));
  }

  // Pulling causes a pending pull since there are no frames available for
  // reading.
  EXPECT_EQ(source->NumPendingPullsForTesting(), 0);
  source->Pull(script_state, ASSERT_NO_EXCEPTION);
  EXPECT_EQ(source->NumPendingPullsForTesting(), 1);

  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest, QueueSizeCannotBeZero) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(script_state, track, 0u);
  // Queue size is always at least 1, even if 0 is requested.
  EXPECT_EQ(source->MaxQueueSize(), 1u);
  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest, PlatformSourceAliveAfterGC) {
  Persistent<MediaStreamComponent> component;
  {
    V8TestingScope v8_scope;
    auto* track = CreateTrack(v8_scope.GetExecutionContext());
    component = track->Component();
    auto* source = CreateSource(v8_scope.GetScriptState(), track, 0u);
    ReadableStream::CreateWithCountQueueingStrategy(v8_scope.GetScriptState(),
                                                    source, 0);
    // |source| is a sink of |track|.
    EXPECT_TRUE(source->Track());
  }
  blink::WebHeap::CollectAllGarbageForTesting();
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest, CloseOnContextDestroyed) {
  MediaStreamVideoTrackUnderlyingSource* source = nullptr;
  {
    V8TestingScope v8_scope;
    ScriptState* script_state = v8_scope.GetScriptState();
    auto* track = CreateTrack(v8_scope.GetExecutionContext());
    source = CreateSource(script_state, track, 0u);
    EXPECT_FALSE(source->IsClosed());
    // Create a stream so that |source| starts.
    auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
        v8_scope.GetScriptState(), source, 0);
    EXPECT_FALSE(source->IsClosed());
    EXPECT_FALSE(stream->IsClosed());
  }
  EXPECT_TRUE(source->IsClosed());
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest, CloseBeforeStart) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(script_state, track, 0u);
  EXPECT_FALSE(source->IsClosed());
  source->Close();
  EXPECT_TRUE(source->IsClosed());
  // Create a stream so that the start method of |source| runs.
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      v8_scope.GetScriptState(), source, 0);
  EXPECT_TRUE(source->IsClosed());
  EXPECT_TRUE(stream->IsClosed());
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest,
       DeviceIdAndMaxFrameCountForMonitoring) {
  using M = MediaStreamVideoTrackUnderlyingSource;
  const std::string window_id = "window:a-window";
  const std::string screen_id = "screen:a-screen";
  const std::string tab_id = "web-contents-media-stream://5:1";
  const std::string camera_id = "my-camera";
  const std::string mic_id = "my-mic";

  MediaStreamDevice device;
  device.type = mojom::MediaStreamType::NO_SERVICE;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);

  device.id = mic_id;
  device.type = mojom::MediaStreamType::DEVICE_AUDIO_CAPTURE;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);

  device.id = tab_id;
  device.type = mojom::MediaStreamType::GUM_TAB_AUDIO_CAPTURE;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);
  device.type = mojom::MediaStreamType::GUM_TAB_VIDEO_CAPTURE;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);

  device.type = mojom::MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE;
  device.id = screen_id;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);
  device.id = window_id;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);

  device.type = mojom::MediaStreamType::DISPLAY_AUDIO_CAPTURE;
  device.id = screen_id;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);
  device.id = window_id;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);
  device.id = tab_id;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);

  device.type = mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE_THIS_TAB;
  device.id = tab_id;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);

  // Camera capture is subject to monitoring.
  device.type = mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE;
  device.id = camera_id;
  EXPECT_FALSE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device),
            static_cast<size_t>(
                std::max(media::kVideoCaptureDefaultMaxBufferPoolSize / 2,
                         media::DeviceVideoCaptureMaxBufferPoolSize() / 3)));

  // Screen and Window capture with the desktop capture extension API are
  // subject to monitoring.
  device.type = mojom::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE;
  device.id = screen_id;
  EXPECT_FALSE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(
      M::GetFramePoolSize(device),
      static_cast<size_t>(media::kVideoCaptureDefaultMaxBufferPoolSize / 2));
  device.id = window_id;
  EXPECT_FALSE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(
      M::GetFramePoolSize(device),
      static_cast<size_t>(media::kVideoCaptureDefaultMaxBufferPoolSize / 2));

  // Screen and Window capture with getDisplayMedia are subject to monitoring,
  // but not tab capture.
  device.type = mojom::MediaStreamType::DISPLAY_VIDEO_CAPTURE;
  device.id = screen_id;
  EXPECT_FALSE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(
      M::GetFramePoolSize(device),
      static_cast<size_t>(media::kVideoCaptureDefaultMaxBufferPoolSize / 2));
  device.id = window_id;
  EXPECT_FALSE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(
      M::GetFramePoolSize(device),
      static_cast<size_t>(media::kVideoCaptureDefaultMaxBufferPoolSize / 2));
  device.id = tab_id;
  EXPECT_TRUE(M::GetDeviceIdForMonitoring(device).empty());
  EXPECT_EQ(M::GetFramePoolSize(device), 0u);
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest, FrameLimiter) {
  const std::string device_id = "window:my-window";
  auto* media_stream_source = CreateDevicePushableSource(device_id);
  auto* platform_video_source =
      static_cast<blink::PushableMediaStreamVideoSource*>(
          media_stream_source->GetPlatformSource());
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope.GetExecutionContext(),
      MediaStreamVideoTrack::CreateVideoTrack(
          platform_video_source,
          MediaStreamVideoSource::ConstraintsOnceCallback(),
          /*enabled=*/true));
  // Use a large buffer so that the effective buffer size is guaranteed to be
  // the one set by frame monitoring.
  auto* source = CreateSource(
      script_state, track,
      MediaStreamVideoTrackUnderlyingSource::kMaxMonitoredFrameCount);
  const wtf_size_t max_frame_count =
      MediaStreamVideoTrackUnderlyingSource::GetFramePoolSize(
          platform_video_source->device());

  // This test assumes that |max_frame_count| is 2, for simplicity.
  ASSERT_EQ(max_frame_count, 2u);

  VideoFrameMonitor& monitor = VideoFrameMonitor::Instance();
  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      v8_scope.GetScriptState(), source, 0);

  // Add a sink to the track to make it possible to wait until a pushed frame
  // is delivered to sinks, including |source|, which is a sink of the track.
  MockMediaStreamVideoSink mock_sink;
  mock_sink.ConnectToTrack(WebMediaStreamTrack(source->Track()));
  auto push_frame_sync = [&](scoped_refptr<media::VideoFrame> video_frame) {
    base::RunLoop sink_loop;
    EXPECT_CALL(mock_sink, OnVideoFrame(_))
        .WillOnce(base::test::RunOnceClosure(sink_loop.QuitClosure()));
    platform_video_source->PushFrame(std::move(video_frame),
                                     base::TimeTicks::Now());
    sink_loop.Run();
  };

  Vector<scoped_refptr<media::VideoFrame>> frames;
  auto create_video_frame = [&]() {
    auto frame = media::VideoFrame::CreateBlackFrame(gfx::Size(10, 10));
    frames.push_back(frame);
    return frame;
  };
  auto get_frame_id = [&](int idx) { return frames[idx]->unique_id(); };

  EXPECT_TRUE(monitor.IsEmpty());
  // These frames are queued, pending to be read.
  for (size_t i = 0; i < max_frame_count; ++i) {
    auto video_frame = create_video_frame();
    media::VideoFrame::ID frame_id = video_frame->unique_id();
    push_frame_sync(std::move(video_frame));
    EXPECT_EQ(monitor.NumFrames(device_id), i + 1);
    EXPECT_EQ(monitor.NumRefs(device_id, frame_id), 1);
  }
  {
    // Push another video frame with the limit reached.
    auto video_frame = create_video_frame();
    media::VideoFrame::ID frame_id = video_frame->unique_id();
    push_frame_sync(std::move(video_frame));
    EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
    EXPECT_EQ(monitor.NumRefs(device_id, frame_id), 1);

    // The oldest frame should have been removed from the queue.
    EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(0)), 0);
  }

  auto* reader = stream->GetDefaultReaderForTesting(
      script_state, v8_scope.GetExceptionState());
  VideoFrame* video_frame1 = ReadObjectFromStream<VideoFrame>(v8_scope, reader);
  EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(1)), 1);

  VideoFrame* clone_frame1 = video_frame1->clone(v8_scope.GetExceptionState());
  EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(1)), 2);

  VideoFrame* video_frame2 = ReadObjectFromStream<VideoFrame>(v8_scope, reader);
  EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(2)), 1);

  // A new frame arrives, but the limit has been reached and there is nothing
  // that can be replaced.
  {
    auto video_frame = create_video_frame();
    media::VideoFrame::ID frame_id = video_frame->unique_id();
    push_frame_sync(std::move(video_frame));
    EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
    EXPECT_EQ(monitor.NumRefs(device_id, frame_id), 0);
  }

  // One of the JS VideoFrames backed by frames[1] is closed.
  clone_frame1->close();
  EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(1)), 1);

  // A new source connected to the same device is created and started in another
  // execution context.
  auto* media_stream_source2 = CreateDevicePushableSource(device_id);
  auto* platform_video_source2 =
      static_cast<blink::PushableMediaStreamVideoSource*>(
          media_stream_source2->GetPlatformSource());
  V8TestingScope v8_scope2;
  ScriptState* script_state2 = v8_scope2.GetScriptState();
  auto* track2 = MakeGarbageCollected<MediaStreamTrackImpl>(
      v8_scope2.GetExecutionContext(),
      MediaStreamVideoTrack::CreateVideoTrack(
          platform_video_source2,
          MediaStreamVideoSource::ConstraintsOnceCallback(),
          /*enabled=*/true));
  auto* source2 = CreateSource(
      script_state2, track2,
      MediaStreamVideoTrackUnderlyingSource::kMaxMonitoredFrameCount);
  ReadableStream::CreateWithCountQueueingStrategy(script_state2, source2, 0);

  MockMediaStreamVideoSink mock_sink2;
  mock_sink2.ConnectToTrack(WebMediaStreamTrack(source2->Track()));
  auto push_frame_sync2 = [&](scoped_refptr<media::VideoFrame> video_frame) {
    base::RunLoop sink_loop;
    EXPECT_CALL(mock_sink2, OnVideoFrame(_))
        .WillOnce(base::test::RunOnceClosure(sink_loop.QuitClosure()));
    platform_video_source2->PushFrame(std::move(video_frame),
                                      base::TimeTicks::Now());
    sink_loop.Run();
  };

  // The system delivers the last two created frames to the new source.
  {
    int idx = frames.size() - 2;
    EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
    EXPECT_GT(monitor.NumRefs(device_id, get_frame_id(idx)), 0);
    int num_refs = monitor.NumRefs(device_id, get_frame_id(idx));
    // The limit has been reached, but this frame is already monitored,
    // so it is queued.
    push_frame_sync2(frames[idx]);
    EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
    EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(idx)), num_refs + 1);
  }
  {
    int idx = frames.size() - 1;
    // The limit has been reached, and this frame was dropped by the other
    // source, so it is dropped by this one too.
    EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
    EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(idx)), 0);
    push_frame_sync2(frames[idx]);
    EXPECT_EQ(monitor.NumFrames(device_id), max_frame_count);
    EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(idx)), 0);
  }

  // The first context closes its source, but its VideoFrame objects are still
  // open.
  source->Close();

  // At this point, the only monitored frames are frames[1] and frames[2], both
  // open in context 1. frames[2] is also queued in context 2.
  EXPECT_EQ(monitor.NumFrames(device_id), 2u);

  // video_frame1 is the only reference to frames[1].
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(1)), 1);

  // video_frame2 is frames[2] and is open in context 1 and queued in context 2.
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(2)), 2);

  // Context 1 closes its video_frame1.
  video_frame1->close();
  EXPECT_EQ(monitor.NumFrames(device_id), 1u);
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(1)), 0);
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(2)), 2);

  // Context 1 closes its video_frame2, after which the only monitored frame is
  // the one queued by source 2.
  video_frame2->close();
  EXPECT_EQ(monitor.NumFrames(device_id), 1u);
  EXPECT_EQ(monitor.NumRefs(device_id, get_frame_id(2)), 1);

  // Context 2 closes its source, which should clear everything in the monitor.
  source2->Close();
  EXPECT_TRUE(monitor.IsEmpty());
}

TEST_F(MediaStreamVideoTrackUnderlyingSourceTest,
       VideoFramePrefersCaptureTimestamp) {
  const base::TimeDelta kTimestamp = base::Seconds(2);
  const base::TimeDelta kReferenceTimestamp = base::Seconds(3);
  const base::TimeDelta kCaptureTimestamp = base::Seconds(4);
  ASSERT_NE(kTimestamp, kCaptureTimestamp);

  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(script_state, track);
  auto* stream =
      ReadableStream::CreateWithCountQueueingStrategy(script_state, source, 0);

  NonThrowableExceptionState exception_state;
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, exception_state);

  // Create and push a video frame with a capture and reference timestamp
  scoped_refptr<media::VideoFrame> video_frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(10, 10));
  video_frame->set_timestamp(kTimestamp);
  media::VideoFrameMetadata metadata;
  metadata.capture_begin_time = base::TimeTicks() + kCaptureTimestamp;
  metadata.reference_time = base::TimeTicks() + kReferenceTimestamp;
  video_frame->set_metadata(metadata);

  PushableMediaStreamVideoSource* pushable_source =
      static_cast<PushableMediaStreamVideoSource*>(
          track->Component()->Source()->GetPlatformSource());
  pushable_source->PushFrame(std::move(video_frame), base::TimeTicks::Now());

  VideoFrame* web_video_frame =
      ReadObjectFromStream<VideoFrame>(v8_scope, reader);
  EXPECT_EQ(web_video_frame->timestamp(), kCaptureTimestamp.InMicroseconds());

  // Create and push a video frame with only a reference timestamp
  video_frame = media::VideoFrame::CreateBlackFrame(gfx::Size(10, 10));
  video_frame->set_timestamp(kTimestamp);
  metadata.capture_begin_time = std::nullopt;
  video_frame->set_metadata(metadata);
  pushable_source->PushFrame(std::move(video_frame), base::TimeTicks::Now());
  VideoFrame* web_video_frame2 =
      ReadObjectFromStream<VideoFrame>(v8_scope, reader);
  EXPECT_EQ(web_video_frame2->timestamp(),
            kReferenceTimestamp.InMicroseconds());

  // Create and push a new video frame without a capture or reference timestamp
  video_frame = media::VideoFrame::CreateBlackFrame(gfx::Size(10, 10));
  video_frame->set_timestamp(kTimestamp);
  EXPECT_FALSE(video_frame->metadata().capture_begin_time);
  EXPECT_FALSE(video_frame->metadata().reference_time);

  pushable_source->PushFrame(std::move(video_frame), base::TimeTicks::Now());
  VideoFrame* web_video_frame3 =
      ReadObjectFromStream<VideoFrame>(v8_scope, reader);

  if (base::FeatureList::IsEnabled(kBreakoutBoxInsertVideoCaptureTimestamp)) {
    scoped_refptr<media::VideoFrame> wrapped_video_frame3 =
        web_video_frame3->frame();
    ASSERT_TRUE(
        wrapped_video_frame3->metadata().capture_begin_time.has_value());
    EXPECT_EQ(web_video_frame3->timestamp(),
              (*wrapped_video_frame3->metadata().capture_begin_time -
               base::TimeTicks())
                  .InMicroseconds());
    ASSERT_TRUE(wrapped_video_frame3->metadata().reference_time.has_value());
    EXPECT_EQ(
        web_video_frame3->timestamp(),
        (*wrapped_video_frame3->metadata().reference_time - base::TimeTicks())
            .InMicroseconds());
  }

  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

}  // namespace blink

"""

```