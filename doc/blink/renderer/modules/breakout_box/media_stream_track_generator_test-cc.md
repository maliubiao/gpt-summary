Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Identify the Core Subject:** The filename `media_stream_track_generator_test.cc` and the `#include` directives immediately point to the core class being tested: `MediaStreamTrackGenerator`. The `.cc` extension confirms it's a C++ source file containing tests.

2. **Recognize the Test Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` clearly indicates that Google Test (gtest) is the testing framework being used. This is crucial because it dictates how tests are structured (using `TEST_F`, `EXPECT_EQ`, etc.).

3. **Understand the Purpose of Testing:**  Test files verify the functionality of specific code components. The goal is to ensure the `MediaStreamTrackGenerator` behaves as expected under various conditions.

4. **Scan for Test Cases:** Look for the `TEST_F` macros. Each `TEST_F` defines an individual test case focusing on a specific aspect of the `MediaStreamTrackGenerator`. List them out to get an overview of the tested functionalities:
    * `VideoFramesAreWritten`
    * `AudioDataAreWritten`
    * `FramesDoNotFlowOnStoppedGenerator`
    * `Clone`
    * `CloneStopSource`

5. **Analyze Individual Test Cases:** For each test case, go through the code line by line, understanding what it's doing and what it's trying to verify:

    * **`VideoFramesAreWritten`:**
        * Creates a `MediaStreamTrackGenerator` for video.
        * Sets up a `MockMediaStreamVideoSink` to receive video frames.
        * Writes a video frame chunk to the generator's writable stream.
        * Asserts that the sink received the frame.
        * Closes the writable stream and checks if the generator's track is ended.
        * **Key takeaway:** Tests that writing video data to the generator results in the data being sent to a connected `MediaStreamTrack`.

    * **`AudioDataAreWritten`:** Very similar to the video test, but uses `MockMediaStreamAudioSink` and `CreateAudioDataChunk`.
        * **Key takeaway:** Tests the same functionality for audio data.

    * **`FramesDoNotFlowOnStoppedGenerator`:**
        * Creates a video generator.
        * Stops the generator immediately.
        * Attempts to write a frame.
        * Asserts that the sink did *not* receive the frame.
        * **Key takeaway:** Verifies that data isn't processed after the track is stopped.

    * **`Clone`:**
        * Creates a generator and clones it.
        * Connects sinks to both the original and the clone.
        * Writes to the *original* generator.
        * Asserts that *both* sinks receive the data.
        * Stops the original, writes again, and checks that only the clone receives the data.
        * Stops the clone and verifies no more data is received.
        * **Key takeaway:**  Examines how cloning works and how stopping one track affects the other. It highlights that writing to the generator's writable stream affects all its tracks (including clones) until those tracks are explicitly stopped.

    * **`CloneStopSource`:**
        * Creates a generator and clones it.
        * Closes the *writable stream* of the original.
        * Asserts that *both* the original and the clone's tracks are ended.
        * **Key takeaway:**  Demonstrates that closing the underlying source (the writable stream) stops all tracks derived from that source, including clones.

6. **Identify Relationships to Web Technologies:** Think about how `MediaStreamTrackGenerator` fits into the broader web platform context.

    * **JavaScript:** The code interacts with JavaScript concepts through the V8 engine (`V8TestingScope`, `ScriptState`, `ScriptPromiseTester`). The `MediaStreamTrackGenerator` is likely exposed to JavaScript, allowing web developers to create media tracks. The `writable` property hints at the Streams API.
    * **HTML:**  HTML elements like `<video>` and `<audio>` use `MediaStreamTrack` objects as sources. The generator provides a way to *programmatically create* these tracks, which can then be assigned to these elements.
    * **CSS:** While not directly involved in data flow, CSS might be used to style the video/audio elements that consume the generated tracks.

7. **Infer Logic and Assumptions:**

    * **Assumption:** Writing to the generator's writable stream pushes data to the underlying `MediaStreamTrack`.
    * **Assumption:**  Cloning creates an independent `MediaStreamTrack` that shares the same source initially.
    * **Assumption:** Stopping a track prevents further data flow to its sinks.
    * **Logic:**  The tests use `MockMediaStreamSink` to verify data reception, which implies that the generator is designed to deliver media data to consumers.

8. **Consider User/Programming Errors:**  Think about common mistakes when working with media streams:

    * Trying to write to a closed stream.
    * Not handling the asynchronous nature of stream operations (although the tests use `RunLoop` to synchronize).
    * Incorrectly assuming that stopping one clone stops the original or other clones.

9. **Trace User Actions:**  Imagine how a user might trigger the code being tested:

    * A web application uses JavaScript to create a `MediaStreamTrackGenerator`.
    * The application gets the generator's writable stream.
    * The application writes video or audio data (e.g., from a canvas or microphone) to the writable stream.
    * The application gets the `MediaStreamTrack` from the generator and assigns it to a `<video>` or `<audio>` element, or uses it with other WebRTC APIs.

10. **Formulate Debugging Clues:**  Based on the code, identify potential debugging steps:

    * Check if the `MediaStreamTrackGenerator` is correctly created.
    * Verify that the writable stream is acquired successfully.
    * Inspect the data being written to the stream.
    * Ensure that sinks are correctly connected to the generated track.
    * Check the state of the track (`Ended()`) at different points.
    * Use browser developer tools to inspect media streams.

By following these steps, you can systematically analyze the test file and extract the relevant information about its functionality, relationships to web technologies, underlying logic, potential errors, and debugging strategies.这个文件 `media_stream_track_generator_test.cc` 是 Chromium Blink 引擎中 `breakout_box` 模块下的一个测试文件。它的主要功能是测试 `MediaStreamTrackGenerator` 类的功能。

**`MediaStreamTrackGenerator` 的功能（从测试代码推断）：**

从测试代码来看，`MediaStreamTrackGenerator` 的主要功能是：

1. **创建可写入的 MediaStreamTrack:**  `MediaStreamTrackGenerator` 能够创建一个 `MediaStreamTrack` 对象，这个 track 可以通过其关联的 `WritableStream` 进行写入。
2. **写入视频帧 (VideoFrame):** 可以将 `VideoFrame` 对象写入到 `MediaStreamTrackGenerator` 关联的 `WritableStream` 中，这些视频帧会流向连接到该 `MediaStreamTrack` 的接收器 (sink)。
3. **写入音频数据 (AudioData):** 同样地，可以将 `AudioData` 对象写入到 `MediaStreamTrackGenerator` 关联的 `WritableStream` 中，这些音频数据会流向连接到该 `MediaStreamTrack` 的接收器。
4. **控制 track 的生命周期:** 可以通过 `stopTrack()` 方法停止 track 的数据流动。
5. **支持 track 的克隆 (clone):**  可以创建 `MediaStreamTrackGenerator` 生成的 track 的副本，克隆的 track 与原始 track 共享相同的源（writable stream）。
6. **关闭 writable stream 会停止 track:** 当 `MediaStreamTrackGenerator` 关联的 `WritableStream` 被关闭时，它所生成的 `MediaStreamTrack` 也会结束。

**与 JavaScript, HTML, CSS 的关系举例说明：**

`MediaStreamTrackGenerator` 是 Blink 渲染引擎内部的 C++ 代码，但它与 JavaScript, HTML, CSS 功能有密切关系，因为它最终会影响到 Web API 的行为。

* **JavaScript:**
    * **创建可写入的 MediaStreamTrack (假设的 JavaScript API):** 开发者可能通过 JavaScript API (目前标准 Web API 中没有直接对应的构造函数，但可以设想有类似的需求) 创建一个可以写入数据的 `MediaStreamTrack`。`MediaStreamTrackGenerator` 可能在底层支撑这样的 API。
    ```javascript
    // 假设的 API
    const generator = new MediaStreamTrackGenerator({ kind: 'video' });
    const writableStream = generator.writable;
    const track = generator.track; // 获取生成的 MediaStreamTrack

    const writer = writableStream.getWriter();
    // ... 从某些来源获取 VideoFrame 数据 (需要转换成引擎内部的格式)
    const videoFrameData = ...;
    writer.write(videoFrameData);

    // 将 track 添加到 MediaStream 并显示在 video 标签中
    const stream = new MediaStream([track]);
    const videoElement = document.getElementById('myVideo');
    videoElement.srcObject = stream;
    ```
    * **Streams API 的使用:**  `MediaStreamTrackGenerator` 使用了 Streams API 的 `WritableStream`，这意味着 JavaScript 中的 `WritableStream` API 可以与之交互，向 track 中写入数据。

* **HTML:**
    * `<video>` 和 `<audio>` 元素通常使用 `MediaStreamTrack` 作为其媒体源。`MediaStreamTrackGenerator` 创建的 track 可以作为 `<video>` 或 `<audio>` 元素的 `srcObject` 属性值的一部分。
    ```html
    <video id="myVideo" autoplay></video>
    <audio id="myAudio" controls></audio>
    ```

* **CSS:**
    * CSS 可以用来样式化 `<video>` 和 `<audio>` 元素，从而间接地影响到使用 `MediaStreamTrackGenerator` 创建的媒体流的呈现效果。例如，可以控制视频的尺寸、宽高比、边框等。

**逻辑推理、假设输入与输出：**

**测试用例：`VideoFramesAreWritten`**

* **假设输入:**
    * 创建一个 `MediaStreamTrackGenerator`，类型为 "video"。
    * 创建一个 `MockMediaStreamVideoSink` 并连接到生成的 track。
    * 创建一个 `VideoFrame` 对象。
    * 通过 `WritableStream` 的 writer 将 `VideoFrame` 写入。
    * 关闭 `WritableStream`。
* **预期输出:**
    * `MockMediaStreamVideoSink` 接收到一个 `VideoFrame`。
    * `MediaStreamTrackGenerator` 生成的 track 的 `Ended()` 状态变为 `true`。
    * 相关的性能指标（通过 `HistogramTester` 检查）被记录。

**测试用例：`Clone`**

* **假设输入:**
    * 创建一个 `MediaStreamTrackGenerator`。
    * 克隆生成的 track。
    * 分别将 `MockMediaStreamVideoSink` 连接到原始 track 和克隆 track。
    * 通过原始 track 的 `WritableStream` 写入一个 `VideoFrame`。
    * 停止原始 track。
    * 再次通过原始 track 的 `WritableStream` 写入一个 `VideoFrame`。
    * 停止克隆 track。
    * 再次通过原始 track 的 `WritableStream` 写入一个 `VideoFrame`。
* **预期输出:**
    * 第一次写入时，两个 sink 都接收到 `VideoFrame`。
    * 停止原始 track 后，只有克隆 track 接收到第二次写入的 `VideoFrame`。
    * 停止克隆 track 后，两个 sink 都不再接收到 `VideoFrame`。

**用户或编程常见的使用错误举例说明：**

1. **尝试写入已关闭的 writable stream:**
   ```javascript
   // 假设的 API
   const generator = new MediaStreamTrackGenerator({ kind: 'video' });
   const writableStream = generator.writable;
   const writer = writableStream.getWriter();
   writableStream.close(); // 关闭 writable stream

   // 尝试写入，会导致错误或写入失败
   writer.write(videoFrameData);
   ```
   **错误说明:** 用户或程序员可能会忘记检查 writable stream 的状态，在 stream 已经关闭后尝试写入数据，这会导致数据丢失或程序异常。

2. **假设克隆的 track 是完全独立的:**
   ```javascript
   // 假设的 API
   const generator = new MediaStreamTrackGenerator({ kind: 'video' });
   const track1 = generator.track;
   const track2 = track1.clone();

   // 错误地认为停止 track1 不会影响 track2 的数据来源
   track1.stop();

   // 仍然尝试向 track2 的来源写入数据 (通过 generator 的 writable stream)
   const writer = generator.writable.getWriter();
   writer.write(videoFrameData);

   // 期望 track2 仍然能接收数据，但实际上可能不会，因为它们共享同一个源。
   ```
   **错误说明:** 用户或程序员可能没有意识到克隆的 track 共享相同的底层数据源（writable stream）。停止原始 track 可能会影响到克隆 track 的行为，特别是当关闭 writable stream 时，所有相关的 track 都会结束。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者在使用 Chromium 内核开发的浏览器或应用程序中遇到了与 `MediaStreamTrack` 数据生成相关的问题，他们可能会：

1. **使用 Web API 创建 MediaStream 和 MediaStreamTrack:** 开发者可能在 JavaScript 代码中使用 `getUserMedia`、`captureStream` 或其他 Web API 来获取或创建 `MediaStreamTrack` 对象。
2. **遇到数据流不通畅或数据错误的问题:** 例如，视频画面没有显示，音频没有播放，或者数据出现延迟、卡顿等问题。
3. **怀疑数据生成环节存在问题:** 开发者可能会怀疑是数据源的问题，例如，从 Canvas 获取的视频帧没有正确写入到 `MediaStreamTrack` 中。
4. **查看浏览器控制台的错误信息:**  如果涉及到 JavaScript API 的错误使用，控制台可能会有相关的错误提示。
5. **启用 Chromium 的调试日志:** 开发者可以启用 Chromium 的 `--enable-logging --v=1` 等命令行参数，查看更底层的日志信息，这些日志可能会包含与 `breakout_box` 模块相关的消息。
6. **阅读 Chromium 源代码:** 如果开发者对 Chromium 的内部实现感兴趣，或者错误信息指向了 `breakout_box` 模块，他们可能会查看 `blink/renderer/modules/breakout_box/` 目录下的源代码，包括 `media_stream_track_generator.cc` 和 `media_stream_track_generator_test.cc`。
7. **查看测试文件以理解 `MediaStreamTrackGenerator` 的工作原理:**  通过阅读 `media_stream_track_generator_test.cc`，开发者可以了解 `MediaStreamTrackGenerator` 的设计意图、如何创建 track、如何写入数据、以及如何控制 track 的生命周期。测试用例中的断言 (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`) 可以帮助理解预期的行为。
8. **使用断点调试:** 如果开发者本地编译了 Chromium，他们可以使用 GDB 或其他调试器在 `media_stream_track_generator.cc` 或相关的代码中设置断点，逐步执行代码，查看变量的值，从而定位问题。
9. **分析 Histogram 数据:** 测试代码中使用了 `HistogramTester` 来检查性能指标。开发者在实际运行环境中也可以查看 Chromium 的 `chrome://histograms` 页面，搜索相关的 `Media.BreakoutBox.Usage` 指标，了解 `MediaStreamTrackGenerator` 的使用情况，辅助排查问题。

总而言之，`media_stream_track_generator_test.cc` 这个文件是理解和调试 Chromium 中 `MediaStreamTrackGenerator` 功能的重要参考资料。它展示了该类的核心功能、使用方式以及预期行为，可以帮助开发者理解 Web API 背后的实现机制，并辅助定位和解决相关问题。

Prompt: 
```
这是目录为blink/renderer/modules/breakout_box/media_stream_track_generator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/breakout_box/media_stream_track_generator.h"

#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track_generator_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/modules/breakout_box/media_stream_track_processor.h"
#include "third_party/blink/renderer/modules/breakout_box/metrics.h"
#include "third_party/blink/renderer/modules/breakout_box/pushable_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/breakout_box/stream_test_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_audio_sink.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

using testing::_;

namespace blink {

namespace {

ScriptValue CreateVideoFrameChunk(ScriptState* script_state) {
  const scoped_refptr<media::VideoFrame> media_frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(10, 5));
  VideoFrame* video_frame = MakeGarbageCollected<VideoFrame>(
      std::move(media_frame), ExecutionContext::From(script_state));
  return ScriptValue(script_state->GetIsolate(),
                     ToV8Traits<VideoFrame>::ToV8(script_state, video_frame));
}

ScriptValue CreateAudioDataChunk(ScriptState* script_state) {
  AudioData* audio_data =
      MakeGarbageCollected<AudioData>(media::AudioBuffer::CreateEmptyBuffer(
          media::ChannelLayout::CHANNEL_LAYOUT_STEREO,
          /*channel_count=*/2,
          /*sample_rate=*/44100,
          /*frame_count=*/500, base::TimeDelta()));
  return ScriptValue(script_state->GetIsolate(),
                     ToV8Traits<AudioData>::ToV8(script_state, audio_data));
}

}  // namespace

class MediaStreamTrackGeneratorTest : public testing::Test {
 public:
  ~MediaStreamTrackGeneratorTest() override {
    platform_->RunUntilIdle();
    WebHeap::CollectAllGarbageForTesting();
  }

 protected:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

TEST_F(MediaStreamTrackGeneratorTest, VideoFramesAreWritten) {
  base::HistogramTester histogram_tester;
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  MediaStreamTrackGenerator* generator = MediaStreamTrackGenerator::Create(
      script_state, "video", v8_scope.GetExceptionState());

  MockMediaStreamVideoSink media_stream_video_sink;
  media_stream_video_sink.ConnectToTrack(
      WebMediaStreamTrack(generator->Component()));
  EXPECT_EQ(media_stream_video_sink.number_of_frames(), 0);
  EXPECT_EQ(media_stream_video_sink.last_frame(), nullptr);

  base::RunLoop sink_loop;
  EXPECT_CALL(media_stream_video_sink, OnVideoFrame(_))
      .WillOnce(base::test::RunOnceClosure(sink_loop.QuitClosure()));
  ExceptionState& exception_state = v8_scope.GetExceptionState();
  auto* writer = generator->writable(script_state)
                     ->getWriter(script_state, exception_state);
  ScriptPromiseTester write_tester(
      script_state,
      writer->write(script_state, CreateVideoFrameChunk(script_state),
                    exception_state));
  EXPECT_FALSE(write_tester.IsFulfilled());
  write_tester.WaitUntilSettled();
  sink_loop.Run();
  EXPECT_TRUE(write_tester.IsFulfilled());
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_EQ(media_stream_video_sink.number_of_frames(), 1);

  // Closing the writable stream should stop the track.
  writer->releaseLock(script_state);
  EXPECT_FALSE(generator->Ended());
  ScriptPromiseTester close_tester(
      script_state,
      generator->writable(script_state)->close(script_state, exception_state));
  close_tester.WaitUntilSettled();
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_TRUE(generator->Ended());
  histogram_tester.ExpectUniqueSample("Media.BreakoutBox.Usage",
                                      BreakoutBoxUsage::kWritableVideo, 1);
  histogram_tester.ExpectTotalCount("Media.BreakoutBox.Usage", 1);
}

TEST_F(MediaStreamTrackGeneratorTest, AudioDataAreWritten) {
  base::HistogramTester histogram_tester;
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  MediaStreamTrackGenerator* generator = MediaStreamTrackGenerator::Create(
      script_state, "audio", v8_scope.GetExceptionState());

  MockMediaStreamAudioSink media_stream_audio_sink;
  WebMediaStreamAudioSink::AddToAudioTrack(
      &media_stream_audio_sink, WebMediaStreamTrack(generator->Component()));

  base::RunLoop sink_loop;
  EXPECT_CALL(media_stream_audio_sink, OnData(_, _))
      .WillOnce(testing::WithArg<0>([&](const media::AudioBus& data) {
        EXPECT_NE(data.frames(), 0);
        sink_loop.Quit();
      }));
  ExceptionState& exception_state = v8_scope.GetExceptionState();
  auto* writer = generator->writable(script_state)
                     ->getWriter(script_state, exception_state);
  ScriptPromiseTester write_tester(
      script_state,
      writer->write(script_state, CreateAudioDataChunk(script_state),
                    exception_state));
  EXPECT_FALSE(write_tester.IsFulfilled());
  write_tester.WaitUntilSettled();
  sink_loop.Run();
  EXPECT_TRUE(write_tester.IsFulfilled());
  EXPECT_FALSE(exception_state.HadException());

  // Closing the writable stream should stop the track.
  writer->releaseLock(script_state);
  EXPECT_FALSE(generator->Ended());
  ScriptPromiseTester close_tester(
      script_state,
      generator->writable(script_state)->close(script_state, exception_state));
  close_tester.WaitUntilSettled();
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_TRUE(generator->Ended());

  WebMediaStreamAudioSink::RemoveFromAudioTrack(
      &media_stream_audio_sink, WebMediaStreamTrack(generator->Component()));
  histogram_tester.ExpectUniqueSample("Media.BreakoutBox.Usage",
                                      BreakoutBoxUsage::kWritableAudio, 1);
  histogram_tester.ExpectTotalCount("Media.BreakoutBox.Usage", 1);
}


TEST_F(MediaStreamTrackGeneratorTest, FramesDoNotFlowOnStoppedGenerator) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  MediaStreamTrackGenerator* generator = MediaStreamTrackGenerator::Create(
      script_state, "video", v8_scope.GetExceptionState());

  MockMediaStreamVideoSink media_stream_video_sink;
  media_stream_video_sink.ConnectToTrack(
      WebMediaStreamTrack(generator->Component()));
  EXPECT_EQ(media_stream_video_sink.number_of_frames(), 0);
  EXPECT_EQ(media_stream_video_sink.last_frame(), nullptr);
  EXPECT_CALL(media_stream_video_sink, OnVideoFrame(_)).Times(0);

  generator->stopTrack(v8_scope.GetExecutionContext());
  EXPECT_TRUE(generator->Ended());

  ExceptionState& exception_state = v8_scope.GetExceptionState();
  auto* writer = generator->writable(script_state)
                     ->getWriter(script_state, exception_state);
  ScriptPromiseTester write_tester(
      script_state,
      writer->write(script_state, CreateVideoFrameChunk(script_state),
                    exception_state));
  write_tester.WaitUntilSettled();
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_EQ(media_stream_video_sink.number_of_frames(), 0);
}

TEST_F(MediaStreamTrackGeneratorTest, Clone) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  MediaStreamTrackGenerator* original = MediaStreamTrackGenerator::Create(
      script_state, "video", v8_scope.GetExceptionState());
  MediaStreamTrack* clone = original->clone(v8_scope.GetExecutionContext());
  EXPECT_FALSE(original->Ended());
  EXPECT_FALSE(clone->Ended());

  MockMediaStreamVideoSink original_sink;
  original_sink.ConnectToTrack(WebMediaStreamTrack(original->Component()));
  EXPECT_EQ(original_sink.number_of_frames(), 0);
  EXPECT_EQ(original_sink.last_frame(), nullptr);

  MockMediaStreamVideoSink clone_sink;
  clone_sink.ConnectToTrack(WebMediaStreamTrack(clone->Component()));
  EXPECT_EQ(clone_sink.number_of_frames(), 0);
  EXPECT_EQ(clone_sink.last_frame(), nullptr);

  // Writing to the original writes to the clone.
  base::RunLoop original_sink_loop;
  base::RunLoop clone_sink_loop;
  EXPECT_CALL(original_sink, OnVideoFrame(_))
      .WillOnce(base::test::RunOnceClosure(original_sink_loop.QuitClosure()));
  EXPECT_CALL(clone_sink, OnVideoFrame(_))
      .WillOnce(base::test::RunOnceClosure(clone_sink_loop.QuitClosure()));
  ExceptionState& exception_state = v8_scope.GetExceptionState();
  auto* writer = original->writable(script_state)
                     ->getWriter(script_state, exception_state);
  ScriptPromiseTester write_tester(
      script_state,
      writer->write(script_state, CreateVideoFrameChunk(script_state),
                    exception_state));
  write_tester.WaitUntilSettled();
  original_sink_loop.Run();
  clone_sink_loop.Run();
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_EQ(original_sink.number_of_frames(), 1);
  EXPECT_EQ(clone_sink.number_of_frames(), 1);

  // Stopping the original does not stop the clone
  original->stopTrack(v8_scope.GetExecutionContext());
  EXPECT_TRUE(original->Ended());
  EXPECT_FALSE(clone->Ended());

  // The original has not been closed, so writing again writes to the clone,
  // which is still live.
  base::RunLoop clone_sink_loop2;
  EXPECT_CALL(original_sink, OnVideoFrame(_)).Times(0);
  EXPECT_CALL(clone_sink, OnVideoFrame(_))
      .WillOnce(base::test::RunOnceClosure(clone_sink_loop2.QuitClosure()));
  ScriptPromiseTester write_tester2(
      script_state,
      writer->write(script_state, CreateVideoFrameChunk(script_state),
                    exception_state));
  write_tester2.WaitUntilSettled();
  clone_sink_loop2.Run();
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_EQ(original_sink.number_of_frames(), 1);
  EXPECT_EQ(clone_sink.number_of_frames(), 2);

  // After stopping the clone, pushing more frames does not deliver frames.
  clone->stopTrack(v8_scope.GetExecutionContext());
  EXPECT_TRUE(clone->Ended());

  EXPECT_CALL(original_sink, OnVideoFrame(_)).Times(0);
  EXPECT_CALL(clone_sink, OnVideoFrame(_)).Times(0);
  ScriptPromiseTester write_tester3(
      script_state,
      writer->write(script_state, CreateVideoFrameChunk(script_state),
                    exception_state));
  write_tester3.WaitUntilSettled();
  EXPECT_FALSE(exception_state.HadException());
  EXPECT_EQ(original_sink.number_of_frames(), 1);
  EXPECT_EQ(clone_sink.number_of_frames(), 2);
}

TEST_F(MediaStreamTrackGeneratorTest, CloneStopSource) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  MediaStreamTrackGenerator* original = MediaStreamTrackGenerator::Create(
      script_state, "video", v8_scope.GetExceptionState());
  MediaStreamTrack* clone = original->clone(v8_scope.GetExecutionContext());
  EXPECT_FALSE(original->Ended());
  EXPECT_FALSE(clone->Ended());

  // Closing writable stops the source and therefore ends all connected tracks.
  ScriptPromiseTester close_tester(
      script_state, original->writable(script_state)
                        ->close(script_state, v8_scope.GetExceptionState()));
  close_tester.WaitUntilSettled();
  EXPECT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_TRUE(original->Ended());
  EXPECT_TRUE(clone->Ended());
}

}  // namespace blink

"""

```