Response:
Let's break down the thought process to analyze this C++ test file.

1. **Understand the Goal:** The overarching goal is to understand the purpose of the `media_stream_video_track_underlying_sink_test.cc` file within the Chromium Blink engine. Specifically, we need to figure out what it's testing and how it relates to web technologies.

2. **File Name Decomposition:** The file name itself provides significant clues:
    * `media_stream_video_track`: This strongly suggests interaction with video from a media stream (likely obtained from the user's camera or screen sharing).
    * `underlying_sink`: This implies a lower-level component that receives video data. The "underlying" part suggests it's not directly exposed to JavaScript but is part of the implementation.
    * `test.cc`:  This clearly indicates a test file, designed for verifying the functionality of the associated code.

3. **Include Headers - Initial Scan:**  The included headers are crucial for understanding the dependencies and functionalities being tested:
    * `media_stream_video_track_underlying_sink.h`: This confirms that the test is for the `MediaStreamVideoTrackUnderlyingSink` class.
    * Standard C++ headers (`<cstdint>`).
    * `base/memory/...`, `base/time/...`: Indicates the use of Chromium base libraries for memory management and time handling.
    * `media/base/video_frame.h`:  Signifies interaction with raw video frame data structures.
    * `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  Confirms the use of Google Test and Google Mock for writing unit tests.
    * `third_party/blink/public/platform/...`:  Points to Blink's platform abstraction layer, likely for threading and scheduling.
    * `third_party/blink/public/web/web_heap.h`:  Indicates interaction with Blink's garbage collection.
    * `third_party/blink/renderer/bindings/core/v8/...`: Shows involvement with V8, the JavaScript engine. This is a key indicator of interaction with JavaScript APIs. Specifically, `ScriptPromiseTester` suggests testing asynchronous operations.
    * `third_party/blink/renderer/bindings/modules/v8/v8_video_frame.h`:  More V8 bindings, specifically for the `VideoFrame` object exposed to JavaScript.
    * `third_party/blink/renderer/core/streams/...`:  Points to the Streams API implementation within Blink (likely related to the WritableStream being used in the tests).
    * `third_party/blink/renderer/modules/breakout_box/...`: The directory where this file resides, suggesting a feature or module named "breakout_box."  `FrameQueueUnderlyingSource` and `PushableMediaStreamVideoSource` are related components within this module.
    * `third_party/blink/renderer/modules/mediastream/...`: More Media Streams API related code, including `MediaStreamVideoTrack` and `MockMediaStreamVideoSink`. The "Mock" part is a big clue that the tests are verifying interactions with other components.
    * `third_party/blink/renderer/modules/webcodecs/video_frame.h`:  Indicates interaction with the WebCodecs API, which provides lower-level access to video encoding and decoding.
    * `third_party/blink/renderer/platform/...`:  Various platform-level functionalities.

4. **Core Class Under Test:** The primary class under test is `MediaStreamVideoTrackUnderlyingSink`. Based on its name, it likely acts as a sink for video data coming from a `MediaStreamVideoTrack`. The "Underlying" suggests it's an implementation detail not directly exposed to web developers.

5. **Test Structure and Individual Tests:**  The file uses Google Test's `TEST_F` macro. Each `TEST_F` function focuses on testing a specific aspect of `MediaStreamVideoTrackUnderlyingSink`. Analyzing each test individually helps understand the class's functionality:
    * `WriteToStreamForwardsToMediaStreamSink`: This test verifies that when data is written to the underlying sink, it's correctly passed on to a `MediaStreamVideoSink`. The use of `MockMediaStreamVideoSink` confirms this.
    * `WriteInvalidDataFails`:  Checks error handling when invalid data (not a `VideoFrame`) is written to the sink.
    * `WriteToAbortedSinkFails`: Tests that writing to the sink after it's been aborted results in an error.
    * `GetGmbManager`: Investigates the handling of GPU memory buffers (GMBs), a performance optimization for video processing.
    * `DeltaTimestampDoesNotWriteCaptureBeginTime` and `CaptureTimestampWritesCaptureBeginTime`: These tests are specifically about how timestamps are handled. They distinguish between regular `TimeDelta` timestamps and `TimeTicks` timestamps, which are treated as capture times.
    * `DecisionToNotWriteCaptureTimeIsSticky`: Checks if the decision to treat timestamps as deltas (and not capture times) persists across multiple writes.

6. **Relationship to Web Technologies:**
    * **JavaScript:** The presence of V8 bindings and `ScriptPromiseTester` indicates direct interaction with JavaScript. The `VideoFrame` objects being passed to the sink are the JavaScript `VideoFrame` objects from the WebCodecs API. The `WritableStream` API is also a JavaScript API.
    * **HTML:** While not directly manipulating HTML elements, the underlying functionality enables features used in HTML, such as the `<video>` element displaying a live camera feed (which is powered by `getUserMedia` and `MediaStreamTrack`).
    * **CSS:**  Indirectly related. CSS might style the `<video>` element, but this test focuses on the data flow *before* rendering.

7. **Logic and Assumptions:**
    * The tests assume a properly functioning `PushableMediaStreamVideoSource` to provide the video data.
    * The tests rely on the behavior of the `WritableStream` API for managing the flow of video frames.
    * The tests related to timestamps make assumptions about the interpretation of `TimeDelta` and `TimeTicks` in the context of video capture.

8. **User/Programming Errors:**
    * Passing incorrect data types to the sink (e.g., integers instead of `VideoFrame`).
    * Trying to write to a sink that has already been closed or aborted.
    * Misunderstanding how timestamps are interpreted (as demonstrated by the timestamp-related tests).

9. **Debugging Steps to Reach This Code:**
    * A web developer might encounter issues with video playback or processing when using the WebCodecs API or Media Streams API.
    * They might report bugs related to video frame timestamps or data being lost.
    * Chromium developers investigating these bugs would then look at the implementation of the `MediaStreamVideoTrackUnderlyingSink`.
    * To understand the behavior and verify fixes, they would run these unit tests (`media_stream_video_track_underlying_sink_test.cc`). The tests serve as executable specifications for the code.

10. **Refine and Organize:**  Finally, organize the findings into clear sections addressing the specific questions asked in the prompt: functionality, relationship to web technologies, logic and assumptions, common errors, and debugging steps. Provide concrete examples to illustrate the points.
This C++ file `media_stream_video_track_underlying_sink_test.cc` within the Chromium Blink engine contains **unit tests** for the `MediaStreamVideoTrackUnderlyingSink` class. The primary goal of these tests is to ensure that the `MediaStreamVideoTrackUnderlyingSink` class functions correctly in various scenarios.

Here's a breakdown of its functionalities and relationships:

**Functionalities of `MediaStreamVideoTrackUnderlyingSinkTest`:**

1. **Testing Data Flow:** The tests verify that video frames provided to the `MediaStreamVideoTrackUnderlyingSink` are correctly passed down the pipeline to a `MediaStreamVideoSink`. This involves simulating writing video frames to the sink and checking if the mock sink receives them as expected.

2. **Testing Error Handling:** The tests check how the sink handles invalid input, such as:
    * Trying to write data that is not a `VideoFrame`.
    * Trying to write a null value.
    * Trying to write a `VideoFrame` that has already been closed/destroyed.
    * Trying to write to a sink that has been aborted or closed.

3. **Testing Interaction with MediaStreamTrack:** The tests involve creating a `MediaStreamVideoTrack` and connecting a mock sink to it. This helps verify the integration between the underlying sink and the higher-level media stream track.

4. **Testing Timestamp Handling:**  The tests specifically examine how timestamps of the video frames are handled, particularly:
    * Whether regular `TimeDelta` timestamps are passed through without being interpreted as capture times.
    * Whether `TimeTicks` timestamps (which can represent capture times) are correctly identified and potentially handled as such (though these tests currently focus on *not* writing capture begin time in some scenarios).
    * The "stickiness" of the decision regarding whether to interpret timestamps as capture times.

5. **Testing GPU Memory Buffer Management:** The tests check if the sink correctly retrieves a GPU memory buffer manager when appropriate (depending on whether GPU memory buffer readback is enabled).

**Relationship with JavaScript, HTML, and CSS:**

This C++ test file is part of the **implementation** of web features. It's not directly interacting with JavaScript, HTML, or CSS at runtime in the way a web page does. However, it tests the underlying mechanisms that enable these web technologies to function.

* **JavaScript:**
    * **`VideoFrame` API:** The tests directly interact with `VideoFrame` objects, which are exposed to JavaScript through the WebCodecs API. JavaScript code can create `VideoFrame` objects and potentially pass them to a sink (though the code under test here is more about the internal plumbing).
        * **Example:** A JavaScript application using the WebCodecs API might obtain video frames from a `<canvas>` element or a video decoder and then write these `VideoFrame`s to a custom sink for further processing or transmission. The `MediaStreamVideoTrackUnderlyingSink` could be part of such a custom sink implementation.
    * **Streams API (`WritableStream`):** The tests use `WritableStream` to pipe data to the underlying sink. This API is directly accessible in JavaScript.
        * **Example:**  A JavaScript application might create a `WritableStream` and its underlying sink could be an instance of something that internally uses `MediaStreamVideoTrackUnderlyingSink` to send video data to a `MediaStreamTrack`.
    * **Media Streams API (`MediaStreamTrack`):** The tests involve `MediaStreamVideoTrack`, which is a core component of the Media Streams API in JavaScript (e.g., used with `getUserMedia`).
        * **Example:** When a user grants camera access, the browser creates a `MediaStreamTrack` representing the video feed. The `MediaStreamVideoTrackUnderlyingSink` plays a role in how the video frames from the camera are processed and made available through this track.

* **HTML:**
    * The features tested by this code enable the `<video>` element to display video content from sources like webcams or screen sharing (via the Media Streams API). The underlying sink is part of the process of getting the video data to the `<video>` element.
    * **Example:** When a website uses `getUserMedia()` to access the camera and then sets the resulting `MediaStream` as the source of a `<video>` element, the `MediaStreamVideoTrackUnderlyingSink` is involved in handling the video frames.

* **CSS:**
    * CSS is used for styling the presentation of web content, including the `<video>` element. While this C++ code doesn't directly interact with CSS, the functionality it tests ensures that the video data is available for the browser to render according to the CSS styles applied to the `<video>` element.

**Logic and Assumptions:**

* **Assumption:** The tests assume the existence and correct functioning of other related classes like `PushableMediaStreamVideoSource`, `MediaStreamVideoTrack`, and `MockMediaStreamVideoSink`. Mock objects are used to isolate the unit under test.
* **Logic:** The tests follow a common pattern:
    1. **Setup:** Create necessary objects like the underlying sink, a writable stream connected to it, and potentially a mock media stream sink.
    2. **Action:** Perform an action on the sink, such as writing a video frame or attempting an invalid operation.
    3. **Verification:** Check the outcome of the action. This might involve verifying that the mock sink received the expected data, that an exception was thrown, or that internal state was updated correctly.

**Example of Assumptions and Input/Output (for `WriteToStreamForwardsToMediaStreamSink`):**

* **Assumption:** A valid `VideoFrame` object can be created.
* **Input:** A `VideoFrame` object (created using `CreateVideoFrameChunk`).
* **Expected Output:** The `MockMediaStreamVideoSink`'s `OnVideoFrame` method should be called with the provided `VideoFrame` (or a representation of it).

**Common User or Programming Errors (that these tests help prevent):**

* **Passing incorrect data types to the sink:** A programmer might mistakenly try to write a number or a string to the sink instead of a `VideoFrame`. The `WriteInvalidDataFails` test covers this.
* **Using a closed or aborted sink:** A programmer might try to write data to a sink after it has been intentionally closed or due to an error. The `WriteToAbortedSinkFails` test verifies the expected error.
* **Not handling `VideoFrame` lifecycle correctly:**  A programmer might try to use a `VideoFrame` after it has been closed, leading to crashes or unexpected behavior. The test that writes a closed `VideoFrame` checks for this.
* **Misunderstanding timestamp interpretation:** Developers working with video processing might have expectations about how timestamps are handled. The timestamp-related tests ensure that the underlying sink behaves consistently with the expected interpretation of `TimeDelta` and `TimeTicks`.

**User Operations and Debugging Clues:**

A user operation leading to this code being executed (and potentially revealing a bug caught by these tests) would typically involve:

1. **User Interaction:** A user interacts with a web page that uses media streams or the WebCodecs API. This could involve:
    * Granting permission for camera or microphone access (`getUserMedia`).
    * Sharing their screen (`getDisplayMedia`).
    * Using a web application that processes video using the WebCodecs API (e.g., a video editor or conferencing tool).

2. **Data Flow:** The browser captures video frames from the user's device or screen. These frames are represented internally as `media::VideoFrame` objects.

3. **Pipeline Involvement:** The `MediaStreamVideoTrackUnderlyingSink` comes into play when these video frames need to be processed or passed along a pipeline. For instance, if a JavaScript application creates a custom `WritableStream` and connects it to a `MediaStreamTrack`, the underlying sink of that stream might be an instance of `MediaStreamVideoTrackUnderlyingSink`.

4. **Potential Issues:**  If there's a bug in the `MediaStreamVideoTrackUnderlyingSink`, it could manifest as:
    * **Video frames not being displayed or processed correctly.**
    * **Errors or crashes in the web application.**
    * **Incorrect timestamps on video frames, leading to synchronization issues.**

**Debugging Steps to Reach This Code as a Developer:**

1. **Identify a Bug:** A bug report might indicate issues with video streams in a specific scenario.
2. **Trace the Data Flow:** Developers would trace the flow of video frames through the Blink rendering engine. They would identify that `MediaStreamVideoTrackUnderlyingSink` is involved in the processing of these frames.
3. **Examine the Code:** Developers would then look at the source code of `MediaStreamVideoTrackUnderlyingSink` to understand its logic.
4. **Run the Tests:** To verify their understanding and test potential fixes, developers would run the unit tests in `media_stream_video_track_underlying_sink_test.cc`.
5. **Write New Tests (if necessary):** If the existing tests don't cover the specific bug scenario, developers might write new test cases to reproduce the issue and ensure the fix is correct.
6. **Debug the Code:** Using a debugger, developers can step through the code of `MediaStreamVideoTrackUnderlyingSink` while the tests are running to pinpoint the source of the bug.

In summary, `media_stream_video_track_underlying_sink_test.cc` is a crucial part of ensuring the stability and correctness of video processing within the Chromium browser, particularly for features related to media streams and the WebCodecs API. It acts as a safety net, catching potential errors before they impact users.

Prompt: 
```
这是目录为blink/renderer/modules/breakout_box/media_stream_video_track_underlying_sink_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/breakout_box/media_stream_video_track_underlying_sink.h"

#include <cstdint>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/time/time.h"
#include "media/base/video_frame.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/modules/breakout_box/frame_queue_underlying_source.h"
#include "third_party/blink/renderer/modules/breakout_box/pushable_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_sink.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_memory_buffer_test_platform.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_video_frame_pool.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

using testing::_;

namespace blink {

namespace {
// Some of these tests rely on Now() being at least 1 minute.
// If this is not the case, affected tests might flake and should not run.
// TODO(crbug.com/343870500): Remove this once capture timestamps are exposed
// as part of WebCodecs VideoFrame metadata.
bool IsTooEarlyForTest() {
  return (base::TimeTicks::Now() - base::TimeTicks()) <= base::Minutes(2);
}
}  // namespace

class MediaStreamVideoTrackUnderlyingSinkTest : public testing::Test {
 public:
  MediaStreamVideoTrackUnderlyingSinkTest() {
    auto pushable_video_source =
        std::make_unique<PushableMediaStreamVideoSource>(
            scheduler::GetSingleThreadTaskRunnerForTesting());
    pushable_video_source_ = pushable_video_source.get();
    media_stream_source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeVideo, "dummy_source_name",
        /*remote=*/false, std::move(pushable_video_source));
  }

  ~MediaStreamVideoTrackUnderlyingSinkTest() override {
    platform_->RunUntilIdle();
    WebHeap::CollectAllGarbageForTesting();
  }

  MediaStreamVideoTrackUnderlyingSink* CreateUnderlyingSink(
      ScriptState* script_state) {
    return MakeGarbageCollected<MediaStreamVideoTrackUnderlyingSink>(
        pushable_video_source_->GetBroker());
  }

  WebMediaStreamTrack CreateTrack() {
    return MediaStreamVideoTrack::CreateVideoTrack(
        pushable_video_source_,
        MediaStreamVideoSource::ConstraintsOnceCallback(),
        /*enabled=*/true);
  }

  ScriptValue CreateVideoFrameChunk(
      ScriptState* script_state,
      VideoFrame** video_frame_out = nullptr,
      base::TimeDelta timestamp = base::Seconds(2)) {
    const scoped_refptr<media::VideoFrame> media_frame =
        media::VideoFrame::CreateBlackFrame(gfx::Size(100, 50));
    // Set a nonzero timestamp to make it easier to detect certain errors such
    // as unit conversions in Web-exposed VideoFrames which use integer
    // timestamps.
    media_frame->set_timestamp(timestamp);
    VideoFrame* video_frame = MakeGarbageCollected<VideoFrame>(
        std::move(media_frame), ExecutionContext::From(script_state));
    if (video_frame_out)
      *video_frame_out = video_frame;
    return ScriptValue(script_state->GetIsolate(),
                       ToV8Traits<VideoFrame>::ToV8(script_state, video_frame));
  }

 protected:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
  Persistent<MediaStreamSource> media_stream_source_;
  raw_ptr<PushableMediaStreamVideoSource> pushable_video_source_;
};

// TODO(1153092): Test flakes, likely due to completing before background
// thread has had chance to call OnVideoFrame().
TEST_F(MediaStreamVideoTrackUnderlyingSinkTest,
       DISABLED_WriteToStreamForwardsToMediaStreamSink) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* underlying_sink = CreateUnderlyingSink(script_state);
  auto* writable_stream = WritableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_sink, 1u);

  auto track = CreateTrack();
  MockMediaStreamVideoSink media_stream_video_sink;
  media_stream_video_sink.ConnectToTrack(track);

  NonThrowableExceptionState exception_state;
  auto* writer = writable_stream->getWriter(script_state, exception_state);

  VideoFrame* video_frame = nullptr;
  auto video_frame_chunk = CreateVideoFrameChunk(script_state, &video_frame);
  EXPECT_NE(video_frame, nullptr);
  EXPECT_NE(video_frame->frame(), nullptr);
  EXPECT_CALL(media_stream_video_sink, OnVideoFrame(_));
  ScriptPromiseTester write_tester(
      script_state,
      writer->write(script_state, video_frame_chunk, exception_state));
  write_tester.WaitUntilSettled();
  // |video_frame| should be invalidated after sending it to the sink.
  EXPECT_EQ(video_frame->frame(), nullptr);

  writer->releaseLock(script_state);
  ScriptPromiseTester close_tester(
      script_state, writable_stream->close(script_state, exception_state));
  close_tester.WaitUntilSettled();

  // Writing to the sink after the stream closes should fail.
  DummyExceptionStateForTesting dummy_exception_state;
  underlying_sink->write(script_state, CreateVideoFrameChunk(script_state),
                         nullptr, dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
  EXPECT_EQ(dummy_exception_state.Code(),
            static_cast<ExceptionCode>(DOMExceptionCode::kInvalidStateError));
}

TEST_F(MediaStreamVideoTrackUnderlyingSinkTest, WriteInvalidDataFails) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateUnderlyingSink(script_state);
  ScriptValue v8_integer =
      ScriptValue(script_state->GetIsolate(),
                  v8::Integer::New(script_state->GetIsolate(), 0));

  // Writing something that is not a VideoFrame to the sink should fail.
  {
    DummyExceptionStateForTesting dummy_exception_state;
    sink->write(script_state, v8_integer, nullptr, dummy_exception_state);
    EXPECT_TRUE(dummy_exception_state.HadException());
  }

  // Writing a null value to the sink should fail.
  {
    DummyExceptionStateForTesting dummy_exception_state;
    EXPECT_FALSE(dummy_exception_state.HadException());
    sink->write(script_state, ScriptValue::CreateNull(v8_scope.GetIsolate()),
                nullptr, dummy_exception_state);
    EXPECT_TRUE(dummy_exception_state.HadException());
  }

  // Writing a destroyed VideoFrame to the sink should fail.
  {
    DummyExceptionStateForTesting dummy_exception_state;
    VideoFrame* video_frame = nullptr;
    auto chunk = CreateVideoFrameChunk(script_state, &video_frame);
    video_frame->close();
    EXPECT_FALSE(dummy_exception_state.HadException());
    sink->write(script_state, chunk, nullptr, dummy_exception_state);
    EXPECT_TRUE(dummy_exception_state.HadException());
  }
}

TEST_F(MediaStreamVideoTrackUnderlyingSinkTest, WriteToAbortedSinkFails) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* underlying_sink = CreateUnderlyingSink(script_state);
  auto* writable_stream = WritableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_sink, 1u);

  NonThrowableExceptionState exception_state;
  ScriptPromiseTester abort_tester(
      script_state, writable_stream->abort(script_state, exception_state));
  abort_tester.WaitUntilSettled();

  // Writing to the sink after the stream closes should fail.
  DummyExceptionStateForTesting dummy_exception_state;
  underlying_sink->write(script_state, CreateVideoFrameChunk(script_state),
                         nullptr, dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
  EXPECT_EQ(dummy_exception_state.Code(),
            static_cast<ExceptionCode>(DOMExceptionCode::kInvalidStateError));
}

TEST_F(MediaStreamVideoTrackUnderlyingSinkTest, GetGmbManager) {
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform_;
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* underlying_sink = CreateUnderlyingSink(script_state);
  EXPECT_EQ(!!underlying_sink->gmb_manager(),
            WebGraphicsContext3DVideoFramePool::
                IsGpuMemoryBufferReadbackFromTextureEnabled());
}

TEST_F(MediaStreamVideoTrackUnderlyingSinkTest,
       DeltaTimestampDoesNotWriteCaptureBeginTime) {
  if (IsTooEarlyForTest()) {
    return;
  }
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* underlying_sink = CreateUnderlyingSink(script_state);
  auto* writable_stream = WritableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_sink, 1u);
  auto track = CreateTrack();

  NonThrowableExceptionState exception_state;
  auto* writer = writable_stream->getWriter(script_state, exception_state);

  VideoFrame* video_frame = nullptr;
  ScriptValue video_frame_chunk =
      CreateVideoFrameChunk(script_state, &video_frame);
  int64_t web_exposed_timestamp = video_frame->timestamp();
  scoped_refptr<media::VideoFrame> media_frame = video_frame->frame();
  EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
  EXPECT_FALSE(media_frame->metadata().capture_begin_time.has_value());

  ScriptPromiseTester write_tester(
      script_state,
      writer->write(script_state, video_frame_chunk, exception_state));
  write_tester.WaitUntilSettled();
  EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
  // No capture timestamp expected because the timestamp is a regular TimeDelta.
  EXPECT_FALSE(media_frame->metadata().capture_begin_time.has_value());
}

TEST_F(MediaStreamVideoTrackUnderlyingSinkTest,
       CaptureTimestampWritesCaptureBeginTime) {
  if (IsTooEarlyForTest()) {
    return;
  }
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* underlying_sink = CreateUnderlyingSink(script_state);
  auto* writable_stream = WritableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_sink, 1u);
  auto track = CreateTrack();

  NonThrowableExceptionState exception_state;
  auto* writer = writable_stream->getWriter(script_state, exception_state);

  VideoFrame* video_frame = nullptr;
  ScriptValue video_frame_chunk = CreateVideoFrameChunk(
      script_state, &video_frame,
      /*timestamp=*/base::TimeTicks::Now() - base::TimeTicks());
  int64_t web_exposed_timestamp = video_frame->timestamp();
  scoped_refptr<media::VideoFrame> media_frame = video_frame->frame();
  EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
  EXPECT_FALSE(media_frame->metadata().capture_begin_time.has_value());

  ScriptPromiseTester write_tester(
      script_state,
      writer->write(script_state, video_frame_chunk, exception_state));
  write_tester.WaitUntilSettled();
  EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
  // Capture timestamp expected because the timestamp looks like a capture time.
  ASSERT_TRUE(media_frame->metadata().capture_begin_time.has_value());
  EXPECT_EQ((*media_frame->metadata().capture_begin_time - base::TimeTicks())
                .InMicroseconds(),
            web_exposed_timestamp);
}

TEST_F(MediaStreamVideoTrackUnderlyingSinkTest,
       DecisionToNotWriteCaptureTimeIsSticky) {
  if (IsTooEarlyForTest()) {
    return;
  }
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* underlying_sink = CreateUnderlyingSink(script_state);
  auto* writable_stream = WritableStream::CreateWithCountQueueingStrategy(
      script_state, underlying_sink, 1u);
  auto track = CreateTrack();

  NonThrowableExceptionState exception_state;
  auto* writer = writable_stream->getWriter(script_state, exception_state);

  // Write a frame with a regular timestamp
  {
    VideoFrame* video_frame = nullptr;
    ScriptValue video_frame_chunk =
        CreateVideoFrameChunk(script_state, &video_frame);
    int64_t web_exposed_timestamp = video_frame->timestamp();
    scoped_refptr<media::VideoFrame> media_frame = video_frame->frame();
    EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
    EXPECT_FALSE(media_frame->metadata().capture_begin_time.has_value());

    ScriptPromiseTester write_tester(
        script_state,
        writer->write(script_state, video_frame_chunk, exception_state));
    write_tester.WaitUntilSettled();
    EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
    // No capture timestamp expected because the timestamp is a regular
    // TimeDelta.
    EXPECT_FALSE(media_frame->metadata().capture_begin_time.has_value());
  }

  // Write a frame with a timestamp that is a TimeTicks capture time.
  {
    VideoFrame* video_frame = nullptr;
    ScriptValue video_frame_chunk = CreateVideoFrameChunk(
        script_state, &video_frame,
        /*timestamp=*/base::TimeTicks::Now() - base::TimeTicks());
    int64_t web_exposed_timestamp = video_frame->timestamp();
    scoped_refptr<media::VideoFrame> media_frame = video_frame->frame();
    EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
    EXPECT_FALSE(media_frame->metadata().capture_begin_time.has_value());

    ScriptPromiseTester write_tester(
        script_state,
        writer->write(script_state, video_frame_chunk, exception_state));
    write_tester.WaitUntilSettled();
    EXPECT_EQ(media_frame->timestamp().InMicroseconds(), web_exposed_timestamp);
    // Capture timestamp not expected despite the TimeTicks timestamp because
    // the decision to not write capture times is sticky
    EXPECT_FALSE(media_frame->metadata().capture_begin_time.has_value());
  }
}

}  // namespace blink

"""

```