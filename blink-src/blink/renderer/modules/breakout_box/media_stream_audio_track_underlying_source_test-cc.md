Response:
Let's break down the thought process for analyzing the given C++ test file.

**1. Initial Understanding: What is the file about?**

The filename `media_stream_audio_track_underlying_source_test.cc` immediately suggests this is a test file. The `MediaStreamAudioTrackUnderlyingSource` part gives a strong hint about what's being tested:  a component involved in handling audio data within media streams. The `UnderlyingSource` suffix likely refers to an interface or mechanism for providing the actual audio data.

**2. Examining the Includes:**

The included headers provide crucial context:

* **Standard Testing Libraries:** `gtest/gtest.h`, `base/test/gmock_callback_support.h` indicate this is a unit test using Google Test and Google Mock.
* **Media Concepts:** `media/base/audio_buffer.h`, `media/base/audio_timestamp_helper.h` point to operations on audio data.
* **Blink Specifics:**
    * `third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h`:  Deals with the web-facing API for media stream tracks.
    * `third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h`:  Indicates asynchronous operations and testing of the renderer's scheduler.
    * `third_party/blink/public/web/web_heap.h`:  Relates to Blink's garbage collection.
    * `third_party/blink/renderer/bindings/...`:  Headers in this directory suggest interaction with JavaScript via V8 bindings. Specifically, `ScriptPromiseTester`, `V8_BINDING_FOR_TESTING`, and `V8_READABLE_STREAM_READ_RESULT` are strong indicators of testing asynchronous operations and streams.
    * `third_party/blink/renderer/core/streams/...`:  Headers here point to the implementation of the Streams API within Blink. `ReadableStream` and its associated controllers are key.
    * `third_party/blink/renderer/modules/breakout_box/...`: This is the directory where the tested class resides. `PushableMediaStreamAudioSource` and `StreamTestUtils` are likely helper classes.
    * `third_party/blink/renderer/modules/mediastream/...`:  More media stream related classes, including `MediaStreamTrack`, `MediaStreamTrackImpl`, and `MockMediaStreamAudioSink`. The "Mock" prefix suggests this is used for testing interactions.
    * `third_party/blink/renderer/modules/webcodecs/audio_data.h`:  Deals with the `AudioData` format, likely used when reading data from the stream.
    * `third_party/blink/renderer/platform/...`: Platform-specific implementations, including testing support.

**3. Analyzing the Test Class (`MediaStreamAudioTrackUnderlyingSourceTest`):**

* **Setup and Teardown:** The constructor and destructor handle setting up the test environment and ensuring resources are cleaned up (`WebHeap::CollectAllGarbageForTesting()`).
* **Helper Methods:**  Methods like `CreateTrack`, `CreateSource`, `PushData`, `SetChannelData`, `DataMatches`, and `CreateTestData` suggest the common operations performed in the tests. They abstract away the details of creating media stream components and manipulating audio data. The multiple `CreateSource` overloads hint at different ways to configure the source, especially regarding buffer size.
* **Member Variables:** `task_environment_` and `platform_` are common testing utilities in Chromium for managing asynchronous operations and platform dependencies.

**4. Examining the Individual Tests:**

Each `TEST_F` function focuses on a specific aspect of the `MediaStreamAudioTrackUnderlyingSource`:

* **`AudioDataFlowsThroughStreamAndCloses`:** Tests basic data flow and stream closure. It uses the Readable Streams API (`GetDefaultReaderForTesting`, `read`).
* **`CancelStreamDisconnectsFromTrack`:** Checks the behavior when a stream is cancelled, ensuring proper disconnection from the track.
* **`DropOldFramesWhenQueueIsFull`:** Tests the behavior of a bounded buffer, confirming that older frames are dropped when the queue is full. The use of `MockMediaStreamAudioSink` is significant for controlling the timing of data delivery.
* **`QueueSizeCannotBeZero`:**  A simple test to ensure a minimum queue size.
* **`PlatformSourceAliveAfterGC`:** Focuses on memory management and garbage collection, ensuring the underlying platform source survives even after the JavaScript context is gone. This is important for preventing crashes.
* **`BufferPooling_Simple`:** Tests the basic functionality of an internal buffer pool for audio data, avoiding unnecessary allocations.
* **`BufferPooling_BufferReuse`:** Verifies that the buffer pool reuses buffers when possible.
* **`BufferPooling_FormatChange`:** Checks how the buffer pool handles changes in the audio format (e.g., stereo to mono).

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The test file has strong connections to JavaScript and the Web APIs:

* **JavaScript API:** The code extensively uses Blink's internal representation of the Readable Streams API, which is directly exposed to JavaScript. The tests simulate how a JavaScript developer would interact with a ReadableStream obtained from a MediaStreamTrack. The use of `ScriptPromiseTester` highlights the asynchronous nature of stream operations in JavaScript.
* **MediaStream API:** The core of the functionality revolves around the MediaStream API, which allows web applications to access audio and video streams. The `MediaStreamTrack` and its underlying source are fundamental components of this API.
* **HTML `<audio>` element (Implicit):** While not directly tested, the underlying functionality being tested enables the `<audio>` element (and JavaScript's `AudioContext`) to consume audio data from a media stream. The tests ensure that data is delivered correctly and efficiently.

**6. Logical Inference and Assumptions:**

* **Assumption:** The `PushableMediaStreamAudioSource` is a mechanism to inject audio data into a `MediaStreamTrack`.
* **Assumption:** The `MediaStreamAudioTrackUnderlyingSource` acts as a bridge between the `MediaStreamTrack`'s audio data and a ReadableStream.
* **Inference:**  When the stream's queue is full, the `MediaStreamAudioTrackUnderlyingSource` needs a strategy to handle new incoming data, and the test confirms it drops the oldest data.

**7. Common User/Programming Errors:**

* **Not Handling Asynchronous Operations:**  Failing to properly use promises when working with Readable Streams in JavaScript can lead to unexpected behavior. The tests implicitly demonstrate the need for asynchronous handling.
* **Incorrect Stream Usage:** Attempting to read from a closed stream or canceling a stream at the wrong time are common errors. The tests for closing and canceling streams highlight these scenarios.
* **Memory Leaks:**  If the `MediaStreamAudioTrackUnderlyingSource` doesn't properly manage its connection to the `MediaStreamTrack`, it could lead to memory leaks, which the `PlatformSourceAliveAfterGC` test aims to prevent.

**8. User Operations and Debugging:**

Imagine a user wants to process the audio from their microphone in a web application.

1. **User Grants Microphone Permission:** The browser prompts the user for permission to access their microphone.
2. **JavaScript Accesses the Microphone:** JavaScript code uses `navigator.mediaDevices.getUserMedia()` to request an audio stream.
3. **Obtaining the Audio Track:** The `getUserMedia()` promise resolves with a `MediaStream`, and the JavaScript code gets the audio track from this stream (e.g., `stream.getAudioTracks()[0]`).
4. **Creating a ReadableStream:**  The user (or a library they are using) might create a `ReadableStream` from the `MediaStreamTrack` using `track.readable`. This is where the tested `MediaStreamAudioTrackUnderlyingSource` comes into play.
5. **Reading from the Stream:** The JavaScript code uses a `ReadableStreamDefaultReader` to read `AudioData` chunks from the stream.
6. **Processing the Audio:** The application can then process the `AudioData` (e.g., for visualization, analysis, or sending it to a server).

**Debugging Scenario:** If the audio processing is skipping chunks of data, a developer might suspect that data is being lost somewhere in the pipeline. They could then investigate the behavior of the `MediaStreamAudioTrackUnderlyingSource` and its queueing mechanism. The `DropOldFramesWhenQueueIsFull` test provides a clue about what might happen if the consumer isn't reading data fast enough.

This detailed thought process allows us to thoroughly understand the purpose and implications of the given C++ test file.
这个C++源代码文件 `media_stream_audio_track_underlying_source_test.cc` 是 Chromium Blink 引擎中用于测试 `MediaStreamAudioTrackUnderlyingSource` 类的单元测试文件。 `MediaStreamAudioTrackUnderlyingSource` 负责将 `MediaStreamTrack` 中的音频数据转换为可读流（ReadableStream）的底层源。

**功能总结:**

该文件的主要功能是测试 `MediaStreamAudioTrackUnderlyingSource` 类的以下方面：

1. **音频数据流的传递:** 验证音频数据能否从 `MediaStreamTrack` 正确地流向通过 `MediaStreamAudioTrackUnderlyingSource` 创建的 `ReadableStream`。
2. **流的关闭:** 测试当 `MediaStreamAudioTrackUnderlyingSource` 或其关联的 `MediaStreamTrack` 关闭时，`ReadableStream` 是否也能正确关闭。
3. **流的取消:**  验证取消 `ReadableStream` 是否会断开其与底层 `MediaStreamTrack` 的连接。
4. **队列满时的帧丢弃:** 测试当内部缓冲区满时，旧的音频帧是否会被丢弃，以防止内存溢出。
5. **最小队列大小:** 确保即使请求队列大小为零，也会分配至少为 1 的缓冲区。
6. **垃圾回收后的平台源存活:** 测试在 JavaScript 上下文被垃圾回收后，底层的平台音频源是否仍然存活，避免在清理过程中出现崩溃。
7. **音频缓冲区池化:** 测试内部的音频缓冲区池化机制，包括：
    * **简单池化:** 验证音频数据能够被正确地复制到池中的缓冲区。
    * **缓冲区重用:** 确保缓冲区在不再使用时能够被重用，减少内存分配。
    * **格式变化:** 测试当音频格式发生变化时，缓冲区池是否能够正确处理。

**与 JavaScript, HTML, CSS 的关系:**

`MediaStreamAudioTrackUnderlyingSource` 是 Web 标准 Media Streams API 的底层实现部分，该 API 可以被 JavaScript 调用。

* **JavaScript:**
    * **`MediaStreamTrack`:**  JavaScript 代码可以通过 `navigator.mediaDevices.getUserMedia()` 等 API 获取 `MediaStreamTrack` 对象，代表一个音轨或视频轨。`MediaStreamAudioTrackUnderlyingSource` 正是为这种音轨提供数据源。
    * **`ReadableStream`:**  JavaScript 可以通过 `track.readable` 属性获取一个与 `MediaStreamTrack` 关联的 `ReadableStream`。 这个 `ReadableStream` 的底层源就是 `MediaStreamAudioTrackUnderlyingSource`。 JavaScript 代码可以使用 `ReadableStreamDefaultReader` 读取流中的 `AudioData`。
    * **`AudioData`:**  从 `ReadableStream` 中读取的数据通常是 `AudioData` 对象，它封装了音频数据。这个测试文件中有使用 `AudioData` 进行断言的例子。

    **例子：**

    ```javascript
    navigator.mediaDevices.getUserMedia({ audio: true })
      .then(function(stream) {
        const audioTrack = stream.getAudioTracks()[0];
        const readableStream = audioTrack.readable;
        const reader = readableStream.getReader();

        function read() {
          reader.read().then(function(result) {
            if (result.done) {
              console.log("Stream finished");
              return;
            }
            const audioData = result.value;
            // 处理 audioData
            console.log("Received audio data", audioData);
            read();
          });
        }
        read();
      });
    ```

* **HTML:**
    * **`<audio>` 元素:**  虽然 `MediaStreamAudioTrackUnderlyingSource` 本身不直接与 HTML 元素交互，但它提供的音频数据最终可能被用于 `<audio>` 元素播放，或者被 Web Audio API 处理。

* **CSS:**
    * **无直接关系:** CSS 与 `MediaStreamAudioTrackUnderlyingSource` 没有直接的功能性联系。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个 `MediaStreamTrack` 对象，并且有音频数据被推送到该轨道。
* **输出:**  通过 `MediaStreamAudioTrackUnderlyingSource` 创建的 `ReadableStream` 可以从中读取包含这些音频数据的 `AudioData` 对象。 这些 `AudioData` 对象会按照时间顺序排列，并且其时间戳等属性与原始音频数据一致。

**例子 (基于测试用例 `AudioDataFlowsThroughStreamAndCloses`):**

1. **假设输入:** 创建了一个 `MediaStreamTrack` (`track`)，并向其推送了一些音频数据 (`PushData(track)`).
2. **逻辑推理:**  `MediaStreamAudioTrackUnderlyingSource` (`source`) 作为 `track` 的数据源，会将这些音频数据缓冲并提供给其创建的 `ReadableStream` (`stream`).
3. **输出:**  通过 `stream` 的 `reader` 读取数据 (`reader->read(...)`)，最终会得到包含之前推送的音频数据的 `AudioData` 对象。断言 (`EXPECT_TRUE(read_tester.IsFulfilled())`) 验证了读取操作成功完成。

**用户或编程常见的使用错误:**

1. **未处理异步操作:**  使用 `ReadableStream` 是异步的，如果 JavaScript 代码没有正确处理 `reader.read()` 返回的 Promise，可能会导致数据丢失或处理顺序错误。
2. **过快读取数据导致队列为空:** 如果 JavaScript 代码读取数据的速度超过了 `MediaStreamTrack` 产生数据的速度，可能会导致 `ReadableStream` 暂时没有数据可读，需要合理处理这种情况。
3. **在流关闭后继续读取:**  尝试在 `ReadableStream` 关闭后继续调用 `reader.read()` 会导致错误。
4. **不恰当的流取消:**  过早或不必要地取消 `ReadableStream` 可能会阻止音频数据的完整传输。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户打开一个使用麦克风的网页应用:**  例如一个在线会议应用或一个录音工具。
2. **网页应用请求麦克风权限:**  JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: true })`。
3. **用户同意授权:**  浏览器提示用户并获得麦克风访问权限。
4. **`getUserMedia` 返回 `MediaStream`:**  包含一个或多个 `MediaStreamTrack` 对象，其中一个是音频轨道。
5. **JavaScript 代码获取音频轨道:** 例如 `stream.getAudioTracks()[0]`。
6. **JavaScript 代码访问 `track.readable`:**  这会触发创建 `MediaStreamAudioTrackUnderlyingSource` 实例，作为 `ReadableStream` 的底层源。
7. **网页应用开始处理音频数据:**  例如，通过创建一个 `ReadableStreamDefaultReader` 并不断读取数据。

**调试线索:**

如果在用户使用网页应用的过程中出现以下问题，可能需要关注 `MediaStreamAudioTrackUnderlyingSource` 的行为：

* **音频数据丢失或断断续续:**  可能是由于 `MediaStreamAudioTrackUnderlyingSource` 的缓冲区溢出导致数据被丢弃 (测试用例 `DropOldFramesWhenQueueIsFull`)。
* **应用在后台标签页被冻结后，切换回来音频出现问题:**  可能涉及到垃圾回收后平台源的存活问题 (测试用例 `PlatformSourceAliveAfterGC`)。
* **性能问题，例如内存占用过高:**  可能与缓冲区池化机制有关 (测试用例 `BufferPooling_*`)。
* **与 `ReadableStream` 相关的错误:** 例如无法读取数据或流提前关闭 (测试用例 `AudioDataFlowsThroughStreamAndCloses`, `CancelStreamDisconnectsFromTrack`)。

通过查看这个测试文件，开发者可以了解 `MediaStreamAudioTrackUnderlyingSource` 的预期行为，并在出现问题时更好地定位和解决错误。 例如，如果怀疑是缓冲区溢出的问题，可以检查相关代码逻辑，并参考测试用例 `DropOldFramesWhenQueueIsFull` 的实现方式。

Prompt: 
```
这是目录为blink/renderer/modules/breakout_box/media_stream_audio_track_underlying_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/breakout_box/media_stream_audio_track_underlying_source.h"

#include "base/run_loop.h"
#include "base/test/gmock_callback_support.h"
#include "media/base/audio_buffer.h"
#include "media/base/audio_timestamp_helper.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/modules/breakout_box/pushable_media_stream_audio_source.h"
#include "third_party/blink/renderer/modules/breakout_box/stream_test_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_audio_sink.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"

using testing::_;
using testing::AnyNumber;

namespace blink {

namespace {
constexpr int kSampleRate = 8000;
constexpr int kFramesPerBuffer = 800;
constexpr int kNumFrames = 10;
const media::AudioParameters kMonoParams =
    media::AudioParameters(media::AudioParameters::AUDIO_PCM_LINEAR,
                           media::ChannelLayoutConfig::Mono(),
                           kSampleRate,
                           kFramesPerBuffer);

const media::AudioParameters kStereoParams =
    media::AudioParameters(media::AudioParameters::AUDIO_PCM_LINEAR,
                           media::ChannelLayoutConfig::Stereo(),
                           kSampleRate,
                           kFramesPerBuffer);

}  // namespace

class MediaStreamAudioTrackUnderlyingSourceTest : public testing::Test {
 public:
  ~MediaStreamAudioTrackUnderlyingSourceTest() override {
    platform_->RunUntilIdle();
    WebHeap::CollectAllGarbageForTesting();
  }

  MediaStreamTrack* CreateTrack(ExecutionContext* execution_context) {
    auto pushable_audio_source =
        std::make_unique<PushableMediaStreamAudioSource>(
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            platform_->GetIOTaskRunner());
    PushableMediaStreamAudioSource* pushable_audio_source_ptr =
        pushable_audio_source.get();
    MediaStreamSource* media_stream_source =
        MakeGarbageCollected<MediaStreamSource>(
            "dummy_source_id", MediaStreamSource::kTypeAudio,
            "dummy_source_name", false /* remote */,
            std::move(pushable_audio_source));
    MediaStreamComponent* component =
        MakeGarbageCollected<MediaStreamComponentImpl>(
            String::FromUTF8("audio_track"), media_stream_source,
            std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */));
    pushable_audio_source_ptr->ConnectToInitializedTrack(component);

    return MakeGarbageCollected<MediaStreamTrackImpl>(execution_context,
                                                      component);
  }

  MediaStreamAudioTrackUnderlyingSource* CreateSource(ScriptState* script_state,
                                                      MediaStreamTrack* track,
                                                      wtf_size_t buffer_size) {
    return MakeGarbageCollected<MediaStreamAudioTrackUnderlyingSource>(
        script_state, track->Component(), nullptr, buffer_size);
  }

  MediaStreamAudioTrackUnderlyingSource* CreateSource(ScriptState* script_state,
                                                      MediaStreamTrack* track) {
    return CreateSource(script_state, track, 1u);
  }

 protected:
  // Pushes data into |track|. |timestamp| is the reference time at the
  // beginning of the audio data to be pushed into |track|.
  void PushData(
      MediaStreamTrack* track,
      const std::optional<base::TimeDelta>& timestamp = std::nullopt) {
    auto data = media::AudioBuffer::CreateEmptyBuffer(
        media::ChannelLayout::CHANNEL_LAYOUT_STEREO, /*channel_count=*/2,
        kSampleRate, kNumFrames, timestamp.value_or(base::Seconds(1)));
    PushableMediaStreamAudioSource* pushable_audio_source =
        static_cast<PushableMediaStreamAudioSource*>(
            MediaStreamAudioSource::From(track->Component()->Source()));
    pushable_audio_source->PushAudioData(std::move(data));
    platform_->RunUntilIdle();
  }

  void SetChannelData(media::AudioBus* bus, int channel, float value) {
    ASSERT_LE(channel, bus->channels());

    float* bus_channel = bus->channel(channel);
    for (int i = 0; i < bus->frames(); ++i) {
      bus_channel[i] = value;
    }
  }

  bool DataMatches(scoped_refptr<media::AudioBuffer> buffer,
                   const media::AudioBus& bus) {
    EXPECT_EQ(bus.channels(), buffer->channel_count());
    EXPECT_EQ(bus.frames(), buffer->frame_count());

    for (int ch = 0; ch < bus.channels(); ch++) {
      const float* bus_channel = bus.channel(ch);
      const float* buffer_channel =
          reinterpret_cast<float*>(buffer->channel_data()[ch]);
      for (int i = 0; i < bus.frames(); ++i) {
        if (bus_channel[i] != buffer_channel[i]) {
          return false;
        }
      }
    }

    return true;
  }

  std::unique_ptr<media::AudioBus> CreateTestData(
      const media::AudioParameters params,
      float channel_value_increment) {
    auto audio_bus = media::AudioBus::Create(params);
    for (int ch = 0; ch < audio_bus->channels(); ++ch) {
      SetChannelData(audio_bus.get(), ch, (ch + 1) * channel_value_increment);
    }
    return audio_bus;
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest,
       AudioDataFlowsThroughStreamAndCloses) {
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
  PushData(track);
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsFulfilled());

  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest,
       CancelStreamDisconnectsFromTrack) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(script_state, track);
  auto* stream =
      ReadableStream::CreateWithCountQueueingStrategy(script_state, source, 0);

  // The stream is connected to a sink.
  EXPECT_TRUE(source->Track());

  NonThrowableExceptionState exception_state;
  stream->cancel(script_state, exception_state);

  // Canceling the stream disconnects it from the track.
  EXPECT_FALSE(source->Track());
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest,
       DropOldFramesWhenQueueIsFull) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  const wtf_size_t buffer_size = 5;
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(script_state, track, buffer_size);
  EXPECT_EQ(source->MaxQueueSize(), buffer_size);
  auto* stream =
      ReadableStream::CreateWithCountQueueingStrategy(script_state, source, 0);

  // Add a sink to the track to make it possible to wait until a pushed frame
  // is delivered to sinks, including |source|, which is a sink of the track.
  MockMediaStreamAudioSink mock_sink;
  WebMediaStreamAudioSink::AddToAudioTrack(
      &mock_sink, WebMediaStreamTrack(track->Component()));

  auto push_frame_sync = [&mock_sink, track,
                          this](const base::TimeDelta timestamp) {
    base::RunLoop sink_loop;
    EXPECT_CALL(mock_sink, OnData(_, _))
        .WillOnce(base::test::RunOnceClosure(sink_loop.QuitClosure()));
    PushData(track, timestamp);
    sink_loop.Run();
  };

  for (wtf_size_t i = 0; i < buffer_size; ++i) {
    base::TimeDelta timestamp = base::Seconds(i);
    push_frame_sync(timestamp);
  }

  // Push another frame while the queue is full.
  push_frame_sync(base::Seconds(buffer_size));

  // Since the queue was full, the oldest frame from the queue (timestamp 0)
  // should have been dropped.
  NonThrowableExceptionState exception_state;
  auto* reader =
      stream->GetDefaultReaderForTesting(script_state, exception_state);
  for (wtf_size_t i = 1; i <= buffer_size; ++i) {
    AudioData* audio_data = ReadObjectFromStream<AudioData>(v8_scope, reader);
    EXPECT_EQ(base::Microseconds(audio_data->timestamp()), base::Seconds(i));
  }

  // Pulling causes a pending pull since there are no frames available for
  // reading.
  EXPECT_EQ(source->NumPendingPullsForTesting(), 0);
  source->Pull(script_state, ASSERT_NO_EXCEPTION);
  EXPECT_EQ(source->NumPendingPullsForTesting(), 1);

  source->Close();
  WebMediaStreamAudioSink::RemoveFromAudioTrack(
      &mock_sink, WebMediaStreamTrack(track->Component()));
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest, QueueSizeCannotBeZero) {
  V8TestingScope v8_scope;
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(v8_scope.GetScriptState(), track, 0u);
  // Queue size is always at least 1, even if 0 is requested.
  EXPECT_EQ(source->MaxQueueSize(), 1u);
  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest, PlatformSourceAliveAfterGC) {
  // This persistent is used to make |track->Component()| (and its
  // MediaStreamAudioTrack) outlive |v8_scope| and stay alive after GC.
  Persistent<MediaStreamComponent> component;
  {
    V8TestingScope v8_scope;
    auto* track = CreateTrack(v8_scope.GetExecutionContext());
    component = track->Component();
    auto* source = CreateSource(v8_scope.GetScriptState(), track);
    ReadableStream::CreateWithCountQueueingStrategy(v8_scope.GetScriptState(),
                                                    source, 0);
    // |source| is a sink of |track|.
    EXPECT_TRUE(source->Track());
  }
  blink::WebHeap::CollectAllGarbageForTesting();
  // At this point, if |source| were still a sink of the MediaStreamAudioTrack
  // owned by |component|, the MediaStreamAudioTrack cleanup would crash since
  // it would try to access |source|, which has been garbage collected.
  // A scenario like this one could occur when an execution context is detached.
}

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest, BufferPooling_Simple) {
  V8TestingScope v8_scope;
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(v8_scope.GetScriptState(), track, 0u);
  auto* buffer_pool = source->GetAudioBufferPoolForTesting();

  // Needs to be called before CopyIntoAudioBuffer().
  buffer_pool->SetFormat(kStereoParams);

  // Create fake data with distinct channels.
  auto audio_bus = CreateTestData(kStereoParams, 0.25);
  base::TimeTicks now = base::TimeTicks::Now();

  // Send data to the pool.
  auto buffer = buffer_pool->CopyIntoAudioBuffer(*audio_bus, now);

  // Verify returned data.
  EXPECT_TRUE(DataMatches(buffer, *audio_bus));
  EXPECT_EQ(buffer->timestamp(), now - base::TimeTicks());

  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest, BufferPooling_BufferReuse) {
  V8TestingScope v8_scope;
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(v8_scope.GetScriptState(), track, 0u);
  auto* buffer_pool = source->GetAudioBufferPoolForTesting();

  // Needs to be called before CopyIntoAudioBuffer().
  buffer_pool->SetFormat(kStereoParams);

  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 0);

  // Create fake data with distinct channels.
  auto audio_bus = CreateTestData(kStereoParams, 0.25);
  auto other_audio_bus = CreateTestData(kStereoParams, 0.33);
  base::TimeTicks now = base::TimeTicks::Now();

  // Send data to the pool.
  auto buffer = buffer_pool->CopyIntoAudioBuffer(*audio_bus, now);

  // Verify returned data.
  EXPECT_TRUE(DataMatches(buffer, *audio_bus));

  // We should have allocated a single buffer.
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 1);

  // Release all references to `buffer`. The pool should still keep one.
  buffer.reset();
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 1);

  // Request a new buffer.
  auto other_buffer = buffer_pool->CopyIntoAudioBuffer(*other_audio_bus, now);

  // There should be no extra allocation since `buffer` was cleared.
  EXPECT_TRUE(DataMatches(other_buffer, *other_audio_bus));
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 1);

  // Request another buffer, without releasing `other_buffer`.
  buffer = buffer_pool->CopyIntoAudioBuffer(*audio_bus, now);

  // There should be two allocated buffers now.
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 2);

  // Make sure we didn't overwrite any data.
  EXPECT_TRUE(DataMatches(buffer, *audio_bus));
  EXPECT_TRUE(DataMatches(other_buffer, *other_audio_bus));

  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

TEST_F(MediaStreamAudioTrackUnderlyingSourceTest, BufferPooling_FormatChange) {
  V8TestingScope v8_scope;
  auto* track = CreateTrack(v8_scope.GetExecutionContext());
  auto* source = CreateSource(v8_scope.GetScriptState(), track, 0u);
  auto* buffer_pool = source->GetAudioBufferPoolForTesting();

  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 0);

  // Needs to be called before CopyIntoAudioBuffer().
  buffer_pool->SetFormat(kStereoParams);

  // Create fake data with distinct channels.
  auto stereo_audio_bus = CreateTestData(kStereoParams, 0.25);
  auto mono_audio_bus = CreateTestData(kMonoParams, 0.33);
  base::TimeTicks now = base::TimeTicks::Now();

  // Send data to the pool.
  auto buffer_a = buffer_pool->CopyIntoAudioBuffer(*stereo_audio_bus, now);
  auto buffer_b = buffer_pool->CopyIntoAudioBuffer(*stereo_audio_bus, now);

  // We should have allocated 2 buffers.
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 2);

  // Sending an identical formats should not clear the pool.
  buffer_pool->SetFormat(kStereoParams);
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 2);

  // Sending a different format should clear the pool.
  buffer_pool->SetFormat(kMonoParams);
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 0);

  // Make sure the references we are holding are still valid.
  EXPECT_TRUE(DataMatches(buffer_a, *stereo_audio_bus));
  EXPECT_TRUE(DataMatches(buffer_b, *stereo_audio_bus));

  // Send data in the new format to the pool.
  auto mono_buffer = buffer_pool->CopyIntoAudioBuffer(*mono_audio_bus, now);

  // The pool should allocate new buffers.
  EXPECT_EQ(buffer_pool->GetSizeForTesting(), 1);

  source->Close();
  track->stopTrack(v8_scope.GetExecutionContext());
}

}  // namespace blink

"""

```