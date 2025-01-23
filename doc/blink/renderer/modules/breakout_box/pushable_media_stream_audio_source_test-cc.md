Response:
Let's break down the thought process for analyzing this C++ test file and generating the explanation.

**1. Initial Scan and Keyword Identification:**

First, I quickly scanned the file for prominent keywords and structures. These immediately jump out:

* `TEST_P`, `TEST`, `EXPECT_EQ`, `ASSERT_NE`:  Indicates a testing file using the Google Test framework. The `_P` suggests parameterized tests.
* `PushableMediaStreamAudioSourceTest`:  The name of the test suite, clearly pointing to the class being tested.
* `PushableMediaStreamAudioSource`, `FakeMediaStreamAudioSink`, `MediaStreamSource`, `MediaStreamAudioTrack`:  Key classes involved in media streaming within Blink. The `Fake` prefix suggests a mock or test double.
* `ConnectSourceToTrack`, `SendEmptyBufferAndVerifyParams`, `SendDataAndVerifyParams`:  Helper methods within the test suite, revealing the core actions being tested.
* `OnData`, `OnSetFormat`:  Methods on `FakeMediaStreamAudioSink`, hinting at what it's designed to verify.
* `#include`: Standard C++ includes, telling us about dependencies.
* `// Copyright`:  Standard copyright header.
* `// TODO`: Indicates potential future work or known issues.

**2. Understanding the Test Structure:**

I noted the presence of `PushableMediaStreamAudioSourceTest` inheriting from `::testing::TestWithParam<bool>`. This means the tests are run twice, once with `true` and once with `false` for some boolean parameter. The `INSTANTIATE_TEST_SUITE_P` confirms this parameter is used.

**3. Deciphering `PushableMediaStreamAudioSource`'s Role:**

The name "PushableMediaStreamAudioSource" strongly suggests this class is responsible for *pushing* audio data into a media stream. The methods and test names reinforce this:  `PushAudioData`, `FramesPropagateToSink`.

**4. Understanding `FakeMediaStreamAudioSink`'s Role:**

The `Fake` prefix indicates this is a mock implementation. By looking at its methods (`OnData`, `OnSetFormat`, `SetupNewAudioParameterExpectations`, `SetDataTimeExpectation`), it's clear its purpose is to receive audio data and format information and verify if they match expected values. It acts as the *consumer* of the audio pushed by `PushableMediaStreamAudioSource`.

**5. Tracing the Test Flows:**

I then went through each test case (`ConnectAndStop`, `FramesPropagateToSink`, `ConvertsFormatInternally`) to understand the specific scenarios being tested:

* **`ConnectAndStop`**: Checks the lifecycle of the source, ensuring it transitions between `Live` and `Ended` states when connected and stopped.
* **`FramesPropagateToSink`**:  Verifies that audio data pushed into the source is correctly received by the sink, and that format changes are handled appropriately via `OnSetFormat`.
* **`ConvertsFormatInternally`**: Focuses on the source's ability to handle different audio data formats (interleaved vs. planar) and whether it correctly converts them before passing them to the sink.

**6. Identifying Relationships to Web Technologies:**

The presence of "MediaStream," "AudioTrack," and "WebMediaStreamAudioSink" immediately links this code to web standards related to media capture and processing. I knew these concepts are exposed to JavaScript through the `getUserMedia` API and related objects.

**7. Inferring Functionality and Potential Issues:**

Based on the code and test names, I could infer the following functionalities:

* Starting and stopping the audio source.
* Pushing raw audio data into the source.
* Handling different audio formats (channels, sample rate, frames).
* Converting between interleaved and planar audio data.
* Delivering audio data and format information to sinks.

Potential issues and common errors would likely revolve around:

* Incorrect audio format parameters.
* Pushing data on the wrong thread.
* Synchronization issues between the source and sink.
* Unexpected state transitions.

**8. Constructing the Explanation:**

With the above understanding, I started structuring the explanation:

* **Purpose:** Start with a clear statement of the file's purpose.
* **Key Functionality:** List the core functionalities tested.
* **Relationship to Web Technologies:** Explain the connection to JavaScript, HTML, and CSS (even if CSS is indirect). Provide concrete examples.
* **Logical Inference:**  Focus on the data flow and parameter verification. Create hypothetical input and output scenarios for clarity.
* **Common Errors:**  List potential user/programmer errors.
* **Debugging Clues:** Explain how a user's actions might lead to this code being executed.

**9. Refining and Adding Details:**

I then went back through the code to add more specific details:

* Mention the Google Test framework and parameterized tests.
* Explain the roles of `PushableMediaStreamAudioSource` and `FakeMediaStreamAudioSink` in detail.
* Clarify the meaning of `ShouldDeliverAudioOnAudioTaskRunner()`.
* Explain the specific checks performed in the test cases.
* Ensure the explanation is clear, concise, and easy to understand for someone familiar with web development and basic C++.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe CSS is irrelevant. **Correction:** While direct interaction is minimal, CSS can influence the visibility or layout of elements displaying the media, making it indirectly related.
* **Initial thought:**  Focus only on the C++ code. **Correction:** Emphasize the connection to web standards and JavaScript APIs to provide a broader context.
* **Initial thought:**  Omit details about the testing framework. **Correction:** Briefly mention Google Test as it's a core part of the file's structure and purpose.

By following this iterative process of scanning, understanding, inferring, and refining, I was able to generate a comprehensive and accurate explanation of the C++ test file.
这个文件 `pushable_media_stream_audio_source_test.cc` 是 Chromium Blink 引擎中用于测试 `PushableMediaStreamAudioSource` 类的单元测试文件。  `PushableMediaStreamAudioSource` 允许开发者以编程方式向一个 MediaStreamTrack 中推送音频数据。

下面列举一下它的功能：

1. **测试 `PushableMediaStreamAudioSource` 的生命周期管理:**
   - 测试了音频源的启动 (`ConnectToInitializedTrack`) 和停止 (`StopSource`)。
   - 验证了当 `PushableMediaStreamAudioSource` 启动和停止时，相关的 `MediaStreamSource` 的状态 (`ReadyState`) 是否正确更新。

2. **测试音频帧数据的传递:**
   - 验证了通过 `PushAudioData` 方法推送的音频帧数据是否能正确地传递到连接的 `WebMediaStreamAudioSink`。
   - 使用了一个假的 `FakeMediaStreamAudioSink` 来模拟实际的音频接收器，并检查接收到的数据参数（通道数、帧数、采样率）和时间戳是否与预期一致。

3. **测试音频格式的传递和处理:**
   - 验证了当推送的音频数据的格式发生变化时（例如，通道数、帧数、采样率发生改变），`WebMediaStreamAudioSink` 的 `OnSetFormat` 方法是否会被正确调用。
   - 确保了格式信息在正确的线程上被传递（主线程或音频线程，这可以通过测试的参数化进行控制）。

4. **测试内部音频格式的转换:**
   - 验证了 `PushableMediaStreamAudioSource` 能够处理不同格式的音频数据（例如，交错(interleaved)格式和平面(planar)格式）。
   - 测试了当推送交错格式的音频数据时，`PushableMediaStreamAudioSource` 能否在内部将其转换为平面格式再传递给 sink。
   - 测试了当推送已经是平面格式的数据时，是否能直接传递。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript, HTML 或 CSS 代码，但它测试的 `PushableMediaStreamAudioSource` 类是 Web API `MediaStreamTrack` 的底层实现的一部分，而 `MediaStreamTrack` 是 JavaScript 中用于处理媒体流的核心接口。

* **JavaScript:**
    - 用户可以通过 JavaScript 的 `getUserMedia()` API 获取一个 `MediaStream` 对象，其中包含音频和视频轨道 (`MediaStreamTrack`)。
    - 对于 `PushableMediaStreamAudioSource`，JavaScript 开发者可以使用自定义的逻辑生成音频数据，并通过某种机制（可能需要中间层或 Native Messaging）将数据传递到 Blink 渲染引擎，然后引擎可以使用 `PushableMediaStreamAudioSource` 将这些数据注入到一个 `MediaStreamTrack` 中。
    - 例如，一个 JavaScript 应用可能需要从一个自定义的音频处理模块或者一个 WebAssembly 模块接收音频数据，并将其添加到浏览器可以播放的媒体流中。

    ```javascript
    navigator.mediaDevices.getUserMedia({ audio: true })
      .then(function(stream) {
        const audioTrack = stream.getAudioTracks()[0];
        // 在这里，我们无法直接使用 PushableMediaStreamAudioSource，
        // 但其功能是允许底层引擎以编程方式填充 audioTrack 的数据。
        console.log("Got an audio track", audioTrack);
      });
    ```

* **HTML:**
    - HTML 的 `<audio>` 或 `<video>` 标签可以用来播放 `MediaStream` 中包含的音频轨道。
    - 当 `PushableMediaStreamAudioSource` 将音频数据推送到 `MediaStreamTrack` 后，这个轨道就可以被用作 `<audio>` 或 `<video>` 元素的 `srcObject` 属性的值，从而在网页上播放自定义生成的音频。

    ```html
    <audio id="myAudio" controls></audio>
    <script>
      navigator.mediaDevices.getUserMedia({ audio: true })
        .then(function(stream) {
          const audioTrack = stream.getAudioTracks()[0];
          const audioElement = document.getElementById('myAudio');
          audioElement.srcObject = new MediaStream([audioTrack]);
        });
    </script>
    ```

* **CSS:**
    - CSS 可以用来控制播放器 (`<audio>` 或 `<video>`) 的外观和布局，但与 `PushableMediaStreamAudioSource` 的核心功能没有直接的逻辑关系。CSS 关注的是呈现，而 `PushableMediaStreamAudioSource` 关注的是数据生成和管理。

**逻辑推理，假设输入与输出:**

假设我们有一个 `PushableMediaStreamAudioSource` 实例，并连接了一个 `FakeMediaStreamAudioSink`。

**假设输入 1:**

* **操作:** 调用 `broker_->PushAudioData` 并传入一个包含以下属性的 `media::AudioBuffer`:
    * `channels`: 2
    * `frames`: 512
    * `sample_rate`: 48000
    * 这是第一次推送数据。

* **预期输出:**
    * `FakeMediaStreamAudioSink` 的 `OnSetFormat` 方法会被调用，参数为 `channels=2`, `frames_per_buffer=512`, `sample_rate=48000`。
    * `FakeMediaStreamAudioSink` 的 `OnData` 方法会被调用，接收到的 `media::AudioBus` 的属性为 `channels=2`, `frames=512`，并且时间戳与传入的 `AudioBuffer` 的时间戳一致。

**假设输入 2:**

* **操作:** 紧接着上次操作，再次调用 `broker_->PushAudioData`，这次传入的 `media::AudioBuffer` 具有相同的格式（`channels=2`, `frames=512`, `sample_rate=48000`）。

* **预期输出:**
    * `FakeMediaStreamAudioSink` 的 `OnSetFormat` 方法**不会**被调用，因为音频格式没有改变。
    * `FakeMediaStreamAudioSink` 的 `OnData` 方法会被调用，接收到新的音频数据。

**假设输入 3:**

* **操作:** 调用 `broker_->PushAudioData` 并传入一个包含不同格式的 `media::AudioBuffer`:
    * `channels`: 1
    * `frames`: 256
    * `sample_rate`: 44100

* **预期输出:**
    * `FakeMediaStreamAudioSink` 的 `OnSetFormat` 方法会被调用，参数为 `channels=1`, `frames_per_buffer=256`, `sample_rate=44100`。
    * `FakeMediaStreamAudioSink` 的 `OnData` 方法会被调用，接收到新的音频数据，其格式与 `OnSetFormat` 中设置的一致。

**涉及用户或者编程常见的使用错误，举例说明:**

1. **在未连接 Track 的情况下推送数据:**
   - **错误:**  在调用 `ConnectToInitializedTrack` 之前就调用 `broker_->PushAudioData`。
   - **结果:** 音频数据可能被丢弃，或者导致程序崩溃（取决于具体的实现）。测试用例 `ConnectAndStop` 确保了在连接前源处于非运行状态。

2. **推送格式不一致的数据:**
   - **错误:**  假设初始推送了采样率为 48000 的数据，之后推送了采样率为 44100 的数据，但没有预期到 `OnSetFormat` 会被调用，并且接收器没有正确处理格式变化。
   - **结果:**  音频播放可能会出现速度异常或者杂音。测试用例 `FramesPropagateToSink` 验证了格式变化的处理。

3. **在错误的线程上调用 `PushAudioData`:**
   - **错误:**  如果 `PushableMediaStreamAudioSource` 被配置为在特定的音频线程上处理数据，但在主线程或其他非音频线程上调用 `PushAudioData`。
   - **结果:**  可能导致线程安全问题，数据丢失，或者程序崩溃。虽然测试用例主要关注逻辑正确性，但在实际应用中线程安全至关重要。测试中的 `ShouldDeliverAudioOnAudioTaskRunner()` 参数化了是否在音频线程上交付音频，以覆盖这方面的逻辑。

4. **忘记停止 Source:**
   - **错误:**  在使用完 `PushableMediaStreamAudioSource` 后没有调用 `StopSource`。
   - **结果:**  可能导致资源泄漏，例如音频设备或缓冲区没有被正确释放。测试用例 `ConnectAndStop` 验证了停止源的行为。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

一个用户操作导致执行到 `PushableMediaStreamAudioSource` 的典型路径可能如下：

1. **用户访问一个网页，该网页请求访问用户的麦克风或以编程方式生成音频。** 例如，一个在线音频编辑器或一个实时的音频处理应用。

2. **JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: true })` 或使用自定义的音频处理逻辑。**

3. **如果使用了自定义音频处理，JavaScript 代码会将生成的音频数据传递到 Native 代码（例如，通过 WebAssembly 或 Native Messaging）。**

4. **Native 代码（在 Blink 渲染引擎中）会创建一个 `PushableMediaStreamAudioSource` 实例。** 这通常发生在需要以编程方式控制音频流数据的情况下。

5. **Native 代码将 `PushableMediaStreamAudioSource` 连接到一个 `MediaStreamTrack`。**

6. **Native 代码通过 `broker_->PushAudioData` 方法将音频数据（以 `media::AudioBuffer` 的形式）推送到 `PushableMediaStreamAudioSource`。** 这可能是响应用户的实时操作（例如，用户在音频编辑器中拖动滑块）或根据程序逻辑定期推送数据。

7. **`PushableMediaStreamAudioSource` 处理接收到的数据，并将其传递给连接的 `WebMediaStreamAudioSink`。**

8. **`WebMediaStreamAudioSink` 最终将音频数据传递给音频后端进行播放或处理。**

**调试线索:**

如果开发者在实现或调试使用 `PushableMediaStreamAudioSource` 的功能时遇到问题，可以考虑以下调试线索：

* **断点调试:** 在 `pushable_media_stream_audio_source_test.cc` 中相关的测试用例中设置断点，例如 `FramesPropagateToSink` 或 `ConvertsFormatInternally`，可以帮助理解数据是如何流动的，以及格式转换是否按预期进行。
* **日志输出:** 在 `PushableMediaStreamAudioSource` 和 `FakeMediaStreamAudioSink` 的关键方法中添加日志输出，记录接收到的数据参数和时间戳，以及格式变化事件。
* **检查 `MediaStreamTrack` 的状态:**  查看 JavaScript 中 `MediaStreamTrack` 的状态（例如，`readyState`），以及是否有错误事件发生。
* **分析音频接收端:**  如果音频最终被播放出来，可以使用音频分析工具来检查播放的音频是否符合预期（例如，采样率、通道数）。
* **查看 Chromium 的内部日志:** Chromium 引擎本身会输出大量的调试信息，可以通过启动 Chromium 时添加特定的命令行参数来查看与 MediaStream 相关的日志。

总而言之，`pushable_media_stream_audio_source_test.cc` 文件是确保 `PushableMediaStreamAudioSource` 类功能正确性和稳定性的重要组成部分，它覆盖了该类的核心功能，并模拟了在实际应用中可能遇到的各种场景。理解这个测试文件的功能有助于开发者更好地理解 `PushableMediaStreamAudioSource` 的工作原理，以及如何正确地使用它来构建强大的 Web 音频应用。

### 提示词
```
这是目录为blink/renderer/modules/breakout_box/pushable_media_stream_audio_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/breakout_box/pushable_media_stream_audio_source.h"

#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_audio_sink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

namespace {

class FakeMediaStreamAudioSink : public WebMediaStreamAudioSink {
 public:
  FakeMediaStreamAudioSink(
      scoped_refptr<base::SingleThreadTaskRunner> main_thread,
      scoped_refptr<base::SingleThreadTaskRunner> audio_thread)
      : main_task_runner_(std::move(main_thread)),
        audio_task_runner_(std::move(audio_thread)) {}
  ~FakeMediaStreamAudioSink() override = default;

  void SetupNewAudioParameterExpectations(int channels,
                                          int frames,
                                          int sample_rate) {
    expected_channels_ = channels;
    expected_frames_ = frames;
    expected_sample_rate_ = sample_rate;
  }

  void SetDataTimeExpectation(base::TimeTicks time,
                              media::AudioBus* expected_data,
                              bool expect_data_on_audio_task_runner,
                              base::OnceClosure on_data) {
    DCHECK(!on_data_);

    expected_time_ = time;
    expected_data_ = expected_data;
    expect_data_on_audio_task_runner_ = expect_data_on_audio_task_runner;

    on_data_ = std::move(on_data);
  }

  void OnData(const media::AudioBus& data, base::TimeTicks time) override {
    // Make sure the source delivered audio data on the right thread.
    EXPECT_EQ(audio_task_runner_->BelongsToCurrentThread(),
              expect_data_on_audio_task_runner_);

    EXPECT_EQ(time, expected_time_);
    EXPECT_EQ(data.channels(), expected_channels_);
    EXPECT_EQ(data.frames(), expected_frames_);

    if (expected_data_) {
      bool unexpected_data = false;

      for (int ch = 0; ch < data.channels(); ++ch) {
        const float* actual_channel_data = data.channel(ch);
        const float* expected_channel_data = expected_data_->channel(ch);

        for (int i = 0; i < data.frames(); ++i) {
          // If we use ASSERT_EQ here, the test will hang, since |on_data_| will
          // never be called.
          EXPECT_EQ(actual_channel_data[i], expected_channel_data[i]);

          // Force an early exit to prevent log spam from EXPECT_EQ.
          if (actual_channel_data[i] != expected_channel_data[i]) {
            unexpected_data = true;
            break;
          }
        }

        if (unexpected_data)
          break;
      }
    }

    // Call this after all expectations are checked, to prevent test from
    // setting new expectations on the main thread.
    std::move(on_data_).Run();
  }

  void OnSetFormat(const media::AudioParameters& params) override {
    // Make sure the source changed parameters data on the right thread.
    if (expect_data_on_audio_task_runner_) {
      EXPECT_TRUE(audio_task_runner_->BelongsToCurrentThread());
    } else {
      EXPECT_TRUE(main_task_runner_->BelongsToCurrentThread());
    }

    // Make sure that the audio thread is different from the main thread (it
    // would be a test error if it wasn't, as it would be impossible for the
    // check above to fail).
    ASSERT_NE(audio_task_runner_->BelongsToCurrentThread(),
              main_task_runner_->BelongsToCurrentThread());

    // This should only be called once per format change.
    EXPECT_FALSE(did_receive_format_change_);

    EXPECT_EQ(params.sample_rate(), expected_sample_rate_);
    EXPECT_EQ(params.channels(), expected_channels_);
    EXPECT_EQ(params.frames_per_buffer(), expected_frames_);

    did_receive_format_change_ = true;
  }

  void ClearDidReceiveFormatChange() { did_receive_format_change_ = false; }

  bool did_receive_format_change() const { return did_receive_format_change_; }

 public:
  int expected_channels_ = 0;
  int expected_frames_ = 0;
  int expected_sample_rate_ = 0;
  bool expect_data_on_audio_task_runner_ = true;
  raw_ptr<media::AudioBus, DanglingUntriaged> expected_data_ = nullptr;
  base::TimeTicks expected_time_;

  bool did_receive_format_change_ = false;

  base::OnceClosure on_data_;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> audio_task_runner_;
};

}  // namespace

class PushableMediaStreamAudioSourceTest
    : public ::testing::TestWithParam<bool> {
 public:
  PushableMediaStreamAudioSourceTest() {
    // Use the IO thread for testing purposes. This is stricter than an audio
    // sequenced task runner needs to be.
    audio_task_runner_ = platform_->GetIOTaskRunner();
    main_task_runner_ = scheduler::GetSingleThreadTaskRunnerForTesting();

    auto pushable_audio_source =
        std::make_unique<PushableMediaStreamAudioSource>(main_task_runner_,
                                                         audio_task_runner_);
    pushable_audio_source_ = pushable_audio_source.get();
    broker_ = pushable_audio_source->GetBroker();
    broker_->SetShouldDeliverAudioOnAudioTaskRunner(
        ShouldDeliverAudioOnAudioTaskRunner());
    stream_source_ = MakeGarbageCollected<MediaStreamSource>(
        "dummy_source_id", MediaStreamSource::kTypeAudio, "dummy_source_name",
        false /* remote */, std::move(pushable_audio_source));
    stream_component_ = MakeGarbageCollected<MediaStreamComponentImpl>(
        stream_source_->Id(), stream_source_,
        std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */));
  }

  void TearDown() override {
    stream_source_ = nullptr;
    stream_component_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  bool ConnectSourceToTrack() {
    return pushable_audio_source_->ConnectToInitializedTrack(stream_component_);
  }

  void SendEmptyBufferAndVerifyParams(FakeMediaStreamAudioSink* fake_sink,
                                      int channels,
                                      int frames,
                                      int sample_rate,
                                      bool expect_format_change) {
    SendDataAndVerifyParams(fake_sink, channels, frames, sample_rate,
                            expect_format_change, nullptr, nullptr);
  }

  void SendDataAndVerifyParams(FakeMediaStreamAudioSink* fake_sink,
                               int channels,
                               int frames,
                               int sample_rate,
                               bool expect_format_change,
                               scoped_refptr<media::AudioBuffer> buffer,
                               media::AudioBus* expected_data) {
    fake_sink->ClearDidReceiveFormatChange();

    if (expect_format_change) {
      fake_sink->SetupNewAudioParameterExpectations(channels, frames,
                                                    sample_rate);
    }

    if (!buffer) {
      base::TimeTicks timestamp = base::TimeTicks::Now();
      buffer = media::AudioBuffer::CreateEmptyBuffer(
          media::GuessChannelLayout(channels), channels, sample_rate, frames,
          timestamp - base::TimeTicks());
    }

    base::RunLoop run_loop;
    fake_sink->SetDataTimeExpectation(
        base::TimeTicks() + buffer->timestamp(), expected_data,
        ShouldDeliverAudioOnAudioTaskRunner(), run_loop.QuitClosure());
    broker_->PushAudioData(std::move(buffer));
    run_loop.Run();

    EXPECT_EQ(fake_sink->did_receive_format_change(), expect_format_change);
  }

  bool ShouldDeliverAudioOnAudioTaskRunner() const { return GetParam(); }

 protected:
  test::TaskEnvironment task_environment_;

  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;

  Persistent<MediaStreamSource> stream_source_;
  Persistent<MediaStreamComponent> stream_component_;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> audio_task_runner_;

  raw_ptr<PushableMediaStreamAudioSource, DanglingUntriaged>
      pushable_audio_source_;
  scoped_refptr<PushableMediaStreamAudioSource::Broker> broker_;
};

TEST_P(PushableMediaStreamAudioSourceTest, ConnectAndStop) {
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_FALSE(pushable_audio_source_->IsRunning());

  EXPECT_TRUE(ConnectSourceToTrack());
  EXPECT_EQ(MediaStreamSource::kReadyStateLive,
            stream_source_->GetReadyState());
  EXPECT_TRUE(pushable_audio_source_->IsRunning());

  // If the pushable source stops, the MediaStreamSource should stop.
  pushable_audio_source_->StopSource();
  EXPECT_EQ(MediaStreamSource::kReadyStateEnded,
            stream_source_->GetReadyState());
  EXPECT_FALSE(pushable_audio_source_->IsRunning());
}

TEST_P(PushableMediaStreamAudioSourceTest, FramesPropagateToSink) {
  EXPECT_TRUE(ConnectSourceToTrack());
  FakeMediaStreamAudioSink fake_sink(main_task_runner_, audio_task_runner_);

  WebMediaStreamAudioSink::AddToAudioTrack(
      &fake_sink, WebMediaStreamTrack(stream_component_.Get()));

  constexpr int kChannels = 1;
  constexpr int kFrames = 256;
  constexpr int kSampleRate = 8000;

  // The first audio data pushed should trigger a call to OnSetFormat().
  SendEmptyBufferAndVerifyParams(&fake_sink, kChannels, kFrames, kSampleRate,
                                 /*expect_format_change=*/true);

  // Using the same audio parameters should not trigger OnSetFormat().
  SendEmptyBufferAndVerifyParams(&fake_sink, kChannels, kFrames, kSampleRate,
                                 /*expect_format_change=*/false);

  // Format changes should trigger OnSetFormat().
  SendEmptyBufferAndVerifyParams(&fake_sink, kChannels * 2, kFrames * 4,
                                 /*sample_rate=*/44100,
                                 /*expect_format_change=*/true);

  WebMediaStreamAudioSink::RemoveFromAudioTrack(
      &fake_sink, WebMediaStreamTrack(stream_component_.Get()));
}

TEST_P(PushableMediaStreamAudioSourceTest, ConvertsFormatInternally) {
  EXPECT_TRUE(ConnectSourceToTrack());
  FakeMediaStreamAudioSink fake_sink(main_task_runner_, audio_task_runner_);

  WebMediaStreamAudioSink::AddToAudioTrack(
      &fake_sink, WebMediaStreamTrack(stream_component_.Get()));

  constexpr media::ChannelLayout kChannelLayout =
      media::ChannelLayout::CHANNEL_LAYOUT_STEREO;
  constexpr int kChannels = 2;
  constexpr int kSampleRate = 8000;
  constexpr int kFrames = 256;
  constexpr base::TimeDelta kDefaultTimeStamp = base::Milliseconds(123);

  auto interleaved_buffer = media::AudioBuffer::CreateBuffer(
      media::SampleFormat::kSampleFormatF32, kChannelLayout, kChannels,
      kSampleRate, kFrames);
  interleaved_buffer->set_timestamp(kDefaultTimeStamp);

  // Create interleaved data, with negative values on the second channel.
  float* interleaved_buffer_data =
      reinterpret_cast<float*>(interleaved_buffer->channel_data()[0]);
  for (int i = 0; i < kFrames; ++i) {
    float value = static_cast<float>(i) / kFrames;

    interleaved_buffer_data[0] = value;
    interleaved_buffer_data[1] = -value;
    interleaved_buffer_data += 2;
  }

  // Create reference planar data.
  auto expected_data = media::AudioBus::Create(kChannels, kFrames);
  float* bus_data_ch_0 = expected_data->channel(0);
  float* bus_data_ch_1 = expected_data->channel(1);
  for (int i = 0; i < kFrames; ++i) {
    float value = static_cast<float>(i) / kFrames;
    bus_data_ch_0[i] = value;
    bus_data_ch_1[i] = -value;
  }

  // Sanity check.
  DCHECK(!expected_data->AreFramesZero());

  // Send the data to the pushable source, which should internally convert the
  // interleaved data to planar data before delivering it to sinks.
  SendDataAndVerifyParams(&fake_sink, kChannels, kFrames, kSampleRate,
                          /*expect_format_change=*/true,
                          std::move(interleaved_buffer), expected_data.get());

  auto planar_buffer = media::AudioBuffer::CopyFrom(
      kSampleRate, kDefaultTimeStamp, expected_data.get());

  // The pushable source shouldn't have to convert data internally, and should
  // just wrap it.
  SendDataAndVerifyParams(&fake_sink, kChannels, kFrames, kSampleRate,
                          /*expect_format_change=*/false,
                          std::move(planar_buffer), expected_data.get());

  WebMediaStreamAudioSink::RemoveFromAudioTrack(
      &fake_sink, WebMediaStreamTrack(stream_component_.Get()));
}

// Tests with audio delivered on a dedicated audio task (GetParam() == true) and
// using the calling task (GetParam() == false).
INSTANTIATE_TEST_SUITE_P(/*no prefix*/,
                         PushableMediaStreamAudioSourceTest,
                         ::testing::Bool());

}  // namespace blink
```