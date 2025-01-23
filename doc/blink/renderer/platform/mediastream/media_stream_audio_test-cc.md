Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive summary.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of a specific Chromium Blink test file (`media_stream_audio_test.cc`). The request also asks to relate it to web technologies (JavaScript, HTML, CSS), provide logical reasoning with examples, and identify common usage errors.

**2. Core Purpose of a Test File:**

The first and most important step is to recognize this is a *test file*. Its primary purpose is to verify the correctness and functionality of other code. In this case, it's testing audio-related parts of the MediaStream API within the Blink rendering engine.

**3. High-Level Overview of the Code:**

Quickly scan the `#include` directives and the overall structure. This reveals:

* **Testing Framework:**  The inclusion of `<testing/gtest/include/gtest/gtest.h>` clearly indicates the use of Google Test.
* **Media-Related Includes:**  Headers like `media/base/audio_bus.h`, `media/base/audio_parameters.h`, and `third_party/blink/public/platform/modules/mediastream/web_media_stream_audio_sink.h` strongly suggest this file tests audio stream functionality.
* **Blink-Specific Includes:** Includes starting with `third_party/blink/` confirm it's within the Blink engine.
* **Helper Classes:**  Notice the definition of `FakeMediaStreamAudioSource` and `FakeMediaStreamAudioSink`. This is a common pattern in testing – creating mock or stub implementations to isolate the code under test.

**4. Analyzing `FakeMediaStreamAudioSource`:**

* **Purpose:**  The comment "A simple MediaStreamAudioSource..." clearly states its intent. It simulates an audio source.
* **Key Features:**  It generates monotonically increasing sample values. This is a simple yet effective way to verify data flow. It also has mechanisms to control buffer size and track lifecycle.
* **Threading:** The use of `base::PlatformThread` is significant. It means the fake source operates on a separate thread, mimicking the real-time nature of audio capture.
* **Inputs/Outputs (Hypothetical):**
    * *Input:*  Starts when a track connects.
    * *Output:*  `media::AudioBus` objects containing increasing sample values. The format is determined by `SetFormat`.
* **Relation to Web Technologies:**  It *simulates* the backend of a `MediaStreamTrack` obtained from JavaScript's `getUserMedia()`.

**5. Analyzing `FakeMediaStreamAudioSink`:**

* **Purpose:**  The comment "A simple WebMediaStreamAudioSink..." indicates it's a test consumer of audio data.
* **Key Features:** It verifies the correctness of the received audio data (sample values, format, silence detection) and tracks the "enabled" state.
* **Inputs/Outputs (Hypothetical):**
    * *Input:* `media::AudioBus` objects from a `MediaStreamTrack`.
    * *Output:*  Assertions (using `ASSERT_EQ`, `CHECK_LE`, etc.) within the `OnData` method to verify the received data.
* **Relation to Web Technologies:** It *simulates* a JavaScript object that would consume audio from a `MediaStreamTrack`, potentially using a `MediaStreamDestination`.

**6. Analyzing the `MediaStreamAudioTest` Fixture:**

* **Purpose:** Sets up the common test environment.
* **Key Actions:** Creates instances of `MediaStreamSource` and `MediaStreamComponentImpl` using the `FakeMediaStreamAudioSource`. This represents the core building blocks of a media stream.
* **`SetUp` and `TearDown`:** Standard Google Test setup and cleanup.

**7. Analyzing Individual Test Cases (using representative examples):**

* **`BasicUsage`:**
    * **Goal:** Verifies the fundamental source-track-sink connection.
    * **Key Actions:** Connects the track, adds a sink, waits for data, checks parameters, stops the track.
    * **Relationship to Web:** Models the basic flow of audio data after `getUserMedia()` and connecting a sink.
* **`EnableAndDisableTracks`:**
    * **Goal:** Tests the `enabled` property of a `MediaStreamTrack`.
    * **Key Actions:**  Enables and disables tracks, verifies that the sink receives audio or silence accordingly, and checks the `OnEnabledChanged` callback.
    * **Relationship to Web:** Directly tests the behavior of `track.enabled = true/false` in JavaScript.

**8. Identifying Relationships with Web Technologies:**

This involves connecting the C++ test code back to the JavaScript/HTML/CSS world:

* **`getUserMedia()`:**  The `FakeMediaStreamAudioSource` simulates the audio source provided by this API.
* **`MediaStreamTrack`:** The `MediaStreamAudioTrack` in the test directly corresponds to the JavaScript `MediaStreamTrack` object.
* **`MediaStreamDestination`:** The `FakeMediaStreamAudioSink` emulates the behavior of a destination that consumes the audio from a track. While not directly a 1:1 mapping, it represents the consumption side.
* **`track.enabled`:** The `EnableAndDisableTracks` test directly relates to this JavaScript property.
* **HTML `<audio>` element:**  While not directly tested, the underlying audio data flow being validated is crucial for the `<audio>` element to function correctly when a `MediaStream` is used as its source.

**9. Identifying Potential User/Programming Errors:**

Think about how a developer might misuse these APIs in JavaScript:

* **Not checking `track.readyState`:** The `AddSinkToStoppedTrack` test highlights the importance of checking if a track is "ended" before adding a sink.
* **Assuming immediate data flow:** The tests implicitly show that there's some latency involved in setting up the audio pipeline.
* **Incorrectly handling `track.enabled`:**  For example, starting processing expecting audio when the track is disabled.

**10. Structuring the Output:**

Organize the information logically with clear headings and bullet points. Start with a high-level summary, then delve into the details of each component. Provide concrete examples and connect the C++ code to the web technologies. Finally, address the user error aspect.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Focusing too much on the low-level C++ details.
* **Correction:** Shift focus to the *purpose* of the tests and how they relate to the web API.
* **Initial thought:**  Only listing the direct API mappings.
* **Correction:**  Thinking more broadly about the overall functionality and how the tests ensure the correct behavior of the web API.
* **Ensuring clarity:** Using clear and concise language, avoiding jargon where possible, and providing illustrative examples.

By following these steps, the comprehensive and accurate summary can be generated. The key is to understand the *context* of the code (it's a test file), analyze the individual components, and then connect them back to the user-facing web technologies.
这个文件 `media_stream_audio_test.cc` 是 Chromium Blink 引擎中用于测试 **MediaStream API** 中 **音频流** 相关功能的单元测试文件。它使用 Google Test 框架来验证音频流的各种行为和交互。

**主要功能：**

1. **测试 `MediaStreamAudioSource`:**  该文件包含了对 `MediaStreamAudioSource` 类的测试。`MediaStreamAudioSource` 代表了音频数据的来源，例如麦克风输入。测试会验证其启动、停止、格式更改以及向 `MediaStreamAudioTrack` 传递音频数据的能力。

2. **测试 `MediaStreamAudioTrack`:**  文件测试了 `MediaStreamAudioTrack` 类的行为。`MediaStreamAudioTrack` 代表了音频轨道，可以被添加到 `MediaStream` 中。测试会验证音频数据的接收、静音/非静音状态的切换、以及与 `WebMediaStreamAudioSink` 的交互。

3. **测试 `WebMediaStreamAudioSink`:**  该文件包含了对 `WebMediaStreamAudioSink` 接口的测试。`WebMediaStreamAudioSink` 代表了音频数据的接收者，例如用于在 `<audio>` 元素中播放或进行 Web Audio API 处理。测试会验证音频数据的接收、格式信息的获取、以及 track 的 `enabled` 状态变化通知。

4. **验证音频数据流:**  核心功能是验证音频数据从 `MediaStreamAudioSource` 经过 `MediaStreamAudioTrack` 流向 `WebMediaStreamAudioSink` 的过程是否正确。测试会检查音频数据的格式、内容（通过生成特定的单调递增的样本值进行验证）、以及时间戳等信息。

5. **测试 Track 的启用和禁用:** 文件测试了 `MediaStreamAudioTrack` 的 `enabled` 属性如何影响音频流。当 track 被禁用时，sink 应该接收到静音音频。

6. **测试格式更改:** 测试了当 `MediaStreamAudioSource` 的音频格式发生变化时，这个变化能否正确地传递到 `MediaStreamAudioTrack` 和 `WebMediaStreamAudioSink`。

7. **测试 Track 的生命周期:**  测试了 track 的启动、停止以及与 source 的连接和断开等生命周期事件。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 测试文件虽然本身不包含 JavaScript, HTML, CSS 代码，但它所测试的功能是 Web API 的核心部分，直接影响这些 Web 技术的功能：

* **JavaScript:**
    * **`getUserMedia()`:**  `MediaStreamAudioSource` 模拟了 `getUserMedia()` API 获取到的音频输入源。测试确保了当 JavaScript 调用 `getUserMedia()` 获取到音频流后，底层 C++ 代码能够正确处理和传递音频数据。
    * **`MediaStreamTrack`:**  `MediaStreamAudioTrack` 直接对应 JavaScript 中的 `MediaStreamTrack` 对象。测试验证了 JavaScript 操作 `MediaStreamTrack` 对象（例如设置 `enabled` 属性）时，底层 C++ 代码的行为是否符合预期。
    * **`MediaStream`:** 虽然测试文件没有直接创建 `MediaStream` 对象，但 `MediaStreamAudioTrack` 是 `MediaStream` 的组成部分，测试保证了音频 track 在 `MediaStream` 中的正常工作。
    * **`MediaStreamDestination` (通过 `WebMediaStreamAudioSink`)**: `WebMediaStreamAudioSink` 模拟了 JavaScript 中用于接收和处理 `MediaStreamTrack` 音频数据的 destination。例如，使用 `MediaStreamDestination` 将音频流连接到 Web Audio API 进行进一步处理。

* **HTML:**
    * **`<audio>` 元素:** 当 JavaScript 将一个包含音频 track 的 `MediaStream` 对象赋值给 `<audio>` 元素的 `srcObject` 属性时，`WebMediaStreamAudioSink` 的实现最终会负责将音频数据传递给浏览器的音频渲染器，从而在 HTML 页面上播放音频。

* **CSS:** CSS 本身与音频流的功能没有直接关系。

**举例说明：**

假设以下 JavaScript 代码：

```javascript
navigator.mediaDevices.getUserMedia({ audio: true })
  .then(function(stream) {
    const audioTrack = stream.getAudioTracks()[0];
    const audioElement = document.querySelector('audio');
    audioElement.srcObject = stream; // 将 MediaStream 设置为 audio 元素的来源

    // 一段时间后禁用音频轨道
    setTimeout(() => {
      audioTrack.enabled = false;
    }, 5000);
  });
```

* **与 `FakeMediaStreamAudioSource` 的关系：**  `FakeMediaStreamAudioSource` 在测试中模拟了 `getUserMedia({ audio: true })`  成功返回的音频源。测试会验证这个模拟的源能否正确地产生音频数据。
* **与 `MediaStreamAudioTrack` 的关系：**  JavaScript 中的 `audioTrack` 对象对应着 C++ 中的 `MediaStreamAudioTrack` 实例。测试文件中的 `EnableAndDisableTracks` 测试用例，就模拟了 JavaScript 中设置 `audioTrack.enabled = false` 时的行为，验证了当 track 被禁用时，sink 是否会接收到静音音频。
* **与 `WebMediaStreamAudioSink` 的关系：**  当 `audioElement.srcObject = stream` 时，浏览器内部会将 `stream` 中的音频 track 连接到一个 sink，以便将音频数据渲染到 audio 元素。`FakeMediaStreamAudioSink` 模拟了这个 sink 的行为，测试验证了它能否正确接收并处理来自 track 的音频数据，包括在 track 被禁用时接收到静音音频。

**逻辑推理和假设输入/输出：**

**测试用例：`BasicUsage`**

* **假设输入:**
    * 创建一个 `FakeMediaStreamAudioSource`。
    * 创建一个 `MediaStreamComponentImpl` (包含 `MediaStreamAudioTrack`) 并连接到 source。
    * 创建一个 `FakeMediaStreamAudioSink` 并添加到 track。
* **逻辑推理:**
    1. 连接 track 到 source 应该启动 source 的音频线程。
    2. sink 应该开始接收来自 track 的音频数据，数据内容是单调递增的样本值。
    3. sink 的 `OnData()` 方法应该被多次调用。
    4. 音频参数（采样率、缓冲区大小等）应该正确地传递到 track 和 sink。
    5. 停止 track 应该停止 source 的音频线程。
    6. sink 应该收到 `ReadyStateEnded` 通知。
* **预期输出:**
    * `source()->was_started()` 为 `true`。
    * `sink.num_on_data_calls()` 的值大于 0。
    * `track()->GetOutputFormat()` 和 `sink.params()` 返回的音频参数匹配预期。
    * `source()->was_stopped()` 为 `true`。
    * `sink.was_ended()` 为 `true`。

**涉及用户或编程常见的使用错误：**

1. **在 Track 停止后尝试添加 Sink:** `AddSinkToStoppedTrack` 测试用例模拟了这种情况。如果 JavaScript 代码尝试在一个已经停止的 `MediaStreamTrack` 上添加 sink，那么 sink 应该立即收到 `ReadyStateEnded` 通知，并且不会接收到任何音频数据。这提醒开发者需要注意 track 的生命周期状态。

   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: true })
     .then(function(stream) {
       const audioTrack = stream.getAudioTracks()[0];
       audioTrack.stop(); // 先停止 track

       const audioDestination = new MediaStreamDestination(audioTrack); // 假设的 sink 创建方式

       // 错误用法：在 track 停止后添加 sink，可能导致 sink 无法正常工作
     });
   ```

2. **没有处理 Track 的 `enabled` 状态:** 开发者可能会错误地假设音频总是会从 track 流出，而忽略了 `enabled` 属性。例如，在一个音视频通话应用中，如果麦克风 track 被禁用，但仍然按照启用状态处理音频，可能会导致意外的行为。`EnableAndDisableTracks` 测试用例强调了正确处理 track 的启用和禁用状态的重要性。

   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: true })
     .then(function(stream) {
       const audioTrack = stream.getAudioTracks()[0];
       // ... 一些操作后禁用 track
       audioTrack.enabled = false;

       // 错误假设：仍然认为 audioTrack 会产生音频数据
       const processor = audioContext.createScriptProcessor(1024, 1, 1);
       const source = audioContext.createMediaStreamSource(stream);
       source.connect(processor);
       processor.connect(audioContext.destination);

       processor.onaudioprocess = function(audioProcessingEvent) {
         const inputBuffer = audioProcessingEvent.inputBuffer;
         // ... 可能错误地处理静音数据，或者期望这里有非静音数据
       };
     });
   ```

3. **没有处理 Track 的 `readyState` 变化:** 开发者可能没有正确监听和处理 `MediaStreamTrack` 的 `readyState` 变化事件（例如从 "live" 变为 "ended"）。`ConnectTrackAfterSourceStopped` 测试用例模拟了在 source 停止后连接 track 的情况，这会导致 track 的 `readyState` 直接为 "ended"。没有正确处理这个状态可能导致程序逻辑错误。

   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: true })
     .then(function(stream) {
       const audioTrack = stream.getAudioTracks()[0];
       // ... 一些操作后，假设底层 source 已经停止
       audioTrack.addEventListener('ended', () => {
         console.log('Audio track ended');
       });

       // 错误用法：假设 track 始终处于 "live" 状态
       const processor = audioContext.createMediaStreamSource(stream);
       // ... 如果 source 已经停止，这里可能会出错或产生意外行为
     });
   ```

总而言之，`media_stream_audio_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎中音频流功能的正确性和稳定性，这些功能直接支撑着 Web 平台上各种音频相关的应用场景。理解这个文件的功能有助于理解 Web MediaStream API 的底层实现和行为。

### 提示词
```
这是目录为blink/renderer/platform/mediastream/media_stream_audio_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <stdint.h>

#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/task_environment.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "media/base/audio_bus.h"
#include "media/base/audio_glitch_info.h"
#include "media/base/audio_parameters.h"
#include "media/base/audio_timestamp_helper.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_audio_sink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_deliverer.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_track_platform.h"

namespace blink {

namespace {

constexpr int kSampleRate = 8000;
constexpr int kBufferSize = kSampleRate / 100;

// The maximum integer that can be exactly represented by the float data type.
constexpr int kMaxValueSafelyConvertableToFloat = 1 << 24;

// A simple MediaStreamAudioSource that spawns a real-time audio thread and
// emits audio samples with monotonically-increasing sample values. Includes
// hooks for the unit tests to confirm lifecycle status and to change audio
// format.
class FakeMediaStreamAudioSource final : public MediaStreamAudioSource,
                                         public base::PlatformThread::Delegate {
 public:
  FakeMediaStreamAudioSource()
      : MediaStreamAudioSource(scheduler::GetSingleThreadTaskRunnerForTesting(),
                               true),
        stop_event_(base::WaitableEvent::ResetPolicy::MANUAL,
                    base::WaitableEvent::InitialState::NOT_SIGNALED),
        next_buffer_size_(kBufferSize),
        sample_count_(0) {}

  FakeMediaStreamAudioSource(const FakeMediaStreamAudioSource&) = delete;
  FakeMediaStreamAudioSource& operator=(const FakeMediaStreamAudioSource&) =
      delete;

  ~FakeMediaStreamAudioSource() override {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    EnsureSourceIsStopped();
  }

  bool was_started() const {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    return !thread_.is_null();
  }

  bool was_stopped() const {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    return stop_event_.IsSignaled();
  }

  void SetBufferSize(int new_buffer_size) {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    base::subtle::NoBarrier_Store(&next_buffer_size_, new_buffer_size);
  }

 protected:
  bool EnsureSourceIsStarted() final {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    if (was_started())
      return true;
    if (was_stopped())
      return false;
    base::PlatformThread::CreateWithType(0, this, &thread_,
                                         base::ThreadType::kRealtimeAudio);
    return true;
  }

  void EnsureSourceIsStopped() final {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    if (was_stopped())
      return;
    stop_event_.Signal();
    if (was_started())
      base::PlatformThread::Join(thread_);
  }

  void ThreadMain() override {
    while (!stop_event_.IsSignaled()) {
      // If needed, notify of the new format and re-create |audio_bus_|.
      const int buffer_size = base::subtle::NoBarrier_Load(&next_buffer_size_);
      if (!audio_bus_ || audio_bus_->frames() != buffer_size) {
        MediaStreamAudioSource::SetFormat(media::AudioParameters(
            media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
            media::ChannelLayoutConfig::Mono(), kSampleRate, buffer_size));
        audio_bus_ = media::AudioBus::Create(1, buffer_size);
      }

      // Deliver the next chunk of audio data. Each sample value is its offset
      // from the very first sample.
      float* const data = audio_bus_->channel(0);
      for (int i = 0; i < buffer_size; ++i)
        data[i] = ++sample_count_;
      CHECK_LT(sample_count_, kMaxValueSafelyConvertableToFloat);
      MediaStreamAudioSource::DeliverDataToTracks(*audio_bus_,
                                                  base::TimeTicks::Now(), {});

      // Sleep before producing the next chunk of audio.
      base::PlatformThread::Sleep(base::Microseconds(
          base::Time::kMicrosecondsPerSecond * buffer_size / kSampleRate));
    }
  }

 private:
  THREAD_CHECKER(main_thread_checker_);

  base::PlatformThreadHandle thread_;
  mutable base::WaitableEvent stop_event_;

  base::subtle::Atomic32 next_buffer_size_;
  std::unique_ptr<media::AudioBus> audio_bus_;
  int sample_count_;
};

// A simple WebMediaStreamAudioSink that consumes audio and confirms the
// sample values. Includes hooks for the unit tests to monitor the format and
// flow of audio, whether the audio is silent, and the propagation of the
// "enabled" state.
class FakeMediaStreamAudioSink final : public WebMediaStreamAudioSink {
 public:
  enum EnableState { kNoEnableNotification, kWasEnabled, kWasDisabled };

  FakeMediaStreamAudioSink()
      : WebMediaStreamAudioSink(),
        expected_sample_count_(-1),
        num_on_data_calls_(0),
        audio_is_silent_(true),
        was_ended_(false),
        enable_state_(kNoEnableNotification) {}

  FakeMediaStreamAudioSink(const FakeMediaStreamAudioSink&) = delete;
  FakeMediaStreamAudioSink& operator=(const FakeMediaStreamAudioSink&) = delete;

  ~FakeMediaStreamAudioSink() override {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
  }

  media::AudioParameters params() const {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    base::AutoLock auto_lock(params_lock_);
    return params_;
  }

  int num_on_data_calls() const {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    return base::subtle::NoBarrier_Load(&num_on_data_calls_);
  }

  bool is_audio_silent() const {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    return !!base::subtle::NoBarrier_Load(&audio_is_silent_);
  }

  bool was_ended() const {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    return was_ended_;
  }

  EnableState enable_state() const {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    return enable_state_;
  }

  void OnSetFormat(const media::AudioParameters& params) final {
    ASSERT_TRUE(params.IsValid());
    base::AutoLock auto_lock(params_lock_);
    params_ = params;
  }

  void OnData(const media::AudioBus& audio_bus,
              base::TimeTicks estimated_capture_time) final {
    ASSERT_TRUE(params_.IsValid());
    ASSERT_FALSE(was_ended_);

    ASSERT_EQ(params_.channels(), audio_bus.channels());
    ASSERT_EQ(params_.frames_per_buffer(), audio_bus.frames());
    if (audio_bus.AreFramesZero()) {
      base::subtle::NoBarrier_Store(&audio_is_silent_, 1);
      expected_sample_count_ = -1;  // Reset for when audio comes back.
    } else {
      base::subtle::NoBarrier_Store(&audio_is_silent_, 0);
      const float* const data = audio_bus.channel(0);
      if (expected_sample_count_ == -1)
        expected_sample_count_ = static_cast<int64_t>(data[0]);
      CHECK_LE(expected_sample_count_ + audio_bus.frames(),
               kMaxValueSafelyConvertableToFloat);
      for (int i = 0; i < audio_bus.frames(); ++i) {
        const float expected_sample_value = expected_sample_count_;
        ASSERT_EQ(expected_sample_value, data[i]);
        ++expected_sample_count_;
      }
    }

    ASSERT_TRUE(!estimated_capture_time.is_null());
    ASSERT_LT(last_estimated_capture_time_, estimated_capture_time);
    last_estimated_capture_time_ = estimated_capture_time;

    base::subtle::NoBarrier_AtomicIncrement(&num_on_data_calls_, 1);
  }

  void OnReadyStateChanged(WebMediaStreamSource::ReadyState state) final {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    if (state == WebMediaStreamSource::kReadyStateEnded)
      was_ended_ = true;
  }

  void OnEnabledChanged(bool enabled) final {
    DCHECK_CALLED_ON_VALID_THREAD(main_thread_checker_);
    enable_state_ = enabled ? kWasEnabled : kWasDisabled;
  }

 private:
  THREAD_CHECKER(main_thread_checker_);

  mutable base::Lock params_lock_;
  media::AudioParameters params_;
  int expected_sample_count_;
  base::TimeTicks last_estimated_capture_time_;
  base::subtle::Atomic32 num_on_data_calls_;
  base::subtle::Atomic32 audio_is_silent_;
  bool was_ended_;
  EnableState enable_state_;
};

}  // namespace

class MediaStreamAudioTest : public ::testing::Test {
 protected:
  void SetUp() override {
    audio_source_ = MakeGarbageCollected<MediaStreamSource>(
        String::FromUTF8("audio_id"), MediaStreamSource::kTypeAudio,
        String::FromUTF8("audio_track"), false /* remote */,
        std::make_unique<FakeMediaStreamAudioSource>());
    audio_component_ = MakeGarbageCollected<MediaStreamComponentImpl>(
        audio_source_->Id(), audio_source_,
        std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */));
  }

  void TearDown() override {
    audio_component_ = nullptr;
    audio_source_ = nullptr;
    WebHeap::CollectAllGarbageForTesting();
  }

  FakeMediaStreamAudioSource* source() const {
    return static_cast<FakeMediaStreamAudioSource*>(
        MediaStreamAudioSource::From(audio_source_.Get()));
  }

  MediaStreamAudioTrack* track() const {
    return MediaStreamAudioTrack::From(audio_component_.Get());
  }

  Persistent<MediaStreamSource> audio_source_;
  Persistent<MediaStreamComponent> audio_component_;

  base::test::TaskEnvironment task_environment_;
};

// Tests that a simple source-->track-->sink connection and audio data flow
// works.
TEST_F(MediaStreamAudioTest, BasicUsage) {
  // Create the source, but it should not be started yet.
  ASSERT_TRUE(source());
  EXPECT_FALSE(source()->was_started());
  EXPECT_FALSE(source()->was_stopped());

  // Connect a track to the source. This should auto-start the source.
  EXPECT_TRUE(source()->ConnectToInitializedTrack(audio_component_));
  ASSERT_TRUE(track());
  EXPECT_TRUE(source()->was_started());
  EXPECT_FALSE(source()->was_stopped());

  // Connect a sink to the track. This should begin audio flow to the
  // sink. Wait and confirm that three OnData() calls were made from the audio
  // thread.
  FakeMediaStreamAudioSink sink;
  EXPECT_FALSE(sink.was_ended());
  track()->AddSink(&sink);
  const int start_count = sink.num_on_data_calls();
  while (sink.num_on_data_calls() - start_count < 3)
    base::PlatformThread::Sleep(TestTimeouts::tiny_timeout());

  // Check that the audio parameters propagated to the track and sink.
  const media::AudioParameters expected_params(
      media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
      media::ChannelLayoutConfig::Mono(), kSampleRate, kBufferSize);
  EXPECT_TRUE(expected_params.Equals(track()->GetOutputFormat()));
  EXPECT_TRUE(expected_params.Equals(sink.params()));

  // Stop the track. Since this was the last track connected to the source, the
  // source should automatically stop. In addition, the sink should receive a
  // ReadyStateEnded notification.
  track()->Stop();
  EXPECT_TRUE(source()->was_started());
  EXPECT_TRUE(source()->was_stopped());
  EXPECT_TRUE(sink.was_ended());

  track()->RemoveSink(&sink);
}

// Tests that "ended" tracks can be connected after the source has stopped.
TEST_F(MediaStreamAudioTest, ConnectTrackAfterSourceStopped) {
  // Create the source, connect one track, and stop it. This should
  // automatically stop the source.
  ASSERT_TRUE(source());
  EXPECT_TRUE(source()->ConnectToInitializedTrack(audio_component_));
  track()->Stop();
  EXPECT_TRUE(source()->was_started());
  EXPECT_TRUE(source()->was_stopped());

  // Now, connect another track. ConnectToInitializedTrack() will return false.
  auto* another_component = MakeGarbageCollected<MediaStreamComponentImpl>(
      audio_source_->Id(), audio_source_,
      std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */));
  EXPECT_FALSE(source()->ConnectToInitializedTrack(another_component));
}

// Tests that a sink is immediately "ended" when connected to a stopped track.
TEST_F(MediaStreamAudioTest, AddSinkToStoppedTrack) {
  // Create a track and stop it. Then, when adding a sink, the sink should get
  // the ReadyStateEnded notification immediately.
  MediaStreamAudioTrack track(true);
  track.Stop();
  FakeMediaStreamAudioSink sink;
  EXPECT_FALSE(sink.was_ended());
  track.AddSink(&sink);
  EXPECT_TRUE(sink.was_ended());
  EXPECT_EQ(0, sink.num_on_data_calls());
  track.RemoveSink(&sink);
}

// Tests that audio format changes at the source propagate to the track and
// sink.
TEST_F(MediaStreamAudioTest, FormatChangesPropagate) {
  // Create a source, connect it to track, and connect the track to a
  // sink.
  ASSERT_TRUE(source());
  EXPECT_TRUE(source()->ConnectToInitializedTrack(audio_component_));
  ASSERT_TRUE(track());
  FakeMediaStreamAudioSink sink;
  ASSERT_TRUE(!sink.params().IsValid());
  track()->AddSink(&sink);

  // Wait until valid parameters are propagated to the sink, and then confirm
  // the parameters are correct at the track and the sink.
  while (!sink.params().IsValid())
    base::PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  const media::AudioParameters expected_params(
      media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
      media::ChannelLayoutConfig::Mono(), kSampleRate, kBufferSize);
  EXPECT_TRUE(expected_params.Equals(track()->GetOutputFormat()));
  EXPECT_TRUE(expected_params.Equals(sink.params()));

  // Now, trigger a format change by doubling the buffer size.
  source()->SetBufferSize(kBufferSize * 2);

  // Wait until the new buffer size propagates to the sink.
  while (sink.params().frames_per_buffer() == kBufferSize)
    base::PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  EXPECT_EQ(kBufferSize * 2, track()->GetOutputFormat().frames_per_buffer());
  EXPECT_EQ(kBufferSize * 2, sink.params().frames_per_buffer());

  track()->RemoveSink(&sink);
}

// Tests that tracks deliver audio when enabled and silent audio when
// disabled. Whenever a track is enabled or disabled, the sink's
// OnEnabledChanged() method should be called.
TEST_F(MediaStreamAudioTest, EnableAndDisableTracks) {
  // Create a source and connect it to track.
  ASSERT_TRUE(source());
  EXPECT_TRUE(source()->ConnectToInitializedTrack(audio_component_));
  ASSERT_TRUE(track());

  // Connect the track to a sink and expect the sink to be notified that the
  // track is enabled.
  FakeMediaStreamAudioSink sink;
  EXPECT_TRUE(sink.is_audio_silent());
  EXPECT_EQ(FakeMediaStreamAudioSink::kNoEnableNotification,
            sink.enable_state());
  track()->AddSink(&sink);
  EXPECT_EQ(FakeMediaStreamAudioSink::kWasEnabled, sink.enable_state());

  // Wait until non-silent audio reaches the sink.
  while (sink.is_audio_silent())
    base::PlatformThread::Sleep(TestTimeouts::tiny_timeout());

  // Now, disable the track and expect the sink to be notified.
  track()->SetEnabled(false);
  EXPECT_EQ(FakeMediaStreamAudioSink::kWasDisabled, sink.enable_state());

  // Wait until silent audio reaches the sink.
  while (!sink.is_audio_silent())
    base::PlatformThread::Sleep(TestTimeouts::tiny_timeout());

  // Create a second track and a second sink, but this time the track starts out
  // disabled. Expect the sink to be notified at the start that the track is
  // disabled.
  auto* another_component = MakeGarbageCollected<MediaStreamComponentImpl>(
      audio_source_->Id(), audio_source_,
      std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */));
  EXPECT_TRUE(source()->ConnectToInitializedTrack(another_component));
  MediaStreamAudioTrack::From(another_component)->SetEnabled(false);
  FakeMediaStreamAudioSink another_sink;
  MediaStreamAudioTrack::From(another_component)->AddSink(&another_sink);
  EXPECT_EQ(FakeMediaStreamAudioSink::kWasDisabled,
            another_sink.enable_state());

  // Wait until OnData() is called on the second sink. Expect the audio to be
  // silent.
  const int start_count = another_sink.num_on_data_calls();
  while (another_sink.num_on_data_calls() == start_count)
    base::PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  EXPECT_TRUE(another_sink.is_audio_silent());

  // Now, enable the second track and expect the second sink to be notified.
  MediaStreamAudioTrack::From(another_component)->SetEnabled(true);
  EXPECT_EQ(FakeMediaStreamAudioSink::kWasEnabled, another_sink.enable_state());

  // Wait until non-silent audio reaches the second sink.
  while (another_sink.is_audio_silent())
    base::PlatformThread::Sleep(TestTimeouts::tiny_timeout());

  // The first track and sink should not have been affected by changing the
  // enabled state of the second track and sink. They should still be disabled,
  // with silent audio being consumed at the sink.
  EXPECT_EQ(FakeMediaStreamAudioSink::kWasDisabled, sink.enable_state());
  EXPECT_TRUE(sink.is_audio_silent());

  MediaStreamAudioTrack::From(another_component)->RemoveSink(&another_sink);
  track()->RemoveSink(&sink);
}

TEST(MediaStreamAudioTestStandalone, GetAudioFrameStats) {
  MediaStreamAudioTrack track(true /* is_local_track */);
  MediaStreamAudioDeliverer<MediaStreamAudioTrack> deliverer;
  media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                media::ChannelLayoutConfig::Mono(), kSampleRate,
                                kBufferSize);
  std::unique_ptr<media::AudioBus> audio_bus = media::AudioBus::Create(params);

  deliverer.AddConsumer(&track);
  deliverer.OnSetFormat(params);

  {
    MediaStreamTrackPlatform::AudioFrameStats stats;
    track.TransferAudioFrameStatsTo(stats);
    EXPECT_EQ(stats.DeliveredFrames(), 0u);
    EXPECT_EQ(stats.DeliveredFramesDuration(), base::TimeDelta());
    EXPECT_EQ(stats.TotalFrames(), 0u);
    EXPECT_EQ(stats.TotalFramesDuration(), base::TimeDelta());
    EXPECT_EQ(stats.Latency(), base::TimeDelta());
    EXPECT_EQ(stats.AverageLatency(), base::TimeDelta());
    EXPECT_EQ(stats.MinimumLatency(), base::TimeDelta());
    EXPECT_EQ(stats.MaximumLatency(), base::TimeDelta());
  }

  // Deliver two callbacks with different latencies and glitch info.
  media::AudioGlitchInfo glitch_info_1 =
      media::AudioGlitchInfo{.duration = base::Milliseconds(3), .count = 1};
  base::TimeDelta latency_1 = base::Milliseconds(40);
  deliverer.OnData(*audio_bus, base::TimeTicks::Now() - latency_1,
                   glitch_info_1);

  media::AudioGlitchInfo glitch_info_2 =
      media::AudioGlitchInfo{.duration = base::Milliseconds(5), .count = 1};
  base::TimeDelta latency_2 = base::Milliseconds(60);
  deliverer.OnData(*audio_bus, base::TimeTicks::Now() - latency_2,
                   glitch_info_2);

  {
    MediaStreamTrackPlatform::AudioFrameStats stats;
    track.TransferAudioFrameStatsTo(stats);
    EXPECT_EQ(stats.DeliveredFrames(), static_cast<size_t>(kBufferSize * 2));
    EXPECT_EQ(stats.DeliveredFramesDuration(), params.GetBufferDuration() * 2);
    EXPECT_EQ(
        stats.TotalFrames() - stats.DeliveredFrames(),
        static_cast<size_t>(media::AudioTimestampHelper::TimeToFrames(
            glitch_info_1.duration + glitch_info_2.duration, kSampleRate)));
    EXPECT_EQ(stats.TotalFramesDuration() - stats.DeliveredFramesDuration(),
              glitch_info_1.duration + glitch_info_2.duration);
    // Due to time differences, the latencies might not be exactly what we
    // expect.
    const base::TimeDelta margin_of_error = base::Milliseconds(5);
    EXPECT_NEAR(stats.Latency().InMillisecondsF(), latency_2.InMillisecondsF(),
                margin_of_error.InMillisecondsF());
    EXPECT_NEAR(stats.AverageLatency().InMillisecondsF(),
                ((latency_1 + latency_2) / 2).InMillisecondsF(),
                margin_of_error.InMillisecondsF());
    EXPECT_NEAR(stats.MinimumLatency().InMillisecondsF(),
                latency_1.InMillisecondsF(), margin_of_error.InMillisecondsF());
    EXPECT_NEAR(stats.MaximumLatency().InMillisecondsF(),
                latency_2.InMillisecondsF(), margin_of_error.InMillisecondsF());
  }

  {
    // When we get the stats again, the interval latency stats should be reset
    // but the other stats should remain the same.
    MediaStreamTrackPlatform::AudioFrameStats stats;
    track.TransferAudioFrameStatsTo(stats);
    EXPECT_EQ(stats.DeliveredFrames(), static_cast<size_t>(kBufferSize * 2));
    EXPECT_EQ(stats.DeliveredFramesDuration(), params.GetBufferDuration() * 2);
    EXPECT_EQ(
        stats.TotalFrames() - stats.DeliveredFrames(),
        static_cast<size_t>(media::AudioTimestampHelper::TimeToFrames(
            glitch_info_1.duration + glitch_info_2.duration, kSampleRate)));
    EXPECT_EQ(stats.TotalFramesDuration() - stats.DeliveredFramesDuration(),
              glitch_info_1.duration + glitch_info_2.duration);
    // Due to time differences, the latencies might not be exactly what we
    // expect.
    const base::TimeDelta margin_of_error = base::Milliseconds(5);
    EXPECT_NEAR(stats.Latency().InMillisecondsF(), latency_2.InMillisecondsF(),
                margin_of_error.InMillisecondsF());
    EXPECT_EQ(stats.AverageLatency(), stats.Latency());
    EXPECT_EQ(stats.MinimumLatency(), stats.Latency());
    EXPECT_EQ(stats.MaximumLatency(), stats.Latency());
  }
}

}  // namespace blink
```