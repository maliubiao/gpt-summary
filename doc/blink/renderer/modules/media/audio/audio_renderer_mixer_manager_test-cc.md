Response:
My thinking process to analyze the provided C++ code and answer the prompt went something like this:

1. **Understand the Goal:** The request is to analyze a C++ test file (`audio_renderer_mixer_manager_test.cc`) for the Chromium Blink engine. The goal is to understand its functionality, its relation to web technologies (JavaScript, HTML, CSS), provide examples of logic, potential errors, debugging hints, and finally summarize its function in this part 1 of the analysis.

2. **Initial Code Scan (Keywords and Structure):** I quickly scanned the code, looking for recognizable C++ patterns, class names, and keywords related to audio and testing. I noticed:
    * `#include` directives indicating dependencies on other Chromium/Blink components and standard C++ libraries.
    * Class `AudioRendererMixerManagerTest` inheriting from `testing::Test`, clearly indicating a unit test file.
    * Member variables like `manager_` of type `AudioRendererMixerManager`, which seems to be the main class being tested.
    * Methods like `GetMixer`, `ReturnMixer`, `CreateInputHelper`, which suggest the core functionalities being tested.
    * Use of `scoped_refptr` for memory management.
    * Use of `testing::gmock` for mocking dependencies.
    * Constants related to sample rates, buffer sizes, and device IDs.

3. **Identify the Core Functionality:** Based on the class name and the methods, I deduced that `AudioRendererMixerManager` is responsible for managing `AudioRendererMixer` instances. The "mixer" likely handles the mixing of audio streams. The test file aims to verify the correct behavior of this manager.

4. **Analyze Key Test Methods:** I looked at individual test methods (those starting with `TEST_F`). Each test method focuses on a specific aspect of the `AudioRendererMixerManager`'s functionality. For instance:
    * `GetSink`: Tests how the manager retrieves audio sinks.
    * `GetReturnMixer`: Tests getting and returning mixers, including reuse.
    * `ReturnMixerWithError`: Tests how errors affect mixer reuse.
    * `MixerReuse`: Tests deduplication of mixers based on parameters.
    * `CreateInput`: Tests creating mixer inputs and their interaction with the manager.
    * `MixerDevices`: Tests creating distinct mixers for different audio devices.
    * `LatencyMixing`, `EffectsMixing`: Tests how latency and audio effects influence mixer creation and reuse.
    * `MixerParamsLatencyPlayback`: Tests the correct configuration of mixer output parameters based on latency.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  This is where the connection to the browser's rendering engine comes in. Audio playback in a web browser is triggered by HTML `<audio>` or `<video>` elements, or through Web Audio API calls in JavaScript. The `AudioRendererMixerManager` is a backend component that *implements* the audio rendering logic for these web features.

    * **HTML:** When an `<audio>` tag starts playing, the browser needs to set up an audio pipeline. The `AudioRendererMixerManager` is involved in creating and managing the mixer that processes the audio data.
    * **JavaScript (Web Audio API):** The Web Audio API provides fine-grained control over audio processing. When a JavaScript application uses the API to create audio nodes and connect them, the `AudioRendererMixerManager` ensures that the audio streams from these nodes are correctly mixed and sent to the audio output device.
    * **CSS:** CSS doesn't directly control audio rendering logic. However, CSS can indirectly influence audio playback by controlling the visibility or playback state of HTML media elements.

6. **Consider Logic and Examples:** I picked a few test cases and thought about the underlying logic:
    * **Mixer Reuse:** The manager should reuse existing mixers if the audio parameters and device are the same. This optimizes resource usage.
    * **Error Handling:** If a mixer encounters an error, it shouldn't be reused, and the manager should create a new one.
    * **Latency and Effects:** Different latency requirements (e.g., for real-time communication) or audio effects require different mixer configurations.

7. **Identify Potential Errors and Debugging:** I considered common mistakes developers might make when working with audio in a browser:
    * Incorrect audio parameters.
    * Problems with device selection.
    * Issues with audio focus management (though not directly tested here).

    For debugging, I noted that the test file itself provides good clues:  look at the assertions (`EXPECT_EQ`, `ASSERT_TRUE`, `EXPECT_NE`) and the setup of the mock objects to understand the expected behavior.

8. **Summarize Functionality for Part 1:** I focused on the high-level purpose of the file and the `AudioRendererMixerManager` class based on the analysis of the test cases.

9. **Iterative Refinement:** Throughout the process, I went back and forth between reading the code, understanding the concepts, and formulating the answers. I ensured that my explanations were consistent with the code and addressed all aspects of the prompt. For example, I initially might have focused too much on the technical details of the C++ code, but then I made sure to explicitly connect it back to the web technologies.
好的，让我们来详细分析一下 `audio_renderer_mixer_manager_test.cc` 这个文件的功能。

**文件功能归纳:**

`audio_renderer_mixer_manager_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件。它的主要目的是 **测试 `AudioRendererMixerManager` 类的功能是否正确**。  `AudioRendererMixerManager` 负责管理音频渲染器中的混音器 (`AudioRendererMixer`) 的创建、复用和销毁。

**具体功能拆解:**

这个测试文件通过创建各种场景和调用 `AudioRendererMixerManager` 的方法，来验证其行为是否符合预期。以下是它测试的一些关键方面：

1. **混音器的创建和获取 (`GetMixer`)：**
   - 测试在给定不同的音频参数（例如采样率、声道布局）、音频延迟类型 (`AudioLatency::Type`) 和设备 ID 的情况下，`AudioRendererMixerManager` 是否能正确创建或返回合适的 `AudioRendererMixer` 实例。
   - 验证对于相同的参数，是否会复用已存在的混音器，以提高性能。
   - 测试在请求不存在的音频设备时，是否能正确处理并返回错误状态。

2. **混音器的返回 (`ReturnMixer`)：**
   - 测试当不再需要混音器时，`AudioRendererMixerManager` 是否能正确地管理混音器的生命周期，可能包括将其放回复用池或销毁。
   - 特别测试了在混音器发生错误 (`OnRenderError`) 时，`ReturnMixer` 的行为，确保错误的混音器不会被再次复用。

3. **混音器的复用策略：**
   - 测试 `AudioRendererMixerManager` 如何根据音频参数的差异来决定是否复用混音器。例如，采样率或缓冲区大小的不同可能不会导致创建新的混音器，但声道布局的不同则会。
   - 测试对于默认音频设备的不同表示（例如空字符串 "" 和 "default"）是否能正确复用混音器。

4. **混音器输入 (`AudioRendererMixerInput`) 的创建 (`CreateInput`)：**
   - 测试 `AudioRendererMixerManager` 能否为不同的渲染帧 (`RenderFrame`) 创建独立的混音器输入。即使音频参数相同，来自不同渲染帧的音频流也应该被独立处理。
   - 测试混音器输入如何与 `AudioRendererMixerManager` 交互，以获取和返回混音器。
   - 验证使用 `session_id` (在某些情况下) 是否能正确选择音频设备。 （注意：代码中有一个被禁用的测试 `DISABLED_CreateInputWithSessionId`，可能反映了对该功能的某些限制或待解决的问题）。

5. **音频延迟 (`AudioLatency`) 的影响：**
   - 测试 `AudioRendererMixerManager` 是否能根据不同的音频延迟类型（例如 `kPlayback`, `kRtc`, `kInteractive`）创建不同的混音器。不同的延迟类型可能对应不同的混音策略和缓冲区大小。

6. **音频效果 (`effects`) 的影响：**
   - 测试 `AudioRendererMixerManager` 是否能根据音频参数中设置的不同效果 (`effects`) 创建不同的混音器。

7. **混音器参数的调整：**
   - 测试对于不同延迟类型的音频流，混音器的输出缓冲区大小是否能根据硬件设备的特性和延迟需求进行合理的调整。例如，对于 `kPlayback` 延迟，通常会使用更大的缓冲区以提高稳定性。
   - 特别测试了当硬件设备的缓冲区大小超过 20 毫秒时，混音器参数的调整策略。
   - 测试了当输出设备是虚拟的 (`AUDIO_FAKE`) 时，混音器参数的调整策略。

**与 Javascript, HTML, CSS 的关系：**

这个 C++ 文件位于 Blink 引擎的底层音频处理模块，它直接服务于 Web 平台上音频的播放需求。它与 Javascript, HTML, CSS 的关系如下：

* **HTML:** 当 HTML 中包含 `<audio>` 或 `<video>` 标签，并开始播放音频时，Blink 引擎会创建相应的音频渲染管道。`AudioRendererMixerManager` 负责管理这个管道中的混音器，将来自不同来源的音频流混合在一起，最终输出到用户的音频设备。
* **Javascript (Web Audio API):** Web Audio API 允许 Javascript 代码对音频进行复杂的处理和合成。当 Javascript 代码使用 Web Audio API 创建音频节点（例如 `OscillatorNode`, `AudioBufferSourceNode`）并连接到输出目标 (`AudioDestinationNode`) 时，Blink 引擎内部会使用 `AudioRendererMixerManager` 来管理混音器，将这些 Javascript 生成的音频流与来自 HTML 媒体元素的音频流进行混合。
* **CSS:** CSS 主要负责页面的样式和布局，它本身不直接参与音频处理逻辑。但是，CSS 可以通过控制 HTML 元素的显示或隐藏，间接地影响音频的播放。例如，隐藏一个 `<audio>` 元素可能会导致其音频流停止播放，从而影响 `AudioRendererMixerManager` 的行为。

**举例说明：**

假设一个网页包含一个 `<audio>` 元素和一个使用 Web Audio API 创建的振荡器。

1. **HTML (`<audio>` 元素):**  当用户点击播放按钮时，浏览器会解码音频文件，并将解码后的音频数据传递给音频渲染管道。`AudioRendererMixerManager` 会根据 `<audio>` 元素的音频参数（例如采样率、声道数）和输出设备，获取或创建一个合适的 `AudioRendererMixer`。

2. **Javascript (Web Audio API 振荡器):**  Javascript 代码创建了一个 `OscillatorNode` 并连接到 `AudioContext` 的 `destination` 属性。Blink 引擎会为这个振荡器创建一个对应的音频源，并将其输出流也交给 `AudioRendererMixerManager` 管理的混音器。

3. **`AudioRendererMixerManager` 的工作:**  `AudioRendererMixerManager` 负责确保来自 `<audio>` 元素的音频流和来自 Javascript 振荡器的音频流被正确地混合在一起。它会根据两个音频源的参数和目标输出设备的特性，选择或创建一个合适的 `AudioRendererMixer` 实例。如果两个音频源的参数兼容，并且目标设备相同，`AudioRendererMixerManager` 可能会复用同一个混音器。

**逻辑推理和假设输入输出：**

**假设输入：**

*  调用 `GetMixer`，传入以下参数：
    * `source_frame_token`:  表示音频来源的渲染帧的标识符。
    * `main_frame_token`:  表示主渲染帧的标识符。
    * `params`:  `media::AudioParameters` 对象，包含采样率 48000，声道布局 `CHANNEL_LAYOUT_STEREO`。
    * `latency`: `AudioLatency::Type::kPlayback`。
    * `device_info`:  表示默认音频输出设备的 `media::AudioOutputDeviceInfo`。
    * `sink`:  一个指向默认音频输出设备的 `media::AudioRendererSink` 的智能指针。

**预期输出：**

*  `GetMixer` 返回一个指向 `AudioRendererMixer` 实例的指针。如果之前已经为相同的参数创建过混音器，则返回相同的实例（复用）。否则，创建一个新的 `AudioRendererMixer` 实例。

**假设输入：**

*  连续两次调用 `GetMixer`，第一次使用 `AudioLatency::Type::kPlayback`，第二次使用 `AudioLatency::Type::kRtc`，其他参数相同。

**预期输出：**

*  两次调用 `GetMixer` 会返回两个不同的 `AudioRendererMixer` 实例，因为音频延迟类型不同，需要不同的混音策略。

**用户或编程常见的使用错误：**

1. **不匹配的音频参数：**  Javascript 代码尝试播放一个采样率为 44100 的音频流，但浏览器的音频输出设备只支持 48000 的采样率。这可能导致浏览器内部进行重采样，如果处理不当，可能会引入音频质量问题或性能开销。`AudioRendererMixerManager` 的测试会验证它在这种情况下能否正确处理或创建合适的混音器。

2. **请求不存在的音频设备：**  Javascript 代码使用 `navigator.mediaDevices.getUserMedia` 获取音频流时，可能会指定一个不存在的音频设备 ID。`AudioRendererMixerManager` 的测试会验证在这种情况下，它是否能正确处理并返回错误，避免程序崩溃。

3. **在不恰当的时间释放混音器相关的资源：**  如果开发者在音频播放过程中过早地释放了与混音器相关的资源（例如 `AudioContext`），可能会导致音频播放中断或崩溃。虽然 `AudioRendererMixerManagerTest` 主要测试 `AudioRendererMixerManager` 自身的逻辑，但理解其生命周期管理对于避免这类错误至关重要。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户打开一个网页，该网页包含音频播放功能。** 这可能是通过 `<audio>` 或 `<video>` 标签，或者通过 Javascript 使用 Web Audio API 实现的。

2. **用户触发音频播放。** 例如，点击 `<audio>` 标签的播放按钮，或者 Javascript 代码调用 `audioNode.start()`。

3. **Blink 引擎开始处理音频播放请求。** 这涉及到解码音频数据（如果需要）、创建音频处理节点、并将音频数据传递到渲染管道。

4. **`AudioRendererMixerManager` 被调用以获取或创建混音器。**  引擎会根据当前音频流的参数（采样率、声道布局等）和目标输出设备的信息，调用 `AudioRendererMixerManager::GetMixer`。

5. **如果音频播放出现问题（例如，没有声音，声音失真，播放卡顿），开发者可能会开始调试。**  调试的线索可能包括：
   - **浏览器的开发者工具控制台输出错误信息。**  例如，关于音频设备初始化失败或混音器创建失败的错误。
   - **使用 Chrome 的 `chrome://media-internals/` 页面查看音频渲染管道的状态。**  这个页面会显示音频流的参数、使用的音频设备以及混音器的信息。
   - **如果怀疑是混音器的问题，开发者可能会查看 Blink 引擎的源代码，并最终定位到 `AudioRendererMixerManager` 相关的代码。**  `audio_renderer_mixer_manager_test.cc` 文件中的测试用例可以帮助开发者理解 `AudioRendererMixerManager` 的预期行为，从而更好地定位问题。

**总结（第 1 部分功能归纳）：**

总而言之，`blink/renderer/modules/media/audio/audio_renderer_mixer_manager_test.cc` 这个 C++ 测试文件的主要功能是 **验证 `AudioRendererMixerManager` 类的核心功能，包括混音器的创建、复用、返回，以及它如何根据音频参数、延迟类型和设备信息来管理混音器实例。**  这个测试确保了 Blink 引擎在处理网页音频播放时，能够正确地创建和管理混音器，从而保证音频播放的稳定性和质量。它与 Web 平台的音频功能紧密相关，是确保浏览器音频能力正常运行的关键组成部分。

### 提示词
```
这是目录为blink/renderer/modules/media/audio/audio_renderer_mixer_manager_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media/audio/audio_renderer_mixer_manager.h"

#include <memory>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/run_loop.h"
#include "build/build_config.h"
#include "media/audio/audio_device_description.h"
#include "media/base/audio_parameters.h"
#include "media/base/fake_audio_render_callback.h"
#include "media/base/mock_audio_renderer_sink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/modules/media/audio/audio_renderer_mixer.h"
#include "third_party/blink/renderer/modules/media/audio/audio_renderer_mixer_input.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

using testing::_;
using testing::Return;

namespace blink {

namespace {
constexpr int kSampleRate = 48000;
constexpr int kBufferSize = 8192;
constexpr int kHardwareSampleRate = 44100;
constexpr int kHardwareBufferSize = 128;
constexpr media::ChannelLayout kChannelLayout = media::CHANNEL_LAYOUT_STEREO;
constexpr media::ChannelLayout kAnotherChannelLayout =
    media::CHANNEL_LAYOUT_2_1;
const char* const kDefaultDeviceId =
    media::AudioDeviceDescription::kDefaultDeviceId;
constexpr char kAnotherDeviceId[] = "another-device-id";
constexpr char kMatchedDeviceId[] = "matched-device-id";
constexpr char kNonexistentDeviceId[] = "nonexistent-device-id";

const LocalFrameToken kLocalFrameToken;
const FrameToken kFrameToken;
const FrameToken kAnotherFrameToken;
}  // namespace

using media::AudioLatency;
using media::AudioParameters;

class AudioRendererMixerManagerTest : public testing::Test {
 public:
  AudioRendererMixerManagerTest()
      : manager_(std::make_unique<AudioRendererMixerManager>(
            base::BindRepeating(&AudioRendererMixerManagerTest::GetPlainSink,
                                base::Unretained(this)))) {}

  AudioRendererMixerManagerTest(const AudioRendererMixerManagerTest&) = delete;
  AudioRendererMixerManagerTest& operator=(
      const AudioRendererMixerManagerTest&) = delete;

  scoped_refptr<media::MockAudioRendererSink> CreateNormalSink(
      const std::string& device_id = std::string(kDefaultDeviceId)) {
    auto sink = base::MakeRefCounted<media::MockAudioRendererSink>(
        device_id, media::OUTPUT_DEVICE_STATUS_OK,
        AudioParameters(
            AudioParameters::AUDIO_PCM_LINEAR,
            media::ChannelLayoutConfig::FromLayout<kChannelLayout>(),
            kHardwareSampleRate, kHardwareBufferSize));
    EXPECT_CALL(*sink, Stop()).Times(1);
    return sink;
  }

  scoped_refptr<media::MockAudioRendererSink> CreateNoDeviceSink() {
    return base::MakeRefCounted<media::MockAudioRendererSink>(
        kNonexistentDeviceId, media::OUTPUT_DEVICE_STATUS_ERROR_NOT_FOUND);
  }

  scoped_refptr<media::MockAudioRendererSink> CreateMatchedDeviceSink() {
    auto sink = base::MakeRefCounted<media::MockAudioRendererSink>(
        kMatchedDeviceId, media::OUTPUT_DEVICE_STATUS_OK);
    EXPECT_CALL(*sink, Stop()).Times(1);
    return sink;
  }

  enum class SinkUseState { kExistingSink, kNewSink };
  AudioRendererMixer* GetMixer(const LocalFrameToken& source_frame_token,
                               const FrameToken& main_frame_token,
                               const media::AudioParameters& params,
                               AudioLatency::Type latency,
                               const std::string& device_id,
                               SinkUseState sink_state) {
    auto sink = GetSink(
        source_frame_token, main_frame_token,
        media::AudioSinkParameters(base::UnguessableToken(), device_id));
    auto device_info = sink->GetOutputDeviceInfo();
    if (sink_state == SinkUseState::kNewSink) {
      EXPECT_CALL(*sink, Start()).Times(1);
    }
    return manager_->GetMixer(source_frame_token, main_frame_token, params,
                              latency, device_info, std::move(sink));
  }

  void ReturnMixer(AudioRendererMixer* mixer) {
    return manager_->ReturnMixer(mixer);
  }

  scoped_refptr<AudioRendererMixerInput> CreateInputHelper(
      const LocalFrameToken& source_frame_token,
      const FrameToken& main_frame_token,
      const base::UnguessableToken& session_id,
      const std::string& device_id,
      media::AudioLatency::Type latency,
      const media::AudioParameters params,
      media::AudioRendererSink::RenderCallback* callback) {
    auto input = manager_->CreateInput(source_frame_token, main_frame_token,
                                       session_id, device_id, latency);
    input->GetOutputDeviceInfoAsync(
        base::DoNothing());  // Primes input, needed for tests.
    base::RunLoop().RunUntilIdle();
    input->Initialize(params, callback);
    return input;
  }

  // Number of instantiated mixers.
  size_t mixer_count() { return manager_->mixers_.size(); }
  size_t dead_mixer_count() { return manager_->dead_mixers_.size(); }

  void InitializeManagerWithMockSink() {
    manager_ = std::make_unique<AudioRendererMixerManager>(base::BindRepeating(
        &AudioRendererMixerManagerTest::GetMockSink, base::Unretained(this)));
  }

  MOCK_METHOD2(GetMockSink,
               scoped_refptr<media::AudioRendererSink>(
                   const LocalFrameToken& source_frame_token,
                   const media::AudioSinkParameters& params));

 protected:
  scoped_refptr<media::MockAudioRendererSink> GetSink(
      const LocalFrameToken& source_frame_token,
      const FrameToken& main_frame_token,
      const media::AudioSinkParameters& params) {
    if ((params.device_id == kDefaultDeviceId) ||
        (params.device_id == kAnotherDeviceId)) {
      return mock_sink_ ? std::move(mock_sink_)
                        : CreateNormalSink(params.device_id);
    }
    if (params.device_id == kNonexistentDeviceId) {
      return CreateNoDeviceSink();
    }
    if (params.device_id.empty()) {
      // The sink used to get device ID from session ID if it's not empty
      return params.session_id
                 ? CreateMatchedDeviceSink()
                 : (mock_sink_ ? std::move(mock_sink_)
                               : CreateNormalSink(params.device_id));
    }
    if (params.device_id == kMatchedDeviceId) {
      return CreateMatchedDeviceSink();
    }

    NOTREACHED();
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<AudioRendererMixerManager> manager_;
  scoped_refptr<media::MockAudioRendererSink> mock_sink_;

 private:
  scoped_refptr<media::AudioRendererSink> GetPlainSink(
      const LocalFrameToken& source_frame_token,
      const media::AudioSinkParameters& params) {
    return GetSink(source_frame_token, kFrameToken, params);
  }
};

TEST_F(AudioRendererMixerManagerTest, GetSink) {
  InitializeManagerWithMockSink();

  // Sinks created for the default device id should use the main frame token if
  // possible. Below we check that the expected local frame token is passed in.
  testing::InSequence in_sequence;
  EXPECT_CALL(*this, GetMockSink(kFrameToken.GetAs<LocalFrameToken>(), _))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(*this, GetMockSink(kLocalFrameToken, _))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(*this, GetMockSink(kLocalFrameToken, _))
      .WillOnce(Return(nullptr));

  manager_->GetSink(kLocalFrameToken, kFrameToken, kDefaultDeviceId);
  manager_->GetSink(kLocalFrameToken, RemoteFrameToken(), kDefaultDeviceId);
  manager_->GetSink(kLocalFrameToken, kFrameToken, kAnotherDeviceId);
}

// Verify GetMixer() and ReturnMixer() both work as expected; particularly with
// respect to the explicit ref counting done.
TEST_F(AudioRendererMixerManagerTest, GetReturnMixer) {
  // There should be no mixers outstanding to start with.
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params1(
      media::AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);

  AudioRendererMixer* mixer1 = GetMixer(
      kLocalFrameToken, kFrameToken, params1, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer1);
  EXPECT_EQ(1u, mixer_count());

  // The same parameters should return the same mixer1.
  EXPECT_EQ(mixer1, GetMixer(kLocalFrameToken, kFrameToken, params1,
                             AudioLatency::Type::kPlayback, kDefaultDeviceId,
                             SinkUseState::kExistingSink));
  EXPECT_EQ(1u, mixer_count());

  // Return the extra mixer we just acquired.
  ReturnMixer(mixer1);
  EXPECT_EQ(1u, mixer_count());

  media::AudioParameters params2(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kAnotherChannelLayout>(),
      kSampleRate * 2, kBufferSize * 2);
  AudioRendererMixer* mixer2 = GetMixer(
      kLocalFrameToken, kFrameToken, params2, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer2);
  EXPECT_EQ(2u, mixer_count());

  // Different parameters should result in a different mixer1.
  EXPECT_NE(mixer1, mixer2);

  // Return both outstanding mixers.
  ReturnMixer(mixer1);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer2);
  EXPECT_EQ(0u, mixer_count());
}

TEST_F(AudioRendererMixerManagerTest, ReturnMixerWithError) {
  mock_sink_ = CreateNormalSink();
  auto* local_sink = mock_sink_.get();

  // There should be no mixers outstanding to start with.
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params1(
      media::AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);

  AudioRendererMixer* mixer1 = GetMixer(
      kLocalFrameToken, kFrameToken, params1, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer1);
  EXPECT_EQ(1u, mixer_count());

  // The same parameters should return the same mixer1.
  EXPECT_EQ(mixer1, GetMixer(kLocalFrameToken, kFrameToken, params1,
                             AudioLatency::Type::kPlayback, kDefaultDeviceId,
                             SinkUseState::kExistingSink));
  EXPECT_EQ(1u, mixer_count());

  // Trigger an error in mixer1.
  local_sink->callback()->OnRenderError();

  // Return the extra mixer we just acquired, it should not be deleted, but put
  // into the dead mixer map.
  ReturnMixer(mixer1);
  EXPECT_EQ(0u, mixer_count());
  EXPECT_EQ(1u, dead_mixer_count());

  // Using the same params should create a new mixer due to the error.
  mock_sink_ = CreateNormalSink();
  local_sink = mock_sink_.get();
  AudioRendererMixer* mixer2 = GetMixer(
      kLocalFrameToken, kFrameToken, params1, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer2);
  EXPECT_EQ(1u, mixer_count());
  EXPECT_EQ(1u, dead_mixer_count());
  EXPECT_NE(mixer1, mixer2);

  // Trigger an error in mixer2 now.
  local_sink->callback()->OnRenderError();

  // Ensure we end up with two dead mixers and not just one in this case.
  AudioRendererMixer* mixer3 = GetMixer(
      kLocalFrameToken, kFrameToken, params1, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer3);
  EXPECT_EQ(1u, mixer_count());
  EXPECT_EQ(2u, dead_mixer_count());
  EXPECT_NE(mixer1, mixer2);

  // Return all outstanding mixers.
  ReturnMixer(mixer1);
  EXPECT_EQ(1u, dead_mixer_count());
  ReturnMixer(mixer2);
  EXPECT_EQ(0u, dead_mixer_count());
  ReturnMixer(mixer3);
  EXPECT_EQ(0u, mixer_count());
}

// Verify GetMixer() correctly deduplicates mixer with irrelevant AudioParameter
// differences.
TEST_F(AudioRendererMixerManagerTest, MixerReuse) {
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params1(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);
  AudioRendererMixer* mixer1 = GetMixer(
      kLocalFrameToken, kFrameToken, params1, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer1);
  EXPECT_EQ(1u, mixer_count());

  // Different sample rates, formats, bit depths, and buffer sizes should not
  // result in a different mixer.
  media::AudioParameters params2(
      AudioParameters::AUDIO_PCM_LOW_LATENCY,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate * 2,
      kBufferSize * 2);
  AudioRendererMixer* mixer2 = GetMixer(
      kLocalFrameToken, kFrameToken, params2, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kExistingSink);
  EXPECT_EQ(mixer1, mixer2);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer2);
  EXPECT_EQ(1u, mixer_count());

  // Modify some parameters that do matter: channel layout
  media::AudioParameters params3(
      AudioParameters::AUDIO_PCM_LOW_LATENCY,
      media::ChannelLayoutConfig::FromLayout<kAnotherChannelLayout>(),
      kSampleRate, kBufferSize);
  ASSERT_NE(params3.channel_layout(), params1.channel_layout());
  AudioRendererMixer* mixer3 = GetMixer(
      kLocalFrameToken, kFrameToken, params3, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  EXPECT_NE(mixer1, mixer3);
  EXPECT_EQ(2u, mixer_count());
  ReturnMixer(mixer3);
  EXPECT_EQ(1u, mixer_count());

  // Return final mixer.
  ReturnMixer(mixer1);
  EXPECT_EQ(0u, mixer_count());
}

// Verify CreateInput() provides AudioRendererMixerInput with the appropriate
// callbacks and they are working as expected.  Also, verify that separate
// mixers are created for separate RenderFrames, even though the
// AudioParameters are the same.
TEST_F(AudioRendererMixerManagerTest, CreateInput) {
  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);

  // Create two mixer inputs and ensure this doesn't instantiate any mixers yet.
  EXPECT_EQ(0u, mixer_count());
  media::FakeAudioRenderCallback callback(0, kSampleRate);
  mock_sink_ = CreateNormalSink();
  EXPECT_CALL(*mock_sink_, Start()).Times(1);
  auto input = CreateInputHelper(
      kLocalFrameToken, kFrameToken, base::UnguessableToken(), kDefaultDeviceId,
      AudioLatency::Type::kPlayback, params, &callback);
  EXPECT_EQ(0u, mixer_count());
  ASSERT_EQ(mock_sink_, nullptr);  // Sink is consumed by CreateInputHelper.

  // Despite being from another local frame, this input has the same main frame
  // so should share the previously created mixer.
  media::FakeAudioRenderCallback another_callback(1, kSampleRate);
  auto another_input = CreateInputHelper(
      LocalFrameToken(), kFrameToken, base::UnguessableToken(),
      kDefaultDeviceId, AudioLatency::Type::kPlayback, params,
      &another_callback);
  EXPECT_EQ(0u, mixer_count());

  // Since this input uses a another main frame token, it should not be shared.
  media::FakeAudioRenderCallback another_callback2(1, kSampleRate);
  mock_sink_ = CreateNormalSink(kDefaultDeviceId);
  EXPECT_CALL(*mock_sink_, Start()).Times(1);
  auto another_input2 = CreateInputHelper(
      kLocalFrameToken, kAnotherFrameToken, base::UnguessableToken(),
      kDefaultDeviceId, AudioLatency::Type::kPlayback, params,
      &another_callback2);
  EXPECT_EQ(0u, mixer_count());
  ASSERT_EQ(mock_sink_, nullptr);  // Sink is consumed by CreateInputHelper.

  // Create another sink but for a non-default device, it should not be shared.
  media::FakeAudioRenderCallback another_callback3(1, kSampleRate);
  mock_sink_ = CreateNormalSink(kAnotherDeviceId);
  EXPECT_CALL(*mock_sink_, Start()).Times(1);
  auto another_input3 = CreateInputHelper(
      kLocalFrameToken, kFrameToken, base::UnguessableToken(), kAnotherDeviceId,
      AudioLatency::Type::kPlayback, params, &another_callback2);
  EXPECT_EQ(0u, mixer_count());
  ASSERT_EQ(mock_sink_, nullptr);  // Sink is consumed by CreateInputHelper.

  // Create another sink for a non-default device, but in a different frame.
  media::FakeAudioRenderCallback another_callback4(1, kSampleRate);
  mock_sink_ = CreateNormalSink(kAnotherDeviceId);
  EXPECT_CALL(*mock_sink_, Start()).Times(1);
  auto another_input4 = CreateInputHelper(
      LocalFrameToken(), kFrameToken, base::UnguessableToken(),
      kAnotherDeviceId, AudioLatency::Type::kPlayback, params,
      &another_callback2);
  EXPECT_EQ(0u, mixer_count());
  ASSERT_EQ(mock_sink_, nullptr);  // Sink is consumed by CreateInputHelper.

  // Implicitly test that AudioRendererMixerInput was provided with the expected
  // callbacks needed to acquire an AudioRendererMixer and return it.
  input->Start();
  EXPECT_EQ(1u, mixer_count());
  another_input->Start();
  EXPECT_EQ(1u, mixer_count());
  another_input2->Start();
  EXPECT_EQ(2u, mixer_count());
  another_input3->Start();
  EXPECT_EQ(3u, mixer_count());
  another_input4->Start();
  EXPECT_EQ(4u, mixer_count());

  // Destroying the inputs should destroy the mixers.
  input->Stop();
  input = nullptr;
  EXPECT_EQ(4u, mixer_count());
  another_input->Stop();
  another_input = nullptr;
  EXPECT_EQ(3u, mixer_count());
  another_input2->Stop();
  another_input2 = nullptr;
  EXPECT_EQ(2u, mixer_count());
  another_input3->Stop();
  EXPECT_EQ(1u, mixer_count());
  another_input4->Stop();
  EXPECT_EQ(0u, mixer_count());
}

// Verify CreateInput() provided with session id creates AudioRendererMixerInput
// with the appropriate callbacks and they are working as expected.
//
// TODO(grunell): |session_id| support currently requires calling the
// synchronous GetOutputDeviceInfo call, this is not allowed. So this test is
// disabled. This should be deleted in the future, https://crbug.com/870836.
TEST_F(AudioRendererMixerManagerTest, DISABLED_CreateInputWithSessionId) {
  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);
  media::FakeAudioRenderCallback callback(0, kSampleRate);
  EXPECT_EQ(0u, mixer_count());

  // Empty device id, zero session id;
  auto input_to_default_device = CreateInputHelper(
      kLocalFrameToken, kFrameToken, base::UnguessableToken(),  // session_id
      std::string(), AudioLatency::Type::kPlayback, params, &callback);
  EXPECT_EQ(0u, mixer_count());

  // Specific device id, zero session id;
  auto input_to_another_device = CreateInputHelper(
      kLocalFrameToken, kFrameToken, base::UnguessableToken(),  // session_id
      kMatchedDeviceId, AudioLatency::Type::kPlayback, params, &callback);
  EXPECT_EQ(0u, mixer_count());

  // Specific device id, non-zero session id (to be ignored);
  auto input_to_matched_device = CreateInputHelper(
      kLocalFrameToken, kFrameToken,
      base::UnguessableToken::Create(),  // session id
      kAnotherDeviceId, AudioLatency::Type::kPlayback, params, &callback);
  EXPECT_EQ(0u, mixer_count());

  // Empty device id, non-zero session id;
  auto input_to_matched_device_with_session_id = CreateInputHelper(
      kLocalFrameToken, kFrameToken,
      base::UnguessableToken::Create(),  // session id
      std::string(), AudioLatency::Type::kPlayback, params, &callback);
  EXPECT_EQ(0u, mixer_count());

  // Implicitly test that AudioRendererMixerInput was provided with the expected
  // callbacks needed to acquire an AudioRendererMixer and return it.
  input_to_default_device->Start();
  EXPECT_EQ(1u, mixer_count());

  input_to_another_device->Start();
  EXPECT_EQ(2u, mixer_count());

  input_to_matched_device->Start();
  EXPECT_EQ(3u, mixer_count());

  // Should go to the same device as the input above.
  input_to_matched_device_with_session_id->Start();
  EXPECT_EQ(3u, mixer_count());

  // Destroying the inputs should destroy the mixers.
  input_to_default_device->Stop();
  input_to_default_device = nullptr;
  EXPECT_EQ(2u, mixer_count());
  input_to_another_device->Stop();
  input_to_another_device = nullptr;
  EXPECT_EQ(1u, mixer_count());
  input_to_matched_device->Stop();
  input_to_matched_device = nullptr;
  EXPECT_EQ(1u, mixer_count());
  input_to_matched_device_with_session_id->Stop();
  input_to_matched_device_with_session_id = nullptr;
  EXPECT_EQ(0u, mixer_count());
}

// Verify GetMixer() correctly creates different mixers with the same
// parameters, but different device ID.
TEST_F(AudioRendererMixerManagerTest, MixerDevices) {
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);
  AudioRendererMixer* mixer1 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer1);
  EXPECT_EQ(1u, mixer_count());

  AudioRendererMixer* mixer2 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kAnotherDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer2);
  EXPECT_EQ(2u, mixer_count());
  EXPECT_NE(mixer1, mixer2);

  ReturnMixer(mixer1);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer2);
  EXPECT_EQ(0u, mixer_count());
}

// Verify GetMixer() correctly deduplicate mixers with the same
// parameters and default device ID, even if one is "" and one is "default".
TEST_F(AudioRendererMixerManagerTest, OneMixerDifferentDefaultDeviceIDs) {
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);
  AudioRendererMixer* mixer1 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer1);
  EXPECT_EQ(1u, mixer_count());

  AudioRendererMixer* mixer2 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      std::string(), SinkUseState::kExistingSink);
  ASSERT_TRUE(mixer2);
  EXPECT_EQ(1u, mixer_count());
  EXPECT_EQ(mixer1, mixer2);

  ReturnMixer(mixer1);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer2);
  EXPECT_EQ(0u, mixer_count());
}

// Verify that GetMixer() correctly returns a null mixer and an appropriate
// status code when a nonexistent device is requested.
TEST_F(AudioRendererMixerManagerTest, NonexistentDevice) {
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);

  auto sink = GetSink(kLocalFrameToken, kFrameToken,
                      media::AudioSinkParameters(base::UnguessableToken(),
                                                 kNonexistentDeviceId));
  auto device_info = sink->GetOutputDeviceInfo();

  EXPECT_EQ(media::OUTPUT_DEVICE_STATUS_ERROR_NOT_FOUND,
            device_info.device_status());
  EXPECT_EQ(0u, mixer_count());
}

// Verify GetMixer() correctly deduplicate mixers basing on latency
// requirements.
TEST_F(AudioRendererMixerManagerTest, LatencyMixing) {
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);
  AudioRendererMixer* mixer1 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer1);
  EXPECT_EQ(1u, mixer_count());

  AudioRendererMixer* mixer2 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kExistingSink);
  ASSERT_TRUE(mixer2);
  EXPECT_EQ(mixer1, mixer2);  // Same latency => same mixer.
  EXPECT_EQ(1u, mixer_count());

  AudioRendererMixer* mixer3 =
      GetMixer(kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kRtc,
               kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer3);
  EXPECT_NE(mixer1, mixer3);
  EXPECT_EQ(2u, mixer_count());  // Another latency => another mixer.

  AudioRendererMixer* mixer4 =
      GetMixer(kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kRtc,
               kDefaultDeviceId, SinkUseState::kExistingSink);
  EXPECT_EQ(mixer3, mixer4);
  EXPECT_EQ(2u, mixer_count());  // Same latency => same mixer.

  AudioRendererMixer* mixer5 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kInteractive,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer5);
  EXPECT_EQ(3u, mixer_count());  // Another latency => another mixer.

  AudioRendererMixer* mixer6 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kInteractive,
      kDefaultDeviceId, SinkUseState::kExistingSink);
  EXPECT_EQ(mixer5, mixer6);
  EXPECT_EQ(3u, mixer_count());  // Same latency => same mixer.

  ReturnMixer(mixer1);
  EXPECT_EQ(3u, mixer_count());
  ReturnMixer(mixer2);
  EXPECT_EQ(2u, mixer_count());
  ReturnMixer(mixer3);
  EXPECT_EQ(2u, mixer_count());
  ReturnMixer(mixer4);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer5);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer6);
  EXPECT_EQ(0u, mixer_count());
}

// Verify GetMixer() correctly deduplicate mixers basing on the effects
// requirements.
TEST_F(AudioRendererMixerManagerTest, EffectsMixing) {
  EXPECT_EQ(0u, mixer_count());

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), kSampleRate,
      kBufferSize);
  params.set_effects(1);
  AudioRendererMixer* mixer1 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer1);
  EXPECT_EQ(1u, mixer_count());

  AudioRendererMixer* mixer2 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kExistingSink);
  ASSERT_TRUE(mixer2);
  EXPECT_EQ(mixer1, mixer2);  // Same effects => same mixer.
  EXPECT_EQ(1u, mixer_count());

  params.set_effects(2);
  AudioRendererMixer* mixer3 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer3);
  EXPECT_NE(mixer1, mixer3);
  EXPECT_EQ(2u, mixer_count());  // Another effects => another mixer.

  AudioRendererMixer* mixer4 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kExistingSink);
  EXPECT_EQ(mixer3, mixer4);
  EXPECT_EQ(2u, mixer_count());  // Same effects => same mixer.

  params.set_effects(3);
  AudioRendererMixer* mixer5 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);
  ASSERT_TRUE(mixer5);
  EXPECT_EQ(3u, mixer_count());  // Another effects => another mixer.

  AudioRendererMixer* mixer6 = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kExistingSink);
  EXPECT_EQ(mixer5, mixer6);
  EXPECT_EQ(3u, mixer_count());  // Same effects => same mixer.

  ReturnMixer(mixer1);
  EXPECT_EQ(3u, mixer_count());
  ReturnMixer(mixer2);
  EXPECT_EQ(2u, mixer_count());
  ReturnMixer(mixer3);
  EXPECT_EQ(2u, mixer_count());
  ReturnMixer(mixer4);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer5);
  EXPECT_EQ(1u, mixer_count());
  ReturnMixer(mixer6);
  EXPECT_EQ(0u, mixer_count());
}

// Verify output bufer size of the mixer is correctly adjusted for Playback
// latency.
TEST_F(AudioRendererMixerManagerTest, MixerParamsLatencyPlayback) {
  mock_sink_ = CreateNormalSink();

  // Expecting hardware buffer size of 128 frames
  EXPECT_EQ(44100,
            mock_sink_->GetOutputDeviceInfo().output_params().sample_rate());
  // Expecting hardware buffer size of 128 frames
  EXPECT_EQ(
      128,
      mock_sink_->GetOutputDeviceInfo().output_params().frames_per_buffer());

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), 32000, 512);
  params.set_latency_tag(AudioLatency::Type::kPlayback);

  AudioRendererMixer* mixer =
      GetMixer(kLocalFrameToken, kFrameToken, params, params.latency_tag(),
               kDefaultDeviceId, SinkUseState::kNewSink);

  if (AudioLatency::IsResamplingPassthroughSupported(params.latency_tag())) {
    // Expecting input sample rate
    EXPECT_EQ(32000, mixer->get_output_params_for_testing().sample_rate());
#if BUILDFLAG(IS_FUCHSIA)
    // On Fuchsia use 80ms buffer.
    EXPECT_EQ(2560, mixer->get_output_params_for_testing().frames_per_buffer());
#else
    // Round up 20 ms (640) to the power of 2.
    EXPECT_EQ(1024, mixer->get_output_params_for_testing().frames_per_buffer());
#endif
  } else {
    // Expecting hardware sample rate
    EXPECT_EQ(44100, mixer->get_output_params_for_testing().sample_rate());

// 20 ms at 44100 is 882 frames per buffer.
#if BUILDFLAG(IS_WIN)
    // Round up 882 to the nearest multiple of the output buffer size (128).
    // which is 7 * 128 = 896
    EXPECT_EQ(896, mixer->get_output_params_for_testing().frames_per_buffer());
#else
    // Round up 882 to the power of 2.
    EXPECT_EQ(1024, mixer->get_output_params_for_testing().frames_per_buffer());
#endif  // BUILDFLAG(IS_WIN)
  }

  ReturnMixer(mixer);
}

// Verify output bufer size of the mixer is correctly adjusted for Playback
// latency when the device buffer size exceeds 20 ms.
TEST_F(AudioRendererMixerManagerTest,
       MixerParamsLatencyPlaybackLargeDeviceBufferSize) {
  mock_sink_ = new media::MockAudioRendererSink(
      std::string(), media::OUTPUT_DEVICE_STATUS_OK,
      AudioParameters(AudioParameters::AUDIO_PCM_LINEAR,
                      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(),
                      44100, 2048));
  EXPECT_CALL(*mock_sink_, Stop()).Times(1);

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), 32000, 512);
  params.set_latency_tag(AudioLatency::Type::kPlayback);

  AudioRendererMixer* mixer =
      GetMixer(kLocalFrameToken, kFrameToken, params, params.latency_tag(),
               kDefaultDeviceId, SinkUseState::kNewSink);

  // 20 ms at 44100 is 882 frames per buffer.
  if (AudioLatency::IsResamplingPassthroughSupported(params.latency_tag())) {
    // Expecting input sample rate
    EXPECT_EQ(32000, mixer->get_output_params_for_testing().sample_rate());
  } else {
    // Expecting hardware sample rate
    EXPECT_EQ(44100, mixer->get_output_params_for_testing().sample_rate());
  }

#if BUILDFLAG(IS_FUCHSIA)
  // On Fuchsia the buffer is rounder to a whole numbem of audio scheduling
  // periods.
  EXPECT_EQ(2560, mixer->get_output_params_for_testing().frames_per_buffer());
#else
  // Prefer device buffer size (2048) if is larger than 20 ms buffer size.
  EXPECT_EQ(2048, mixer->get_output_params_for_testing().frames_per_buffer());
#endif

  ReturnMixer(mixer);
}

// Verify output bufer size of the mixer is correctly adjusted for Playback
// latency when output audio is fake.
TEST_F(AudioRendererMixerManagerTest, MixerParamsLatencyPlaybackFakeAudio) {
  mock_sink_ = new media::MockAudioRendererSink(
      std::string(), media::OUTPUT_DEVICE_STATUS_OK,
      AudioParameters(AudioParameters::AUDIO_FAKE,
                      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(),
                      44100, 2048));
  EXPECT_CALL(*mock_sink_, Stop()).Times(1);

  media::AudioParameters params(
      AudioParameters::AUDIO_PCM_LINEAR,
      media::ChannelLayoutConfig::FromLayout<kChannelLayout>(), 32000, 512);

  AudioRendererMixer* mixer = GetMixer(
      kLocalFrameToken, kFrameToken, params, AudioLatency::Type::kPlayback,
      kDefaultDeviceId, SinkUseState::kNewSink);

  // Expecting input sample rate
  EXPECT_EQ(32000, mixer->get_output_params_for_testing().sample_rate());

  // 20 ms at 32000 is 640 frames per buffer.
#if BUILDFLAG(IS_WIN)
  // Use 20 ms buffer.
  EXPECT_EQ(640, mixer->get_output_params_for_testing().frames_per_buffer());
#elif BUILDFLAG(IS_FUCHSIA)
  // Use 80 ms buffer.
  EXPECT_EQ(2560, mixer->get_output_params_for_testing().frames_per_buffer());
#else
  // Ignore device buffer size, round up 640 to the power of 2.
  EXPECT_EQ(1024, mixer->get_output_params_for_testing().frames_per_buffer());
#endif  // BUILDFLAG(IS_W
```