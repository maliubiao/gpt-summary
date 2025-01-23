Response:
The user wants to understand the functionality of the `media_stream_audio_processor_test.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose of the file:** Based on the name, it's a test file for the `MediaStreamAudioProcessor` class.
2. **Analyze the included headers:** These will give clues about the functionalities being tested (e.g., audio processing, media streams, WebRTC).
3. **Examine the test structure:** Look for `TEST_F`, `TEST_P`, and other testing macros to understand the different test cases.
4. **Summarize the functionalities tested:** Focus on what aspects of `MediaStreamAudioProcessor` are being verified.
5. **Relate to web technologies (JavaScript, HTML, CSS):** Consider how the tested functionalities are exposed or used in web applications.
6. **Infer logical reasoning:** Identify test cases that validate specific input-output behaviors.
7. **Consider user/programming errors:** Think about common mistakes when using or configuring audio processing in web contexts.
8. **Trace user actions:**  Describe how a user's interaction in a browser might lead to the execution of this code.
9. **Provide a summary of the file's functions:** Concisely state what the file does.
这是 `blink/renderer/modules/mediastream/media_stream_audio_processor_test.cc` 文件的第一部分，它主要的功能是 **测试 Blink 渲染引擎中 `MediaStreamAudioProcessor` 类的各种功能和特性**。

以下是对其功能的详细解释，以及与 JavaScript、HTML、CSS 的关系，逻辑推理，常见错误和用户操作路径的说明：

**功能归纳:**

1. **单元测试框架:**  该文件使用了 Google Test 框架 (`testing/gmock/include/gmock/gmock.h` 和 `testing/gtest/include/gtest/gtest.h`) 来编写单元测试。这意味着它的主要目的是验证 `MediaStreamAudioProcessor` 类的行为是否符合预期。

2. **测试核心类 `MediaStreamAudioProcessor`:**  顾名思义，它专注于测试 `MediaStreamAudioProcessor` 类的各种方法，例如音频处理、格式转换、回声消除、增益控制等等。

3. **测试音频处理流程:**  文件中模拟了音频数据的输入，并验证 `MediaStreamAudioProcessor` 处理后的输出是否符合预期。这包括测试启用和禁用不同的音频处理模块（例如回声消除、噪声抑制、自动增益控制）时的行为。

4. **测试音频格式转换:**  测试了在不同的输入音频格式下，`MediaStreamAudioProcessor` 是否能正确处理并输出期望的格式。例如，测试了不同的采样率和声道数。

5. **测试与 WebRTC 的集成:**  `MediaStreamAudioProcessor` 与 WebRTC 音频处理模块紧密相关，文件中测试了这种集成，包括测试默认的音频处理配置。

6. **测试 AEC Dump 功能:**  测试了将音频处理过程中的数据转储到文件的功能，这对于调试音频问题很有用。

7. **测试多声道音频处理:**  专门创建了 `MediaStreamAudioProcessorTestMultichannel` 测试套件来测试多声道音频的处理。

8. **测试音频数据回调:**  测试了当 `MediaStreamAudioProcessor` 处理完音频数据后，是否能及时地通过回调函数 (`MockProcessedCaptureCallback`) 将处理后的数据传递出去。

**与 JavaScript, HTML, CSS 的关系:**

虽然此文件是 C++ 代码，直接与 JavaScript, HTML, CSS 没有直接的代码关联，但它测试的 `MediaStreamAudioProcessor` 类是 Web Audio API 和 WebRTC API 的底层实现的一部分，这些 API 可以在 JavaScript 中被调用，从而影响到网页的功能。

* **JavaScript (Web Audio API 和 WebRTC API):**
    * **`getUserMedia()`:**  当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 获取用户麦克风音频流时，Blink 引擎会创建 `MediaStreamAudioProcessor` 的实例来处理音频数据。
    * **WebRTC 的 `RTCPeerConnection`:**  在使用 WebRTC 进行音视频通信时，`MediaStreamAudioProcessor` 负责处理本地麦克风采集到的音频，进行各种音频处理后，再发送给远端。
    * **Web Audio API 的 `MediaStreamSourceNode`:**  当使用 Web Audio API 处理来自 `getUserMedia()` 的音频流时，`MediaStreamSourceNode` 可能会将音频数据传递给 `MediaStreamAudioProcessor` 进行处理。

* **HTML:**  HTML 主要负责页面的结构，与此文件的关联不直接。但通过 HTML 元素（如 `<audio>` 或用户交互触发的 JavaScript 代码）可以间接地触发音频流的获取和处理。

* **CSS:**  CSS 负责页面的样式，与此文件完全无关。

**举例说明:**

假设一个用户在网页上使用 WebRTC 进行视频通话：

1. **用户操作:** 用户点击网页上的 "开始通话" 按钮。
2. **JavaScript 调用:**  网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: true })` 来请求用户的麦克风访问权限。
3. **Blink 引擎处理:** Blink 引擎接收到请求，获取麦克风音频流，并创建一个 `MediaStreamAudioProcessor` 实例来处理音频数据。
4. **`media_stream_audio_processor_test.cc` 的作用:**  这个测试文件中的测试用例会模拟音频数据的输入，并验证 `MediaStreamAudioProcessor` 是否正确地进行了回声消除、噪声抑制等操作，确保通话质量。
5. **WebRTC 连接:** 处理后的音频数据会被传递给 WebRTC 的 `RTCPeerConnection`，并通过网络发送给通话的另一方。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一段包含回声的音频数据。
* **期望输出 (如果回声消除启用):**  `MediaStreamAudioProcessor` 处理后的音频数据中，回声被有效地降低或消除。
* **测试用例:** 文件中可能会有类似的测试用例，通过模拟带有回声的音频输入，然后断言 `MockProcessedCaptureCallback` 收到的处理后音频数据中回声的能量显著降低。

* **假设输入:**  采样率为 44100Hz 的音频数据。
* **期望输出 (如果 WebRTC 音频处理启用):** `MediaStreamAudioProcessor` 将音频数据重采样到 WebRTC 推荐的采样率 (通常是 48000Hz 或更低)。
* **测试用例:** 文件中会有测试用例验证 `audio_processor.output_format().sample_rate()` 的值是否为预期的 WebRTC 采样率。

**用户或编程常见的使用错误:**

1. **未正确配置音频处理参数:**  开发者可能没有正确地设置 `AudioProcessingProperties`，导致音频处理功能没有按预期启用或禁用。例如，想要禁用回声消除，但配置错误导致回声消除仍然生效。测试文件中的用例可以帮助验证这些配置是否生效。

2. **误解音频处理对性能的影响:**  某些音频处理功能（如噪声抑制）会消耗一定的 CPU 资源。开发者可能在低端设备上过度使用音频处理，导致性能问题。测试文件可以帮助评估不同音频处理配置的性能影响。

3. **处理多声道音频时的错误假设:**  开发者可能没有考虑到多声道音频的处理逻辑，导致在处理多声道音频时出现错误。`MediaStreamAudioProcessorTestMultichannel` 可以帮助发现这类问题。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户报告音频问题:**  用户在使用浏览器进行音视频通话或录音时，可能会遇到诸如回声、噪音过大、音量异常等问题。
2. **开发者介入调试:** 开发者会尝试重现用户的问题，并开始调试 Blink 引擎的音频处理流程。
3. **定位到 `MediaStreamAudioProcessor`:**  开发者可能会怀疑是 `MediaStreamAudioProcessor` 的行为异常导致了问题。
4. **查看测试文件:** 为了理解 `MediaStreamAudioProcessor` 的工作原理和查找潜在的 bug，开发者会查看 `media_stream_audio_processor_test.cc` 文件，了解其测试覆盖范围和已知的行为。
5. **运行相关测试:**  开发者可能会运行文件中的特定测试用例，以验证 `MediaStreamAudioProcessor` 在特定场景下的行为是否符合预期。
6. **修改代码并重新测试:**  如果发现测试失败或行为异常，开发者会修改 `MediaStreamAudioProcessor` 的代码，并重新运行测试，直到所有测试都通过。

**总结 `media_stream_audio_processor_test.cc` (第1部分) 的功能:**

总而言之，该文件的主要功能是提供一个全面的测试套件，用于验证 Blink 引擎中 `MediaStreamAudioProcessor` 类的各种音频处理功能，确保其在各种场景下都能正确地处理音频数据，并与 WebRTC 等相关模块正确集成。它对于保证浏览器音频功能的质量和稳定性至关重要。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_audio_processor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream_audio_processor.h"

#include <stddef.h>
#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/aligned_memory.h"
#include "base/numerics/safe_conversions.h"
#include "base/path_service.h"
#include "base/test/mock_callback.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "build/chromecast_buildflags.h"
#include "media/base/audio_bus.h"
#include "media/base/audio_parameters.h"
#include "media/webrtc/constants.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/renderer/modules/webrtc/webrtc_audio_device_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_processor_options.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/webrtc/api/media_stream_interface.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::Return;

using media::AudioParameters;

using AnalogGainController =
    webrtc::AudioProcessing::Config::GainController1::AnalogGainController;

namespace blink {
namespace {

using MockProcessedCaptureCallback =
    base::MockRepeatingCallback<void(const media::AudioBus& audio_bus,
                                     base::TimeTicks audio_capture_time,
                                     std::optional<double> new_volume)>;

// The number of packets used for testing.
const int kNumberOfPacketsForTest = 100;

void ReadDataFromSpeechFile(base::HeapArray<int16_t>& data) {
  base::FilePath file;
  CHECK(base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &file));
  file = file.Append(FILE_PATH_LITERAL("media"))
             .Append(FILE_PATH_LITERAL("test"))
             .Append(FILE_PATH_LITERAL("data"))
             .Append(FILE_PATH_LITERAL("speech_16b_stereo_48kHz.raw"));
  DCHECK(base::PathExists(file));
  std::optional<int64_t> data_file_size64 = base::GetFileSize(file);
  DCHECK(data_file_size64.has_value());
  auto bytes = base::as_writable_chars(data.as_span());
  EXPECT_EQ(base::checked_cast<int>(bytes.size_bytes()),
            base::ReadFile(file, bytes));
  DCHECK(data_file_size64.value() > base::checked_cast<int64_t>(data.size()));
}

}  // namespace

class MediaStreamAudioProcessorTest : public ::testing::Test {
 public:
  MediaStreamAudioProcessorTest()
      : params_(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                media::ChannelLayoutConfig::Stereo(),
                48000,
                480) {}

 protected:
  // Helper method to save duplicated code.
  static void ProcessDataAndVerifyFormat(
      MediaStreamAudioProcessor& audio_processor,
      MockProcessedCaptureCallback& mock_capture_callback,
      int expected_output_sample_rate,
      int expected_output_channels,
      int expected_output_buffer_size) {
    // Read the audio data from a file.
    const media::AudioParameters& params =
        audio_processor.GetInputFormatForTesting();
    const int frames_per_packet =
        params.frames_per_buffer() * params.channels();
    const size_t length = frames_per_packet * kNumberOfPacketsForTest;
    auto capture_data = base::HeapArray<int16_t>::Uninit(length);
    ReadDataFromSpeechFile(capture_data);
    const int16_t* data_ptr =
        reinterpret_cast<const int16_t*>(capture_data.data());
    std::unique_ptr<media::AudioBus> data_bus =
        media::AudioBus::Create(params.channels(), params.frames_per_buffer());

    const base::TimeTicks input_capture_time = base::TimeTicks::Now();
    int num_preferred_channels = -1;
    for (int i = 0; i < kNumberOfPacketsForTest; ++i) {
      data_bus->FromInterleaved<media::SignedInt16SampleTypeTraits>(
          data_ptr, data_bus->frames());

      // 1. Provide playout audio, if echo cancellation is enabled.
      const bool is_aec_enabled =
          audio_processor.has_webrtc_audio_processing() &&
          (*audio_processor.GetAudioProcessingModuleConfigForTesting())
              .echo_canceller.enabled;
      if (is_aec_enabled) {
        audio_processor.OnPlayoutData(data_bus.get(), params.sample_rate(),
                                      base::Milliseconds(10));
      }

      // 2. Set up expectations and process captured audio.
      EXPECT_CALL(mock_capture_callback, Run(_, _, _))
          .WillRepeatedly([&](const media::AudioBus& processed_audio,
                              base::TimeTicks audio_capture_time,
                              std::optional<double> new_volume) {
            EXPECT_EQ(audio_capture_time, input_capture_time);
          });
      audio_processor.ProcessCapturedAudio(*data_bus, input_capture_time,
                                           num_preferred_channels, 1.0);
      EXPECT_EQ(expected_output_sample_rate,
                audio_processor.output_format().sample_rate());
      EXPECT_EQ(expected_output_channels,
                audio_processor.output_format().channels());
      EXPECT_EQ(expected_output_buffer_size,
                audio_processor.output_format().frames_per_buffer());

      data_ptr += params.frames_per_buffer() * params.channels();

      // Test different values of num_preferred_channels.
      if (++num_preferred_channels > 5) {
        num_preferred_channels = 0;
      }
    }
  }

  // TODO(bugs.webrtc.org/7494): Remove/reduce duplication with
  // `CreateWebRtcAudioProcessingModuleTest.CheckDefaultAudioProcessingConfig`.
  void VerifyDefaultComponents(MediaStreamAudioProcessor& audio_processor) {
    ASSERT_TRUE(audio_processor.has_webrtc_audio_processing());
    const webrtc::AudioProcessing::Config config =
        *audio_processor.GetAudioProcessingModuleConfigForTesting();

    EXPECT_FALSE(config.pre_amplifier.enabled);
    EXPECT_TRUE(config.echo_canceller.enabled);

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_MAC) || BUILDFLAG(IS_LINUX)
    EXPECT_FALSE(config.gain_controller1.enabled);
    EXPECT_TRUE(config.gain_controller2.enabled);
#elif BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_FUCHSIA)
    EXPECT_FALSE(config.gain_controller1.enabled);
    EXPECT_TRUE(config.gain_controller2.enabled);
#elif BUILDFLAG(IS_CASTOS) || BUILDFLAG(IS_CAST_ANDROID)
    EXPECT_TRUE(config.gain_controller1.enabled);
    EXPECT_FALSE(config.gain_controller2.enabled);
#elif BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
    EXPECT_FALSE(config.gain_controller1.enabled);
    EXPECT_TRUE(config.gain_controller2.enabled);
#else
    GTEST_FAIL() << "Undefined expectation.";
#endif

    EXPECT_TRUE(config.noise_suppression.enabled);
    EXPECT_EQ(config.noise_suppression.level,
              webrtc::AudioProcessing::Config::NoiseSuppression::kHigh);
    EXPECT_FALSE(config.transient_suppression.enabled);

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
    // Android uses echo cancellation optimized for mobiles.
    EXPECT_TRUE(config.echo_canceller.mobile_mode);
#else
    EXPECT_FALSE(config.echo_canceller.mobile_mode);
#endif
  }

  test::TaskEnvironment task_environment_;
  media::AudioParameters params_;
  MockProcessedCaptureCallback mock_capture_callback_;
};

class MediaStreamAudioProcessorTestMultichannel
    : public MediaStreamAudioProcessorTest,
      public ::testing::WithParamInterface<bool> {};

// Test crashing with ASAN on Android. crbug.com/468762
#if BUILDFLAG(IS_ANDROID) && defined(ADDRESS_SANITIZER)
#define MAYBE_WithAudioProcessing DISABLED_WithAudioProcessing
#else
#define MAYBE_WithAudioProcessing WithAudioProcessing
#endif
TEST_P(MediaStreamAudioProcessorTestMultichannel, MAYBE_WithAudioProcessing) {
  const bool use_multichannel_processing = GetParam();
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  blink::AudioProcessingProperties properties;
  scoped_refptr<MediaStreamAudioProcessor> audio_processor(
      new rtc::RefCountedObject<MediaStreamAudioProcessor>(
          mock_capture_callback_.Get(),
          properties.ToAudioProcessingSettings(use_multichannel_processing),
          params_, webrtc_audio_device));
  EXPECT_TRUE(audio_processor->has_webrtc_audio_processing());
  VerifyDefaultComponents(*audio_processor);

  const int expected_output_channels =
      use_multichannel_processing ? params_.channels() : 1;
  ProcessDataAndVerifyFormat(*audio_processor, mock_capture_callback_,
                             media::WebRtcAudioProcessingSampleRateHz(),
                             expected_output_channels,
                             media::WebRtcAudioProcessingSampleRateHz() / 100);

  // Stop |audio_processor| so that it removes itself from
  // |webrtc_audio_device| and clears its pointer to it.
  audio_processor->Stop();
}

TEST_F(MediaStreamAudioProcessorTest, TurnOffDefaultConstraints) {
  blink::AudioProcessingProperties properties;
  // Turn off the default constraints and pass it to MediaStreamAudioProcessor.
  properties.DisableDefaultProperties();
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  scoped_refptr<MediaStreamAudioProcessor> audio_processor(
      new rtc::RefCountedObject<MediaStreamAudioProcessor>(
          mock_capture_callback_.Get(),
          properties.ToAudioProcessingSettings(
              /*multi_channel_capture_processing=*/true),
          params_, webrtc_audio_device));
  EXPECT_FALSE(audio_processor->has_webrtc_audio_processing());

  ProcessDataAndVerifyFormat(*audio_processor, mock_capture_callback_,
                             params_.sample_rate(), params_.channels(),
                             params_.sample_rate() / 100);

  // Stop |audio_processor| so that it removes itself from
  // |webrtc_audio_device| and clears its pointer to it.
  audio_processor->Stop();
}

// Test crashing with ASAN on Android. crbug.com/468762
#if BUILDFLAG(IS_ANDROID) && defined(ADDRESS_SANITIZER)
#define MAYBE_TestAllSampleRates DISABLED_TestAllSampleRates
#else
#define MAYBE_TestAllSampleRates TestAllSampleRates
#endif
TEST_P(MediaStreamAudioProcessorTestMultichannel, MAYBE_TestAllSampleRates) {
  const bool use_multichannel_processing = GetParam();
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  blink::AudioProcessingProperties properties;

  // TODO(crbug.com/1334991): Clarify WebRTC audio processing support for 96 kHz
  // input.
  static const int kSupportedSampleRates[] = {
    8000,
    16000,
    22050,
    32000,
    44100,
    48000
#if BUILDFLAG(IS_CASTOS) || BUILDFLAG(IS_CAST_ANDROID)
    ,
    96000
#endif  // BUILDFLAG(IS_CASTOS) || BUILDFLAG(IS_CAST_ANDROID)
  };
  for (int sample_rate : kSupportedSampleRates) {
    SCOPED_TRACE(testing::Message() << "sample_rate=" << sample_rate);
    int buffer_size = sample_rate / 100;
    media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                  media::ChannelLayoutConfig::Stereo(),
                                  sample_rate, buffer_size);
    scoped_refptr<MediaStreamAudioProcessor> audio_processor(
        new rtc::RefCountedObject<MediaStreamAudioProcessor>(
            mock_capture_callback_.Get(),
            properties.ToAudioProcessingSettings(use_multichannel_processing),
            params, webrtc_audio_device));
    EXPECT_TRUE(audio_processor->has_webrtc_audio_processing());
    VerifyDefaultComponents(*audio_processor);

    // TODO(crbug.com/1336055): Investigate why chromecast devices need special
    // logic here.
    int expected_sample_rate =
#if BUILDFLAG(IS_CASTOS) || BUILDFLAG(IS_CAST_ANDROID)
        std::min(sample_rate, media::WebRtcAudioProcessingSampleRateHz());
#else
        media::WebRtcAudioProcessingSampleRateHz();
#endif  // BUILDFLAG(IS_CASTOS) || BUILDFLAG(IS_CAST_ANDROID)
    const int expected_output_channels =
        use_multichannel_processing ? params_.channels() : 1;
    ProcessDataAndVerifyFormat(*audio_processor, mock_capture_callback_,
                               expected_sample_rate, expected_output_channels,
                               expected_sample_rate / 100);

    // Stop |audio_processor| so that it removes itself from
    // |webrtc_audio_device| and clears its pointer to it.
    audio_processor->Stop();
  }
}

TEST_F(MediaStreamAudioProcessorTest, StartStopAecDump) {
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  blink::AudioProcessingProperties properties;

  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
  base::FilePath temp_file_path;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(temp_directory.GetPath(),
                                             &temp_file_path));
  media::AudioParameters params(
      media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
      media::ChannelLayoutConfig::FromLayout<
          media::CHANNEL_LAYOUT_STEREO_AND_KEYBOARD_MIC>(),
      48000, 480);
  {
    scoped_refptr<MediaStreamAudioProcessor> audio_processor(
        new rtc::RefCountedObject<MediaStreamAudioProcessor>(
            mock_capture_callback_.Get(),
            properties.ToAudioProcessingSettings(
                /*multi_channel_capture_processing=*/true),
            params, webrtc_audio_device));

    // Start and stop recording.
    audio_processor->OnStartDump(base::File(
        temp_file_path, base::File::FLAG_WRITE | base::File::FLAG_OPEN));
    audio_processor->OnStopDump();

    // Start and wait for d-tor.
    audio_processor->OnStartDump(base::File(
        temp_file_path, base::File::FLAG_WRITE | base::File::FLAG_OPEN));
  }

  // Check that dump file is non-empty after audio processor has been
  // destroyed. Note that this test fails when compiling WebRTC
  // without protobuf support, rtc_enable_protobuf=false.
  std::string output;
  ASSERT_TRUE(base::ReadFileToString(temp_file_path, &output));
  ASSERT_FALSE(output.empty());
  // The tempory file is deleted when temp_directory exists scope.
}

TEST_P(MediaStreamAudioProcessorTestMultichannel, TestStereoAudio) {
  const bool use_multichannel_processing = GetParam();
  SCOPED_TRACE(testing::Message() << "use_multichannel_processing="
                                  << use_multichannel_processing);
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  const media::AudioParameters source_params(
      media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
      media::ChannelLayoutConfig::Stereo(), 48000, 480);

  // Construct a stereo audio bus and fill the left channel with content.
  std::unique_ptr<media::AudioBus> data_bus =
      media::AudioBus::Create(params_.channels(), params_.frames_per_buffer());
  data_bus->Zero();
  for (int i = 0; i < data_bus->frames(); ++i) {
    data_bus->channel(0)[i] = (i % 11) * 0.1f - 0.5f;
  }

  // Test without and with audio processing enabled.
  constexpr bool kUseApmValues[] =
#if BUILDFLAG(IS_IOS)
      // TODO(https://crbug.com/1417474): `false` fails on ios-blink platform
      // due to a special case for iOS in settings.NeedWebrtcAudioProcessing()
      {true};
#else
      {false, true};
#endif
  for (bool use_apm : kUseApmValues) {
    // No need to test stereo with APM if disabled.
    if (use_apm && !use_multichannel_processing) {
      continue;
    }
    SCOPED_TRACE(testing::Message() << "use_apm=" << use_apm);

    blink::AudioProcessingProperties properties;
    if (!use_apm) {
      // Turn off the audio processing.
      properties.DisableDefaultProperties();
    }
    scoped_refptr<MediaStreamAudioProcessor> audio_processor(
        new rtc::RefCountedObject<MediaStreamAudioProcessor>(
            mock_capture_callback_.Get(),
            properties.ToAudioProcessingSettings(use_multichannel_processing),
            source_params, webrtc_audio_device));
    EXPECT_EQ(audio_processor->has_webrtc_audio_processing(), use_apm);
    // There's no sense in continuing if this fails.
    ASSERT_EQ(2, audio_processor->output_format().channels());

    // Run the test consecutively to make sure the stereo channels are not
    // flipped back and forth.
    const base::TimeTicks pushed_capture_time = base::TimeTicks::Now();

    for (int num_preferred_channels = 0; num_preferred_channels <= 5;
         ++num_preferred_channels) {
      SCOPED_TRACE(testing::Message()
                   << "num_preferred_channels=" << num_preferred_channels);
      for (int i = 0; i < kNumberOfPacketsForTest; ++i) {
        SCOPED_TRACE(testing::Message() << "packet index i=" << i);
        EXPECT_CALL(mock_capture_callback_, Run(_, _, _)).Times(1);
        // Pass audio for processing.
        audio_processor->ProcessCapturedAudio(*data_bus, pushed_capture_time,
                                              num_preferred_channels, 0.0);
      }
      // At this point, the audio processing algorithms have gotten past any
      // initial buffer silence generated from resamplers, FFTs, and whatnot.
      // Set up expectations via the mock callback:
      EXPECT_CALL(mock_capture_callback_, Run(_, _, _))
          .WillRepeatedly([&](const media::AudioBus& processed_audio,
                              base::TimeTicks audio_capture_time,
                              std::optional<double> new_volume) {
            EXPECT_EQ(audio_capture_time, pushed_capture_time);
            if (!use_apm) {
              EXPECT_FALSE(new_volume.has_value());
            }
            float left_channel_energy = 0.0f;
            float right_channel_energy = 0.0f;
            for (int i = 0; i < processed_audio.frames(); ++i) {
              left_channel_energy +=
                  processed_audio.channel(0)[i] * processed_audio.channel(0)[i];
              right_channel_energy +=
                  processed_audio.channel(1)[i] * processed_audio.channel(1)[i];
            }
            if (use_apm && num_preferred_channels <= 1) {
              // Mono output. Output channels are averaged.
              EXPECT_NE(left_channel_energy, 0);
              EXPECT_NE(right_channel_energy, 0);
            } else {
              // Stereo output. Output channels are independent.
              EXPECT_NE(left_channel_energy, 0);
              EXPECT_EQ(right_channel_energy, 0);
            }
          });
      // Process one more frame of audio.
      audio_processor->ProcessCapturedAudio(*data_bus, pushed_capture_time,
                                            num_preferred_channels, 0.0);
    }

    // Stop |audio_processor| so that it removes itself from
    // |webrtc_audio_device| and clears its pointer to it.
    audio_processor->Stop();
  }
}

// Ensure that discrete channel layouts do not crash with audio processing
// enabled.
TEST_F(MediaStreamAudioProcessorTest, DiscreteChannelLayout) {
  blink::AudioProcessingProperties properties;
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());

  // Test both 1 and 2 discrete channels.
  for (int channels = 1; channels <= 2; ++channels) {
    media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                  {media::CHANNEL_LAYOUT_DISCRETE, channels},
                                  48000, 480);
    scoped_refptr<MediaStreamAudioProcessor> audio_processor(
        new rtc::RefCountedObject<MediaStreamAudioProcessor>(
            mock_capture_callback_.Get(),
            properties.ToAudioProcessingSettings(
                /*multi_channel_capture_processing==*/true),
            params, webrtc_audio_device));
    EXPECT_TRUE(audio_processor->has_webrtc_audio_processing());
    audio_processor->Stop();
  }
}

INSTANTIATE_TEST_SUITE_P(MediaStreamAudioProcessorMultichannelAffectedTests,
                         MediaStreamAudioProcessorTestMultichannel,
                         ::testing::Values(false, true));

// When audio processing is performed, processed audio should be delivered as
// soon as 10 ms of audio has been received.
TEST(MediaStreamAudioProcessorCallbackTest,
     ProcessedAudioIsDeliveredAsSoonAsPossibleWithShortBuffers) {
  test::TaskEnvironment task_environment_;
  MockProcessedCaptureCallback mock_capture_callback;
  blink::AudioProcessingProperties properties;
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  // Set buffer size to 4 ms.
  media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                media::ChannelLayoutConfig::Stereo(), 48000,
                                48000 * 4 / 1000);
  scoped_refptr<MediaStreamAudioProcessor> audio_processor(
      new rtc::RefCountedObject<MediaStreamAudioProcessor>(
          mock_capture_callback.Get(),
          properties.ToAudioProcessingSettings(
              /*multi_channel_capture_processing=*/true),
          params, webrtc_audio_device));
  ASSERT_TRUE(audio_processor->has_webrtc_audio_processing());

  int output_sample_rate = audio_processor->output_format().sample_rate();
  std::unique_ptr<media::AudioBus> data_bus =
      media::AudioBus::Create(params.channels(), params.frames_per_buffer());
  data_bus->Zero();

  auto check_audio_length = [&](const media::AudioBus& processed_audio,
                                base::TimeTicks, std::optional<double>) {
    EXPECT_EQ(processed_audio.frames(), output_sample_rate * 10 / 1000);
  };

  // 4 ms of data: Not enough to process.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _)).Times(0);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);
  // 8 ms of data: Not enough to process.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _)).Times(0);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);
  // 12 ms of data: Should trigger callback, with 2 ms left in the processor.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(1)
      .WillOnce(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);
  // 2 + 4 ms of data: Not enough to process.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _)).Times(0);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);
  // 10 ms of data: Should trigger callback.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(1)
      .WillOnce(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);

  audio_processor->Stop();
}

// When audio processing is performed, input containing 10 ms several times over
// should trigger a comparable number of processing callbacks.
TEST(MediaStreamAudioProcessorCallbackTest,
     ProcessedAudioIsDeliveredAsSoonAsPossibleWithLongBuffers) {
  test::TaskEnvironment task_environment_;
  MockProcessedCaptureCallback mock_capture_callback;
  blink::AudioProcessingProperties properties;
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  // Set buffer size to 35 ms.
  media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                media::ChannelLayoutConfig::Stereo(), 48000,
                                48000 * 35 / 1000);
  scoped_refptr<MediaStreamAudioProcessor> audio_processor(
      new rtc::RefCountedObject<MediaStreamAudioProcessor>(
          mock_capture_callback.Get(),
          properties.ToAudioProcessingSettings(
              /*multi_channel_capture_processing=*/true),
          params, webrtc_audio_device));
  ASSERT_TRUE(audio_processor->has_webrtc_audio_processing());

  int output_sample_rate = audio_processor->output_format().sample_rate();
  std::unique_ptr<media::AudioBus> data_bus =
      media::AudioBus::Create(params.channels(), params.frames_per_buffer());
  data_bus->Zero();

  auto check_audio_length = [&](const media::AudioBus& processed_audio,
                                base::TimeTicks, std::optional<double>) {
    EXPECT_EQ(processed_audio.frames(), output_sample_rate * 10 / 1000);
  };

  // 35 ms of audio --> 3 chunks of 10 ms, and 5 ms left in the processor.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(3)
      .WillRepeatedly(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);
  // 5 + 35 ms of audio --> 4 chunks of 10 ms.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(4)
      .WillRepeatedly(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);

  audio_processor->Stop();
}

// When no audio processing is performed, audio is delivered immediately. Note
// that unlike the other cases, unprocessed audio input of less than 10 ms is
// forwarded directly instead of collecting chunks of 10 ms.
TEST(MediaStreamAudioProcessorCallbackTest,
     UnprocessedAudioIsDeliveredImmediatelyWithShortBuffers) {
  test::TaskEnvironment task_environment_;
  MockProcessedCaptureCallback mock_capture_callback;
  blink::AudioProcessingProperties properties;
  properties.DisableDefaultProperties();
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  // Set buffer size to 4 ms.
  media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                media::ChannelLayoutConfig::Stereo(), 48000,
                                48000 * 4 / 1000);
  scoped_refptr<MediaStreamAudioProcessor> audio_processor(
      new rtc::RefCountedObject<MediaStreamAudioProcessor>(
          mock_capture_callback.Get(),
          properties.ToAudioProcessingSettings(
              /*multi_channel_capture_processing=*/true),
          params, webrtc_audio_device));
  ASSERT_FALSE(audio_processor->has_webrtc_audio_processing());

  int output_sample_rate = audio_processor->output_format().sample_rate();
  std::unique_ptr<media::AudioBus> data_bus =
      media::AudioBus::Create(params.channels(), params.frames_per_buffer());
  data_bus->Zero();

  auto check_audio_length = [&](const media::AudioBus& processed_audio,
                                base::TimeTicks, std::optional<double>) {
    EXPECT_EQ(processed_audio.frames(), output_sample_rate * 4 / 1000);
  };

  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(1)
      .WillOnce(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);
  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(1)
      .WillOnce(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);

  audio_processor->Stop();
}

// When no audio processing is performed, audio is delivered immediately. Chunks
// greater than 10 ms are delivered in chunks of 10 ms.
TEST(MediaStreamAudioProcessorCallbackTest,
     UnprocessedAudioIsDeliveredImmediatelyWithLongBuffers) {
  test::TaskEnvironment task_environment_;
  MockProcessedCaptureCallback mock_capture_callback;
  blink::AudioProcessingProperties properties;
  properties.DisableDefaultProperties();
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  // Set buffer size to 35 ms.
  media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                media::ChannelLayoutConfig::Stereo(), 48000,
                                48000 * 35 / 1000);
  scoped_refptr<MediaStreamAudioProcessor> audio_processor(
      new rtc::RefCountedObject<MediaStreamAudioProcessor>(
          mock_capture_callback.Get(),
          properties.ToAudioProcessingSettings(
              /*multi_channel_capture_processing=*/true),
          params, webrtc_audio_device));
  ASSERT_FALSE(audio_processor->has_webrtc_audio_processing());

  int output_sample_rate = audio_processor->output_format().sample_rate();
  std::unique_ptr<media::AudioBus> data_bus =
      media::AudioBus::Create(params.channels(), params.frames_per_buffer());
  data_bus->Zero();

  auto check_audio_length = [&](const media::AudioBus& processed_audio,
                                base::TimeTicks, std::optional<double>) {
    EXPECT_EQ(processed_audio.frames(), output_sample_rate * 10 / 1000);
  };

  // 35 ms of audio --> 3 chunks of 10 ms, and 5 ms left in the processor.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(3)
      .WillRepeatedly(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);
  // 5 + 35 ms of audio --> 4 chunks of 10 ms.
  EXPECT_CALL(mock_capture_callback, Run(_, _, _))
      .Times(4)
      .WillRepeatedly(check_audio_length);
  audio_processor->ProcessCapturedAudio(*data_bus, base::TimeTicks::Now(), -1,
                                        1.0);

  audio_processor->Stop();
}

namespace {
scoped_refptr<MediaStreamAudioProcessor> CreateAudioProcessorWithProperties(
    AudioProcessingProperties properties) {
  MockProcessedCaptureCallback mock_capture_callback;
  scoped_refptr<WebRtcAudioDeviceImpl> webrtc_audio_device(
      new rtc::RefCountedObject<WebRtcAudioDeviceImpl>());
  media::AudioParameters params(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                media::ChannelLayoutConfig::Stereo(), 48000,
                                480);
  scoped_refptr<MediaStreamAudioProcessor> audio_processor(
      new rtc::RefCountedObject<MediaStreamAudioProcessor>(
          mock_capture_callback.Get(),
          properties.ToAudioProcessingSettings(
              /*multi_channel_capture_processing=*/true),
          params, webrtc_audio_device));
  return audio_processor;
}
}  // namespace

TEST(MediaStreamAudioProcessorWouldModifyAudioTest, TrueByDefault) {
  test::TaskEnvironment task_environment;
  blink::AudioProcessingProperties properties;
  EXPECT_TRUE(MediaStreamAudioProcessor::WouldModifyAudio(properties));

  scoped_refptr<MediaStreamAudioProcessor> audio_processor =
      CreateAudioProcessorWithProperties(properties);
  EXPECT_TRUE(audio_processor->has_webrtc_audio_processing());
}

TEST(MediaStreamAudioProcessorWouldModifyAudioTest,
     FalseWhenEverythingIsDisabled) {
  test::TaskEnvironment task_environment_;
  blink::AudioProcessingProperties properties;
  properties.DisableDefaultProperties();
  EXPECT_FALSE(MediaStreamAudioProcessor::WouldModifyAudio(properties));

  scoped_refptr<MediaStreamAudioProcessor> audio_processor =
      CreateAudioProcessorWithProperties(properties);
  EXPECT_FALSE(audio_processor->has_webrtc_audio_processing());
}

TEST(MediaStreamAudioProcessorWouldModifyAudioTest,
     FalseWhenOnlyHardwareEffectsAreUsed) {
  test::TaskEnvironment task_environment_;
  blink::AudioProcessingProperties properties;
  properties.DisableDefaultProperties();
  properties.echo_cancellation_type =
      AudioProcessingProperties::EchoCancellationType::kEchoCancellationSystem;
  properties.system_gain_control_activated = true;
  properties.system_noise_suppression_activated = true;
  EXPECT_FALSE(MediaStreamAudioProcessor::WouldModifyAudio(properties));

  scoped_refptr<MediaStreamAudioProcessor> audio_processor =
      CreateAudioProcessorWithProperties(properties);
  EXPECT_FALSE(audio_processor->has_webrtc_audio_processing());
}

#if BUILDFLAG(IS_IOS)
// TODO(https://crbug.com/1417474): Remove legacy iOS case in
// AudioProcessingSettings::NeedWebrtcAudioProcessing().
#define MAYBE_TrueWhenSoftwareEchoCancellationIsEnabled \
  DISABLED_TrueWhenSoftwareEchoCancellationIsEnabled
#else
#define MAYBE_TrueWhenSoftw
```