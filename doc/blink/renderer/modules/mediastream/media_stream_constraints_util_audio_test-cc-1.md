Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the Chromium Blink engine and is located in a testing file. Therefore, the functionality is likely related to testing the audio constraints logic.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name `media_stream_constraints_util_audio_test.cc` strongly suggests it's testing the `MediaStreamConstraintsUtil` specifically for audio.

2. **Analyze the test names:**  The `TEST_P` macros indicate parameterized tests. The names of the tests (`ChannelCount`, `SampleRate`, `Latency`, `EchoCancellation`, `DeviceID`, `VoiceIsolationControl`, `AdvancedCompatibleConstraints`, `NoDevices`, `SourceWithNoAudioProcessing`, `SourceWithAudioProcessing`) reveal the specific audio constraints being tested.

3. **Examine the test logic:**  Each test sets up different constraint scenarios using `constraint_factory_`, calls `SelectSettings` or `SelectSettingsAudioCapture`, and then uses `EXPECT_TRUE` or `EXPECT_FALSE` to verify the expected outcome.

4. **Look for relationships to web technologies:** The tests deal with concepts like sample rate, channel count, latency, echo cancellation, and device IDs, all of which are exposed through JavaScript's WebRTC API in the context of `getUserMedia` and `applyConstraints`.

5. **Consider user errors and debugging:** The tests implicitly demonstrate how incorrect constraints can lead to failures in selecting audio devices or settings.

6. **Synthesize the information into a concise summary.**
这是 blink/renderer/modules/mediastream/media_stream_constraints_util_audio_test.cc 文件的一部分，主要用于测试在 Blink 引擎中处理音频流约束的功能。具体来说，这段代码的功能是：

**归纳功能：**

这段代码主要测试了音频轨道的各种约束条件（Constraints）在有或没有源（Source）的情况下，`SelectSettings` 和 `SelectSettingsAudioCapture` 函数是否能正确地选择或拒绝符合这些约束的音频设置。测试覆盖了以下音频属性：

* **声道数 (Channel Count):** 验证了设置精确声道数约束时的选择行为。
* **采样率 (Sample Rate):**  详细测试了设置精确值、最小值、最大值以及理想值的采样率约束时的选择行为，包括在有源和无源的情况下。
* **延迟 (Latency):**  测试了设置精确值、最小值、最大值以及理想值的延迟约束时的选择行为，包括在有源和无源的情况下。

**与 JavaScript, HTML, CSS 的关系：**

这段 C++ 代码的功能直接支持了 WebRTC API 中 `getUserMedia()` 和 `MediaStreamTrack.applyConstraints()` 方法的实现。这些方法允许 JavaScript 代码指定媒体流的约束条件。

**举例说明：**

1. **JavaScript `getUserMedia()`：**  当一个网页使用 `navigator.mediaDevices.getUserMedia({ audio: { channelCount: 2 } })` 时，JavaScript 代码设置了一个精确的声道数约束。这段 C++ 代码中的 `TEST_P(MediaStreamConstraintsUtilAudioTest, ChannelCount)` 就在测试当收到这样的约束时，Blink 引擎是否能正确地找到并选择具有两个声道的音频设备（或者如果找不到，则返回失败）。

2. **JavaScript `applyConstraints()`：**  如果一个音频轨道已经存在，可以使用 `track.applyConstraints({ sampleRate: { min: 44100 } })` 来更新约束，要求采样率至少为 44100Hz。这段 C++ 代码中的 `TEST_P(MediaStreamConstraintsUtilAudioTest, SampleRateWithSource)` 就在测试当通过 `applyConstraints` 收到这样的约束时，Blink 引擎是否能正确地应用这些约束到已有的音频源上。

**逻辑推理 (假设输入与输出):**

* **假设输入 (ChannelCount 测试):**
    * 可用的音频设备支持 1 个声道和 2 个声道。
    * 约束条件设置为精确 2 个声道 (`constraint_factory_.basic().channel_count.SetExact(2)`).
* **预期输出 (ChannelCount 测试):**
    * `SelectSettingsAudioCapture` 函数应该返回一个表示成功的值 (`EXPECT_TRUE(result.HasValue())`)。

* **假设输入 (SampleRate 测试):**
    * 设备支持的采样率包括 8kHz 和 44.1kHz。
    * 约束条件设置为精确 11111Hz (`constraint_factory_.basic().sample_rate.SetExact(11111)`).
* **预期输出 (SampleRate 测试):**
    * `SelectSettings` 函数应该返回一个表示失败的值 (`EXPECT_FALSE(result.HasValue())`)，因为没有设备支持 11111Hz 的采样率。

**用户或编程常见的使用错误：**

1. **指定了设备不支持的约束值：** 用户在 JavaScript 中可能设置了设备硬件上无法满足的约束，例如指定了超出设备支持范围的采样率或声道数。
    * **示例：** `navigator.mediaDevices.getUserMedia({ audio: { sampleRate: { exact: 192000 } } })`，如果用户的音频设备不支持 192kHz 的采样率，这个请求将会失败。这段 C++ 代码中的测试用例如 `constraint_factory_.basic().sample_rate.SetExact(11111)` 就是在模拟这种情况。

2. **在 `applyConstraints()` 中设置了与现有源不兼容的约束：**  当使用 `applyConstraints()` 时，新的约束可能与当前音频源的属性冲突，导致应用失败。
    * **示例：** 如果一个音频源已经以单声道打开，尝试使用 `track.applyConstraints({ channelCount: 2 })` 可能会失败。这段 C++ 代码中的 `TEST_P(MediaStreamConstraintsUtilAudioTest, SampleRateWithSource)` 和 `TEST_P(MediaStreamConstraintsUtilAudioTest, LatencyWithSource)` 模拟了这种场景。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页，该网页使用了 WebRTC 功能。**
2. **网页中的 JavaScript 代码调用了 `navigator.mediaDevices.getUserMedia({ audio: ... })` 或获取到音频轨道后调用了 `track.applyConstraints({...})`。**
3. **这些 JavaScript 调用会触发 Blink 引擎中相应的 C++ 代码执行。**
4. **`MediaStreamDispatcherHost` 或类似的组件接收到来自渲染进程的请求，要求获取或更新音频流。**
5. **`MediaStreamConstraintsUtil::SelectSettings` 或 `MediaStreamConstraintsUtil::SelectSettingsAudioCapture` 函数会被调用，并传入用户指定的约束条件以及可用的音频设备信息。**
6. **这段测试代码就是在验证 `SelectSettings` 和 `SelectSettingsAudioCapture` 函数在各种约束条件下的行为是否符合预期。**
7. **如果在测试中发现 `EXPECT_FALSE(result.HasValue())` 但实际应该成功的情况，或者反之，就说明 `MediaStreamConstraintsUtil` 中的逻辑存在错误，需要进行调试。** 开发者可能会查看 `blink/renderer/modules/mediastream/media_stream_constraints_util.cc` 中的 `SelectSettings` 和 `SelectSettingsAudioCapture` 函数的实现，并结合这段测试代码来定位问题。

总而言之，这段代码是 Chromium Blink 引擎中用于测试音频流约束处理逻辑的关键部分，确保了 WebRTC 音频功能的正确性和稳定性。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_audio_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
false /* disable_local_echo */,
                                     false /* render_to_associated_sink */);
  int channel_count = kMinChannels;
  for (; channel_count <= media::limits::kMaxChannels; ++channel_count) {
    ResetFactory();
    constraint_factory_.basic().channel_count.SetExact(channel_count);
    auto result = SelectSettingsAudioCapture(
        source.get(), constraint_factory_.CreateMediaConstraints());
    if (channel_count == 2)
      EXPECT_TRUE(result.HasValue());
    else
      EXPECT_FALSE(result.HasValue());
  }
}

TEST_P(MediaStreamConstraintsUtilAudioTest, SampleRate) {
  AudioCaptureSettings result;
  int exact_sample_rate = webrtc::AudioProcessing::kSampleRate8kHz;
  int min_sample_rate = webrtc::AudioProcessing::kSampleRate8kHz;
  // |max_sample_rate| is different based on architecture, namely due to a
  // difference on Android.
  int max_sample_rate =
      std::max(static_cast<int>(media::AudioParameters::kAudioCDSampleRate),
               media::WebRtcAudioProcessingSampleRateHz());
  int ideal_sample_rate = webrtc::AudioProcessing::kSampleRate8kHz;
  if (!IsDeviceCapture()) {
    exact_sample_rate = media::AudioParameters::kAudioCDSampleRate;
    min_sample_rate =
        std::min(static_cast<int>(media::AudioParameters::kAudioCDSampleRate),
                 media::WebRtcAudioProcessingSampleRateHz());
    ideal_sample_rate = media::AudioParameters::kAudioCDSampleRate;
  }

  // Test set exact sampleRate.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetExact(exact_sample_rate);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  constraint_factory_.basic().sample_rate.SetExact(11111);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Only set a min value for the constraint.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetMin(max_sample_rate);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "default_device");

  constraint_factory_.basic().sample_rate.SetMin(max_sample_rate + 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Only set a max value for the constraint.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetMax(min_sample_rate);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  constraint_factory_.basic().sample_rate.SetMax(min_sample_rate - 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Define a bounded range for the constraint.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetMin(min_sample_rate);
  constraint_factory_.basic().sample_rate.SetMax(max_sample_rate);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "default_device");

  constraint_factory_.basic().sample_rate.SetMin(min_sample_rate - 1000);
  constraint_factory_.basic().sample_rate.SetMax(min_sample_rate - 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  constraint_factory_.basic().sample_rate.SetMin(max_sample_rate + 1);
  constraint_factory_.basic().sample_rate.SetMax(max_sample_rate + 1000);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test ideal constraints.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetIdeal(ideal_sample_rate);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  constraint_factory_.basic().sample_rate.SetIdeal(ideal_sample_rate);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  if (IsDeviceCapture()) {
    constraint_factory_.basic().sample_rate.SetIdeal(
        webrtc::AudioProcessing::kSampleRate48kHz + 1000);
    result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(result.device_id(), "default_device");
  }
}

TEST_P(MediaStreamConstraintsUtilAudioTest, SampleRateWithSource) {
  if (!IsDeviceCapture())
    return;

  std::unique_ptr<blink::LocalMediaStreamAudioSource> source =
      GetLocalMediaStreamAudioSource(false /* enable_system_echo_canceller */,
                                     false /* disable_local_echo */,
                                     false /* render_to_associated_sink */);

  // Test set exact sampleRate.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetExact(
      media::AudioParameters::kAudioCDSampleRate);
  auto result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().sample_rate.SetExact(11111);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_FALSE(result.HasValue());

  // Test set min sampleRate.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetMin(
      media::AudioParameters::kAudioCDSampleRate);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().sample_rate.SetMin(
      media::AudioParameters::kAudioCDSampleRate + 1);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_FALSE(result.HasValue());

  // Test set max sampleRate.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetMax(
      media::AudioParameters::kAudioCDSampleRate);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().sample_rate.SetMax(
      media::AudioParameters::kAudioCDSampleRate - 1);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_FALSE(result.HasValue());

  // Test set ideal sampleRate.
  ResetFactory();
  constraint_factory_.basic().sample_rate.SetIdeal(
      media::AudioParameters::kAudioCDSampleRate);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().sample_rate.SetIdeal(
      media::AudioParameters::kAudioCDSampleRate - 1);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());
}

TEST_P(MediaStreamConstraintsUtilAudioTest, Latency) {
  // Test set exact sampleRate.
  ResetFactory();
  if (IsDeviceCapture())
    constraint_factory_.basic().latency.SetExact(0.125);
  else
    constraint_factory_.basic().latency.SetExact(0.01);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  constraint_factory_.basic().latency.SetExact(
      static_cast<double>(blink::kFallbackAudioLatencyMs) / 1000);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "default_device");

  constraint_factory_.basic().latency.SetExact(0.0);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test set min sampleRate.
  ResetFactory();
  if (IsDeviceCapture())
    constraint_factory_.basic().latency.SetMin(0.125);
  else
    constraint_factory_.basic().latency.SetMin(0.01);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  constraint_factory_.basic().latency.SetMin(0.126);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test set max sampleRate.
  ResetFactory();
  constraint_factory_.basic().latency.SetMax(0.1);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "default_device");

  constraint_factory_.basic().latency.SetMax(0.001);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test set bounded sampleRate range.
  ResetFactory();
  if (IsDeviceCapture()) {
    constraint_factory_.basic().latency.SetMin(0.1);
    constraint_factory_.basic().latency.SetMax(0.125);
  } else {
    constraint_factory_.basic().latency.SetMin(0.01);
    constraint_factory_.basic().latency.SetMax(0.1);
  }
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  constraint_factory_.basic().latency.SetMin(0.0001);
  constraint_factory_.basic().latency.SetMax(0.001);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  constraint_factory_.basic().latency.SetMin(0.126);
  constraint_factory_.basic().latency.SetMax(0.2);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test set ideal sampleRate range.
  ResetFactory();
  if (IsDeviceCapture())
    constraint_factory_.basic().latency.SetIdeal(0.125);
  else
    constraint_factory_.basic().latency.SetIdeal(0.01);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "8khz_sample_rate_device");

  constraint_factory_.basic().latency.SetIdeal(0.0);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  if (IsDeviceCapture())
    EXPECT_EQ(result.device_id(), "default_device");
}

TEST_P(MediaStreamConstraintsUtilAudioTest, LatencyWithSource) {
  if (!IsDeviceCapture())
    return;

  std::unique_ptr<blink::LocalMediaStreamAudioSource> source =
      GetLocalMediaStreamAudioSource(false /* enable_system_echo_canceller */,
                                     false /* disable_local_echo */,
                                     false /* render_to_associated_sink */);
  // Test set exact sampleRate.
  ResetFactory();
  constraint_factory_.basic().latency.SetExact(0.01);
  auto result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().latency.SetExact(0.1234);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_FALSE(result.HasValue());

  // Test set min sampleRate.
  ResetFactory();
  constraint_factory_.basic().latency.SetMin(0.01);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().latency.SetMin(0.2);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test set max sampleRate.
  ResetFactory();
  constraint_factory_.basic().latency.SetMax(
      static_cast<double>(blink::kFallbackAudioLatencyMs) / 1000);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().latency.SetMax(0.001);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test set bounded sampleRate range.
  ResetFactory();
  constraint_factory_.basic().latency.SetMin(0.01);
  constraint_factory_.basic().latency.SetMax(0.1);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().latency.SetMin(0.0001);
  constraint_factory_.basic().latency.SetMax(0.001);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  constraint_factory_.basic().latency.SetMin(0.2);
  constraint_factory_.basic().latency.SetMax(0.4);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test set ideal sampleRate.
  ResetFactory();
  constraint_factory_.basic().latency.SetIdeal(0.01);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().latency.SetIdeal(0.1234);
  result = SelectSettingsAudioCapture(
      source.get(), constraint_factory_.CreateMediaConstraints());
  EXPECT_TRUE(result.HasValue());
}

// DeviceID tests.
TEST_P(MediaStreamConstraintsUtilAudioTest, ExactArbitraryDeviceID) {
  const String kArbitraryDeviceID = "arbitrary";
  constraint_factory_.basic().device_id.SetExact(kArbitraryDeviceID);
  auto result = SelectSettings();
  // kArbitraryDeviceID is invalid for device capture, but it is considered
  // valid for content capture. For content capture, validation of device
  // capture is performed by the getUserMedia() implementation.
  if (IsDeviceCapture()) {
    EXPECT_FALSE(result.HasValue());
    EXPECT_EQ(std::string(constraint_factory_.basic().device_id.GetName()),
              std::string(result.failed_constraint_name()));
  } else {
    EXPECT_TRUE(result.HasValue());
    EXPECT_EQ(kArbitraryDeviceID.Utf8(), result.device_id());
    CheckBoolDefaults(AudioSettingsBoolMembers(), AudioPropertiesBoolMembers(),
                      result);
    CheckEchoCancellationTypeDefault(result);
  }
}

// DeviceID tests check various ways to deal with the device_id constraint.
TEST_P(MediaStreamConstraintsUtilAudioTest, IdealArbitraryDeviceID) {
  const String kArbitraryDeviceID = "arbitrary";
  constraint_factory_.basic().device_id.SetIdeal(kArbitraryDeviceID);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  // kArbitraryDeviceID is invalid for device capture, but it is considered
  // valid for content capture. For content capture, validation of device
  // capture is performed by the getUserMedia() implementation.
  if (IsDeviceCapture())
    CheckDeviceDefaults(result);
  else
    EXPECT_EQ(kArbitraryDeviceID.Utf8(), result.device_id());
  CheckProcessingType(result);
  CheckBoolDefaults(AudioSettingsBoolMembers(), AudioPropertiesBoolMembers(),
                    result);
  CheckEchoCancellationTypeDefault(result);
}

TEST_P(MediaStreamConstraintsUtilAudioTest, ExactValidDeviceID) {
  for (const auto& device : capabilities_) {
    constraint_factory_.basic().device_id.SetExact(device.DeviceID());
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    CheckDevice(device, result);
    CheckProcessingType(result);
    CheckBoolDefaults(AudioSettingsBoolMembers(), AudioPropertiesBoolMembers(),
                      result);
    EchoCancellationType expected_echo_cancellation_type =
        EchoCancellationType::kEchoCancellationDisabled;
    if (IsDeviceCapture()) {
      const bool has_system_echo_cancellation =
          device.Parameters().effects() &
          media::AudioParameters::ECHO_CANCELLER;
      expected_echo_cancellation_type =
          has_system_echo_cancellation
              ? EchoCancellationType::kEchoCancellationSystem
              : EchoCancellationType::kEchoCancellationAec3;
    }
    EXPECT_EQ(expected_echo_cancellation_type,
              result.audio_processing_properties().echo_cancellation_type);
  }
}

TEST_P(MediaStreamConstraintsUtilAudioTest, ExactGroupID) {
  for (const auto& device : capabilities_) {
    constraint_factory_.basic().group_id.SetExact(device.GroupID());
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());
    CheckDevice(device, result);
    CheckProcessingType(result);
    CheckBoolDefaults(AudioSettingsBoolMembers(), AudioPropertiesBoolMembers(),
                      result);
    EchoCancellationType expected_echo_cancellation_type =
        EchoCancellationType::kEchoCancellationDisabled;
    if (IsDeviceCapture()) {
      const bool has_system_echo_cancellation =
          device.Parameters().effects() &
          media::AudioParameters::ECHO_CANCELLER;
      expected_echo_cancellation_type =
          has_system_echo_cancellation
              ? EchoCancellationType::kEchoCancellationSystem
              : EchoCancellationType::kEchoCancellationAec3;
    }
    EXPECT_EQ(expected_echo_cancellation_type,
              result.audio_processing_properties().echo_cancellation_type);
  }
}

// Tests the echoCancellation constraint with a device without system echo
// cancellation.
TEST_P(MediaStreamConstraintsUtilAudioTest, EchoCancellationWithWebRtc) {
  for (auto set_function : kBoolSetFunctions) {
    for (auto accessor : kFactoryAccessors) {
      // Ideal advanced is ignored by the SelectSettings algorithm.
      // Using array elements instead of pointer values due to the comparison
      // failing on some build configurations.
      if (set_function == kBoolSetFunctions[1] &&
          accessor == kFactoryAccessors[1]) {
        continue;
      }
      for (bool value : kBoolValues) {
        ResetFactory();
        ((constraint_factory_.*accessor)().echo_cancellation.*
         set_function)(value);
        auto result = SelectSettings();
        EXPECT_TRUE(result.HasValue());
        const AudioProcessingProperties& properties =
            result.audio_processing_properties();
        // With device capture, the echo_cancellation constraint
        // enables/disables all audio processing by default.
        // With content capture, the echo_cancellation constraint controls
        // only the echo_cancellation properties. The other audio processing
        // properties default to false.
        const EchoCancellationType expected_echo_cancellation_type =
            value ? EchoCancellationType::kEchoCancellationAec3
                  : EchoCancellationType::kEchoCancellationDisabled;
        EXPECT_EQ(expected_echo_cancellation_type,
                  properties.echo_cancellation_type);
        const bool enable_webrtc_audio_processing =
            IsDeviceCapture() ? value : false;
        EXPECT_EQ(enable_webrtc_audio_processing, properties.auto_gain_control);
        EXPECT_EQ(enable_webrtc_audio_processing, properties.noise_suppression);

        // The following are not audio processing.
        EXPECT_EQ(GetMediaStreamSource() != blink::kMediaStreamSourceDesktop,
                  result.disable_local_echo());
        EXPECT_FALSE(result.render_to_associated_sink());
        CheckProcessingType(result);
        if (IsDeviceCapture()) {
          CheckDevice(*default_device_, result);
        } else {
          EXPECT_TRUE(result.device_id().empty());
        }
      }
    }
  }
}

// Tests the echoCancellation constraint with a device with system echo
// cancellation.
TEST_P(MediaStreamConstraintsUtilAudioTest, EchoCancellationWithSystem) {
  // With content capture, there is no system echo cancellation, so
  // nothing to test.
  if (!IsDeviceCapture())
    return;

  for (auto set_function : kBoolSetFunctions) {
    for (auto accessor : kFactoryAccessors) {
      // Ideal advanced is ignored by the SelectSettings algorithm.
      // Using array elements instead of pointer values due to the comparison
      // failing on some build configurations.
      if (set_function == kBoolSetFunctions[1] &&
          accessor == kFactoryAccessors[1]) {
        continue;
      }
      for (bool value : kBoolValues) {
        ResetFactory();
        constraint_factory_.basic().device_id.SetExact(
            system_echo_canceller_device_->DeviceID());
        ((constraint_factory_.*accessor)().echo_cancellation.*
         set_function)(value);
        auto result = SelectSettings();
        EXPECT_TRUE(result.HasValue());
        const AudioProcessingProperties& properties =
            result.audio_processing_properties();
        // With system echo cancellation, the echo_cancellation constraint
        // enables/disables all audio processing by default, WebRTC echo
        // cancellation is always disabled, and system echo cancellation is
        // disabled if the echo_cancellation constraint is false.
        const EchoCancellationType expected_echo_cancellation_type =
            value ? EchoCancellationType::kEchoCancellationSystem
                  : EchoCancellationType::kEchoCancellationDisabled;
        EXPECT_EQ(expected_echo_cancellation_type,
                  properties.echo_cancellation_type);
        EXPECT_EQ(value, properties.auto_gain_control);
        EXPECT_EQ(value, properties.noise_suppression);

        // The following are not audio processing.
        EXPECT_EQ(GetMediaStreamSource() != blink::kMediaStreamSourceDesktop,
                  result.disable_local_echo());
        EXPECT_FALSE(result.render_to_associated_sink());
        CheckProcessingType(result);
        CheckDevice(*system_echo_canceller_device_, result);
      }
    }
  }
}

// Tests that individual boolean audio-processing constraints override the
// default value set by the echoCancellation constraint.
TEST_P(MediaStreamConstraintsUtilAudioTest,
       EchoCancellationAndSingleBoolConstraint) {
  const WTF::Vector<blink::BooleanConstraint MediaTrackConstraintSetPlatform::*>
      kAudioProcessingConstraints = {
          &MediaTrackConstraintSetPlatform::auto_gain_control,
          &MediaTrackConstraintSetPlatform::noise_suppression,
      };

  ASSERT_EQ(GetAudioProcessingProperties().size(),
            kAudioProcessingConstraints.size());
  for (auto set_function : kBoolSetFunctions) {
    for (auto accessor : kFactoryAccessors) {
      // Ideal advanced is ignored by the SelectSettings algorithm.
      // Using array elements instead of pointer values due to the comparison
      // failing on some build configurations.
      if (set_function == kBoolSetFunctions[1] &&
          accessor == kFactoryAccessors[1]) {
        continue;
      }
      for (WTF::wtf_size_t i = 0; i < GetAudioProcessingProperties().size();
           ++i) {
        ResetFactory();
        ((constraint_factory_.*accessor)().echo_cancellation.*
         set_function)(false);
        (((constraint_factory_.*accessor)().*kAudioProcessingConstraints[i]).*
         set_function)(true);
        auto result = SelectSettings();
        EXPECT_TRUE(result.HasValue());
        CheckProcessingType(result);
        EXPECT_EQ(EchoCancellationType::kEchoCancellationDisabled,
                  result.audio_processing_properties().echo_cancellation_type);
        EXPECT_TRUE(result.audio_processing_properties().*
                    GetAudioProcessingProperties()[i]);
        for (WTF::wtf_size_t j = 0; j < GetAudioProcessingProperties().size();
             ++j) {
          if (i == j)
            continue;
          EXPECT_FALSE(result.audio_processing_properties().*
                       GetAudioProcessingProperties()[j]);
        }
      }
    }
  }
}

TEST_P(MediaStreamConstraintsUtilAudioTest,
       ReconfigurationSystemEchoCancellation) {
  // This test is relevant only for device capture, where HW EC can be found.
  if (!IsDeviceCapture())
    return;

  // Create a capability that is based on a already opened source with system
  // echo cancellation enabled.
  AudioProcessingProperties properties;
  properties.echo_cancellation_type =
      EchoCancellationType::kEchoCancellationSystem;
  std::unique_ptr<ProcessedLocalAudioSource> system_echo_canceller_source =
      GetProcessedLocalAudioSource(
          properties, false /* disable_local_echo */,
          false /* render_to_associated_sink */,
          media::AudioParameters::PlatformEffectsMask::ECHO_CANCELLER,
          1 /* num_requested_channels */);
  AudioDeviceCaptureCapabilities capabilities = {
      AudioDeviceCaptureCapability(system_echo_canceller_source.get())};
  AudioDeviceCaptureCapability* system_echo_canceller_with_source =
      &capabilities[0];

  constraint_factory_.Reset();
  constraint_factory_.basic().device_id.SetExact(
      system_echo_canceller_with_source->DeviceID());
  constraint_factory_.basic().echo_cancellation.SetExact(true);
  auto result = SelectSettings(true, capabilities);
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.Reset();
  constraint_factory_.basic().device_id.SetExact(
      system_echo_canceller_with_source->DeviceID());
  constraint_factory_.basic().echo_cancellation.SetExact(false);
  result = SelectSettings(true, capabilities);
#if BUILDFLAG(IS_CHROMEOS)
  // ChromeOS supports reopening a device with a different system AEC setting.
  EXPECT_TRUE(result.HasValue());
#else
  EXPECT_FALSE(result.HasValue());
#endif
}

TEST_P(MediaStreamConstraintsUtilAudioTest, VoiceIsolationControl) {
  constraint_factory_.Reset();
  constraint_factory_.basic().voice_isolation.SetExact(true);
  AudioCaptureSettings settings = SelectSettings(true, capabilities_);
  EXPECT_TRUE(settings.HasValue());
  EXPECT_EQ(
      settings.audio_processing_properties().voice_isolation,
      AudioProcessingProperties::VoiceIsolationType::kVoiceIsolationEnabled);

  constraint_factory_.Reset();
  constraint_factory_.basic().voice_isolation.SetExact(false);
  settings = SelectSettings(true, capabilities_);
  EXPECT_TRUE(settings.HasValue());
  EXPECT_EQ(
      settings.audio_processing_properties().voice_isolation,
      AudioProcessingProperties::VoiceIsolationType::kVoiceIsolationDisabled);
  constraint_factory_.Reset();
  settings = SelectSettings(true, capabilities_);
  EXPECT_TRUE(settings.HasValue());
  EXPECT_EQ(
      settings.audio_processing_properties().voice_isolation,
      AudioProcessingProperties::VoiceIsolationType::kVoiceIsolationDefault);
}

// Test advanced constraints sets that can be satisfied.
TEST_P(MediaStreamConstraintsUtilAudioTest, AdvancedCompatibleConstraints) {
  constraint_factory_.AddAdvanced().render_to_associated_sink.SetExact(true);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  CheckDeviceDefaults(result);
  CheckProcessingType(result);
  CheckBoolDefaults({&AudioCaptureSettings::render_to_associated_sink}, {},
                    result);
  CheckEchoCancellationTypeDefault(result);
  EXPECT_TRUE(result.render_to_associated_sink());
}

// Test that an advanced constraint set that contradicts a previous constraint
// set is ignored, but that further constraint sets that can be satisfied are
// applied.
TEST_P(MediaStreamConstraintsUtilAudioTest,
       AdvancedConflictingMiddleConstraints) {
  constraint_factory_.AddAdvanced().noise_suppression.SetExact(true);
  auto& advanced2 = constraint_factory_.AddAdvanced();
  advanced2.noise_suppression.SetExact(false);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  CheckProcessingType(result);
  CheckDeviceDefaults(result);
  CheckBoolDefaults({}, {&AudioProcessingProperties::noise_suppression},
                    result);
  CheckEchoCancellationTypeDefault(result);
  EXPECT_TRUE(result.audio_processing_properties().noise_suppression);
}

// Test that an advanced constraint set that contradicts a previous constraint
// set with a boolean constraint is ignored.
TEST_P(MediaStreamConstraintsUtilAudioTest, AdvancedConflictingLastConstraint) {
  constraint_factory_.AddAdvanced().noise_suppression.SetExact(true);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  CheckProcessingType(result);
  CheckDeviceDefaults(result);
  CheckBoolDefaults({}, {&AudioProcessingProperties::noise_suppression},
                    result);
  CheckEchoCancellationTypeDefault(result);
  // The fourth advanced set is ignored because it contradicts the second set.
  EXPECT_TRUE(result.audio_processing_properties().noise_suppression);
}

// NoDevices tests verify that the case with no devices is handled correctly.
TEST_P(MediaStreamConstraintsUtilAudioTest, NoDevicesNoConstraints) {
  // This test makes sense only for device capture.
  if (!IsDeviceCapture())
    return;

  AudioDeviceCaptureCapabilities capabilities;
  auto result = SelectSettingsAudioCapture(
      capabilities, constraint_factory_.CreateMediaConstraints(),
      GetMediaStreamType(), false);
  EXPECT_FALSE(result.HasValue());
  EXPECT_TRUE(std::string(result.failed_constraint_name()).empty());
}

TEST_P(MediaStreamConstraintsUtilAudioTest, NoDevicesWithConstraints) {
  // This test makes sense only for device capture.
  if (!IsDeviceCapture())
    return;

  AudioDeviceCaptureCapabilities capabilities;
  constraint_factory_.basic().sample_size.SetExact(16);
  auto result = SelectSettingsAudioCapture(
      capabilities, constraint_factory_.CreateMediaConstraints(),
      GetMediaStreamType(), false);
  EXPECT_FALSE(result.HasValue());
  EXPECT_TRUE(std::string(result.failed_constraint_name()).empty());
}

// Test functionality to support applyConstraints() for tracks attached to
// sources that have no audio processing.
TEST_P(MediaStreamConstraintsUtilAudioTest, SourceWithNoAudioProcessing) {
  for (bool enable_properties : {true, false}) {
    std::unique_ptr<blink::LocalMediaStreamAudioSource> source =
        GetLocalMediaStreamAudioSource(
            enable_properties /* enable_system_echo_canceller */,
            enable_properties /* disable_local_echo */,
            enable_properties /* render_to_associated_sink */);

    // These constraints are false in |source|.
    const WTF::Vector<
        blink::BooleanConstraint MediaTrackConstraintSetPlatform::*>
        kConstraints = {
            &MediaTrackConstraintSetPlatform::echo_cancellation,
            &MediaTrackConstraintSetPlatform::disable_local_echo,
            &MediaTrackConstraintSetPlatform::render_to_associated_sink,
        };

    for (WTF::wtf_size_t i = 0; i < kConstraints.size(); ++i) {
      constraint_factory_.Reset();
      (constraint_factory_.basic().*kConstraints[i])
          .SetExact(enable_properties);
      auto result = SelectSettingsAudioCapture(
          source.get(), constraint_factory_.CreateMediaConstraints());
      EXPECT_TRUE(result.HasValue());

      constraint_factory_.Reset();
      (constraint_factory_.basic().*kConstraints[i])
          .SetExact(!enable_properties);
      result = SelectSettingsAudioCapture(
          source.get(), constraint_factory_.CreateMediaConstraints());
      EXPECT_FALSE(result.HasValue());

      // Setting just ideal values should always succeed.
      constraint_factory_.Reset();
      (constraint_factory_.basic().*kConstraints[i]).SetIdeal(true);
      result = SelectSettingsAudioCapture(
          source.get(), constraint_factory_.CreateMediaConstraints());
      EXPECT_TRUE(result.HasValue());

      constraint_factory_.Reset();
      (constraint_factory_.basic().*kConstraints[i]).SetIdeal(false);
      result = SelectSettingsAudioCapture(
          source.get(), constraint_factory_.CreateMediaConstraints());
      EXPECT_TRUE(result.HasValue());
    }
  }
}

// Test functionality to support applyConstraints() for tracks attached to
// sources that have audio processing.
TEST_P(MediaStreamConstraintsUtilAudioTest, SourceWithAudioProcessing) {
  // Processed audio sources are supported only for device capture.
  if (!IsDeviceCapture())
    return;

  for (bool use_defaults : {true, false}) {
    AudioProcessingProperties properties;
    if (!use_defaults) {
      properties.echo_cancellation_type =
          EchoCancellationType::kEchoCancellationDisabled;
      properties.auto_gain_control = !properties.auto_gain_control;
      properties.noise_suppression = !properties.noise_suppression;
    }

    std::unique_ptr<ProcessedLocalAudioSource> source =
        GetProcessedLocalAudioSource(
            properties, use_defaults /* disable_local_echo */,
            use_defaults /* render_to_associated_sink */);
    const WTF::Vector<
        blink::BooleanConstraint MediaTrackConstraintSetPlatform::*>
        kAudioProcessingConstraints = {
            &MediaTrackConstraintSetPlatform::auto_gain_control,
            &MediaTrackConstraintSetPlatform::noise_suppression,
        };
    ASSERT_EQ(kAudioProcessingConstraints.size(),
              GetAudioProcessingProperties().size());

    for (WTF::wtf_size_t i = 0; i < kAudioProcessingConstraints.size(); ++i) {
      constraint_factory_.Reset();
      (constraint_factory_.basic().*kAudioProcessingConstraints[i])
          .SetExact(properties.*GetAudioProcessingProperties()[i]);
      auto result = SelectSettingsAudioCapture(
          source.get(), constraint_factory_.CreateMediaConstraints());
      EXPECT_TRUE(result.HasValue());

      constraint_factory_.Reset();
      (constraint_factory_.basic().*kAudioProcessingConstraints[i])
          .SetExact(!(properties.*GetAudioProcessingProperties()[i]));
      result = SelectSettingsAudioCapture(
          source.get(), constraint_factory_.CreateMediaConstraints());
      EXPECT_FALSE(result.HasValue());

      // Setting just ideal values should always succeed.
      constraint_factory_.Reset();
      (constraint_factory_.basic().*kAudioProcessingConstraints[i])
          .SetIdeal(true);
      result = SelectSettingsAudioCapture(
          source.get(), constraint_factory_.CreateMediaConstraints());
      EXPECT_TRUE(result.HasValue());

      const
```