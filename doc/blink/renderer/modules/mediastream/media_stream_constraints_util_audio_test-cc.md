Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine.
Specifically, it's a test file (`media_stream_constraints_util_audio_test.cc`) located in the `blink/renderer/modules/mediastream` directory.

I need to:
1. **List the functionalities** of the code. Based on the file name and content, it's clearly involved in testing the logic for applying audio constraints in the context of media streams.
2. **Explain its relation to JavaScript, HTML, and CSS**, providing examples if any exist. Since it's a *test* file, its direct interaction with these web technologies is likely indirect, focusing on validating the underlying C++ logic that *supports* the Web APIs.
3. **Provide examples of logical reasoning** with hypothetical inputs and outputs. This will involve imagining different constraint scenarios and how the code might evaluate them.
4. **Illustrate common user or programming errors** that this test helps to catch. This will involve thinking about incorrect constraint specifications or misunderstandings of how audio constraints work.
5. **Describe the user interaction** leading to this code execution as a debugging clue. This will involve tracing back the user's actions in a web page that triggers the media stream processing.
6. **Summarize the functionality** of the code based on the provided first part.

**Mental Sandbox:**

* **Functionality:** The code defines test cases to verify the `SelectSettingsAudioCapture` function (and potentially related functions) which determines the best audio capture settings based on user-defined constraints. It tests various combinations of constraints like `channelCount`, `sampleRate`, `echoCancellation`, `deviceId`, etc.
* **Relation to Web Technologies:**  When a website uses the `getUserMedia` API in JavaScript to request audio access, the browser's underlying C++ engine (Blink) uses logic similar to what's being tested here to translate those JavaScript constraints into concrete audio device settings.
* **Logical Reasoning:** If a JavaScript constraint specifies `echoCancellation: true` and the available device supports it, the test should verify that `SelectSettingsAudioCapture` returns settings with echo cancellation enabled.
* **User Errors:** A user might provide conflicting constraints (e.g., requesting a sample rate not supported by the device). These tests ensure the system handles such errors gracefully.
* **User Interaction:** A user clicks a "Start Recording" button on a webpage that calls `navigator.mediaDevices.getUserMedia({ audio: { channelCount: 2 } })`. This triggers the browser's audio capture logic, which involves the C++ code being tested.
* **Summary:** This test file validates the C++ logic in Blink responsible for selecting appropriate audio capture settings based on user-provided constraints, ensuring that the `getUserMedia` API behaves as expected.

Strategizing complete. I will now proceed with generating the response based on these insights.
这个C++源代码文件 `media_stream_constraints_util_audio_test.cc` 的主要功能是：

**对 Blink 引擎中用于处理音频媒体流约束的工具函数 `SelectSettingsAudioCapture` 和 `SelectEligibleSettingsAudioCapture` 进行单元测试。**

具体来说，它通过编写一系列的测试用例来验证以下功能：

* **基本的约束选择:** 测试在没有约束或只有基本约束的情况下，系统如何选择默认的音频捕获设置。
* **布尔类型约束:** 测试如何应用和解析布尔类型的约束，例如 `disableLocalEcho`, `renderToAssociatedSink`, `autoGainControl`, `noiseSuppression` 等，包括 `exact` 和 `ideal` 两种匹配模式。
* **数值类型约束:** 测试如何应用和解析数值类型的约束，例如 `sampleSize`, `channelCount`, `latency`，包括 `exact`, `min`, `max`, 和 `ideal` 等匹配模式。
* **字符串类型约束:** 测试如何应用和解析字符串类型的约束，例如 `deviceId` 和 `echoCancellationType`，包括 `exact` 和 `ideal` 匹配模式以及使用枚举值。
* **组合约束:** 测试当同时存在多个约束时，系统如何选择合适的音频捕获设置。
* **设备特定约束:** 测试如何根据不同的音频设备能力来选择合适的设置。
* **内容捕获约束:** 测试针对不同类型的媒体流源（例如，设备麦克风、Tab 捕获、桌面捕获）约束选择的不同行为。
* **回声消除约束:** 测试不同类型的回声消除约束 (例如 `browser`, `aec3`, `system`) 的选择逻辑。
* **实验性特性测试:**  测试在开启或关闭某些实验性特性时，约束选择的行为是否符合预期。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 测试文件本身不直接包含 JavaScript, HTML, 或 CSS 代码，但它测试的 C++ 代码是 Blink 引擎的一部分，Blink 引擎负责渲染网页并执行 JavaScript 代码。这个测试文件验证的音频约束处理逻辑与以下 Web API 密切相关：

* **`getUserMedia()` (JavaScript):**  当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: constraints })` 时，`constraints` 对象中指定的音频约束会被传递到 Blink 引擎。`SelectSettingsAudioCapture` 和 `SelectEligibleSettingsAudioCapture` 这两个函数就是用来解析和应用这些约束，最终确定用于捕获音频流的硬件和软件设置。

   **举例说明:**

   ```javascript
   navigator.mediaDevices.getUserMedia({
       audio: {
           sampleRate: { exact: 48000 },
           channelCount: { min: 2 }
       }
   })
   .then(function(stream) {
       // 使用音频流
   })
   .catch(function(err) {
       console.error("无法获取音频流", err);
   });
   ```

   在这个 JavaScript 例子中，`sampleRate` 和 `channelCount` 是音频约束。`media_stream_constraints_util_audio_test.cc` 中的测试用例会模拟这些 JavaScript 约束，并验证 Blink 引擎的 C++ 代码是否能够正确地根据这些约束选择合适的音频设备和参数。

* **HTML `<audio>` 元素 (间接关系):** 虽然 `getUserMedia` 返回的音频流可以直接用于 `<audio>` 元素播放，但这个测试文件本身不直接操作 HTML 元素。它关注的是媒体流的 *获取* 阶段，而不是播放阶段。

* **CSS (无直接关系):** CSS 主要负责网页的样式，与音频约束的处理逻辑没有直接关系。

**逻辑推理示例 (假设输入与输出):**

**假设输入:**

* **音频设备能力:**  存在两个麦克风设备：
    * 设备 A：立体声，采样率 44100 Hz，支持回声消除。
    * 设备 B：单声道，采样率 48000 Hz，不支持回声消除。
* **JavaScript 约束:**
  ```javascript
  {
      audio: {
          channelCount: { exact: 1 },
          echoCancellation: true
      }
  }
  ```

**逻辑推理:**

`SelectSettingsAudioCapture` 函数会根据提供的约束和设备能力进行匹配。

1. **`channelCount: { exact: 1 }`:**  要求单声道音频。设备 A 是立体声，不完全匹配。设备 B 是单声道，匹配。
2. **`echoCancellation: true`:** 要求启用回声消除。设备 A 支持回声消除，匹配。设备 B 不支持回声消除，不匹配。

**输出:**

在这种情况下，最合适的输出是 **设备 A**。虽然设备 A 是立体声，但约束中只要求单声道，Blink 引擎可能会选择设备 A 并进行声道降混。设备 B 因为不支持回声消除，与约束不符。

**常见的使用错误 (用户或编程):**

* **约束冲突:** 用户或开发者可能会设置相互冲突的约束，例如要求一个特定的采样率，但连接的设备不支持该采样率。测试用例会验证在这种情况下，系统是否能正确处理并可能返回错误。
  * **例子:**  JavaScript 代码请求 `{ audio: { sampleRate: { exact: 96000 } } }`，但用户的麦克风只支持 44100 Hz 和 48000 Hz。测试会验证 `SelectSettingsAudioCapture` 是否会返回空或者选择最接近的有效值。
* **误解 `exact` 和 `ideal` 的区别:**  开发者可能错误地使用了 `exact` 约束，导致即使存在更好的匹配设备也无法被选中。
  * **例子:**  用户希望使用高音质麦克风，设置了 `{ audio: { sampleRate: { exact: 48000 } } }`。如果当前连接的麦克风只支持 44100 Hz，则会匹配失败，即使可能存在一个支持更高采样率的麦克风但其采样率不是精确的 48000 Hz。测试会验证 `ideal` 约束是否能更好地处理这种情况。
* **忽略设备能力:** 开发者可能设置了设备不支持的约束，例如要求特定的音频处理特性，但硬件不支持。
  * **例子:**  请求 `{ audio: { echoCancellation: true } }`，但在没有回声消除硬件或软件支持的环境下运行。测试会验证系统是否能优雅地处理这种情况，或者选择不启用回声消除并通知用户。

**用户操作到达此处的调试线索:**

以下步骤描述了用户操作如何一步步触发到 `media_stream_constraints_util_audio_test.cc` 中代码的执行（作为开发或测试的一部分）：

1. **用户访问一个网页:** 用户在 Chromium 浏览器中打开一个需要访问麦克风的网页，例如一个在线会议应用、语音录制网站等。
2. **网页请求麦克风权限:** 网页上的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: audioConstraints })`，其中 `audioConstraints` 包含了对音频流的各种约束，例如采样率、声道数、回声消除等。
3. **Blink 引擎处理请求:** Chromium 浏览器的 Blink 渲染引擎接收到这个 `getUserMedia` 请求和相关的音频约束。
4. **约束解析和设备选择:**  Blink 引擎内部的媒体栈会调用类似于 `SelectSettingsAudioCapture` 的 C++ 函数，并传入用户指定的 `audioConstraints` 和当前系统可用的音频设备信息。
5. **执行测试用例 (开发/测试阶段):**  在 Chromium 的开发或测试阶段，开发者或自动化测试脚本会运行 `media_stream_constraints_util_audio_test.cc` 中的测试用例。这些测试用例会模拟各种可能的 `audioConstraints` 和设备配置，以验证 `SelectSettingsAudioCapture` 函数的逻辑是否正确。
6. **验证结果:** 测试框架会比较 `SelectSettingsAudioCapture` 函数的输出结果与预期的结果，以判断约束处理逻辑是否存在错误。如果测试失败，则表明 `SelectSettingsAudioCapture` 的实现可能存在 bug，需要修复。

**功能归纳 (第1部分):**

这个 C++ 代码文件的主要功能是**作为 Blink 引擎中音频媒体流约束处理逻辑的单元测试套件**。它通过定义各种测试用例，验证 `SelectSettingsAudioCapture` 等关键函数在接收到不同的音频约束时，是否能够正确地选择合适的音频捕获设置，并涵盖了基本的约束类型、组合约束、设备特定约束以及内容捕获等多种场景。这确保了当网页通过 JavaScript 的 `getUserMedia` API 请求音频访问时，Blink 引擎能够按照规范和用户的意愿选择最佳的音频配置。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_audio_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_audio.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <string>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/test/scoped_feature_list.h"
#include "base/types/optional_util.h"
#include "build/build_config.h"
#include "media/base/audio_parameters.h"
#include "media/base/media_switches.h"
#include "media/media_buildflags.h"
#include "media/webrtc/constants.h"
#include "media/webrtc/webrtc_features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink-forward.h"
#include "third_party/blink/public/platform/modules/mediastream/web_platform_media_stream_source.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/modules/mediastream/local_media_stream_audio_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/modules/mediastream/processed_local_audio_source.h"
#include "third_party/blink/renderer/modules/webrtc/webrtc_audio_device_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"

namespace blink {

using blink::AudioCaptureSettings;
using blink::AudioProcessingProperties;
using EchoCancellationType = AudioProcessingProperties::EchoCancellationType;
using ProcessingType = AudioCaptureSettings::ProcessingType;

namespace {

using BoolSetFunction = void (blink::BooleanConstraint::*)(bool);
using StringSetFunction =
    void (blink::StringConstraint::*)(const blink::WebString&);
using MockFactoryAccessor =
    MediaTrackConstraintSetPlatform& (blink::MockConstraintFactory::*)();

const BoolSetFunction kBoolSetFunctions[] = {
    &blink::BooleanConstraint::SetExact,
    &blink::BooleanConstraint::SetIdeal,
};

const MockFactoryAccessor kFactoryAccessors[] = {
    &blink::MockConstraintFactory::basic,
    &blink::MockConstraintFactory::AddAdvanced};

const bool kBoolValues[] = {true, false};

const int kMinChannels = 1;

using AudioSettingsBoolMembers =
    WTF::Vector<bool (AudioCaptureSettings::*)() const>;
using AudioPropertiesBoolMembers =
    WTF::Vector<bool AudioProcessingProperties::*>;

template <typename T>
static bool Contains(const WTF::Vector<T>& vector, T value) {
  return base::Contains(vector, value);
}

}  // namespace

class MediaStreamConstraintsUtilAudioTestBase : public SimTest {
 protected:
  void SetMediaStreamSource(const std::string& source) {}

  void ResetFactory() {
    constraint_factory_.Reset();
    constraint_factory_.basic().media_stream_source.SetExact(
        String::FromUTF8(GetMediaStreamSource()));
  }

  // If not overridden, this function will return device capture by default.
  virtual std::string GetMediaStreamSource() { return std::string(); }
  bool IsDeviceCapture() { return GetMediaStreamSource().empty(); }
  static AudioPropertiesBoolMembers GetAudioProcessingProperties() {
    return {&AudioProcessingProperties::auto_gain_control,
            &AudioProcessingProperties::noise_suppression};
  }

  blink::mojom::MediaStreamType GetMediaStreamType() {
    std::string media_source = GetMediaStreamSource();
    if (media_source.empty())
      return blink::mojom::MediaStreamType::DEVICE_AUDIO_CAPTURE;
    else if (media_source == blink::kMediaStreamSourceTab)
      return blink::mojom::MediaStreamType::GUM_TAB_AUDIO_CAPTURE;
    return blink::mojom::MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE;
  }

  std::unique_ptr<ProcessedLocalAudioSource> GetProcessedLocalAudioSource(
      const AudioProcessingProperties& properties,
      bool disable_local_echo,
      bool render_to_associated_sink,
      int effects,
      int num_requested_channels) {
    blink::MediaStreamDevice device;
    device.id = "processed_source";
    device.type = GetMediaStreamType();
    if (render_to_associated_sink)
      device.matched_output_device_id = std::string("some_device_id");
    device.input.set_effects(effects);

    return std::make_unique<ProcessedLocalAudioSource>(
        *MainFrame().GetFrame(), device, disable_local_echo, properties,
        num_requested_channels, base::NullCallback(),
        blink::scheduler::GetSingleThreadTaskRunnerForTesting());
  }

  std::unique_ptr<ProcessedLocalAudioSource> GetProcessedLocalAudioSource(
      const AudioProcessingProperties& properties,
      bool disable_local_echo,
      bool render_to_associated_sink) {
    return GetProcessedLocalAudioSource(
        properties, disable_local_echo, render_to_associated_sink,
        media::AudioParameters::PlatformEffectsMask::NO_EFFECTS,
        1 /* num_requested_channels */);
  }

  std::unique_ptr<blink::LocalMediaStreamAudioSource>
  GetLocalMediaStreamAudioSource(
      bool enable_system_echo_canceller,
      bool disable_local_echo,
      bool render_to_associated_sink,
      const int* requested_buffer_size = nullptr) {
    blink::MediaStreamDevice device;
    device.type = GetMediaStreamType();

    int effects = 0;
    if (enable_system_echo_canceller)
      effects |= media::AudioParameters::ECHO_CANCELLER;
    device.input.set_effects(effects);

    if (render_to_associated_sink)
      device.matched_output_device_id = std::string("some_device_id");

    return std::make_unique<blink::LocalMediaStreamAudioSource>(
        /*blink::WebLocalFrame=*/nullptr, device, requested_buffer_size,
        /*disable_local_echo=*/disable_local_echo,
        /*enable_system_echo_canceller=*/enable_system_echo_canceller,
        blink::WebPlatformMediaStreamSource::ConstraintsRepeatingCallback(),
        blink::scheduler::GetSingleThreadTaskRunnerForTesting());
  }

  AudioCaptureSettings SelectSettings(
      bool is_reconfigurable = false,
      std::optional<AudioDeviceCaptureCapabilities> capabilities =
          std::nullopt) {
    MediaConstraints constraints = constraint_factory_.CreateMediaConstraints();
    if (capabilities) {
      return SelectSettingsAudioCapture(*capabilities, constraints,
                                        GetMediaStreamType(), false,
                                        is_reconfigurable);
    } else {
      return SelectSettingsAudioCapture(capabilities_, constraints,
                                        GetMediaStreamType(), false,
                                        is_reconfigurable);
    }
  }

  base::expected<Vector<blink::AudioCaptureSettings>, std::string>
  SelectEligibleSettings(bool is_reconfigurable = false) {
    MediaConstraints constraints = constraint_factory_.CreateMediaConstraints();
    return SelectEligibleSettingsAudioCapture(
        capabilities_, constraints, GetMediaStreamType(),
        /*should_disable_hardware_noise_suppression=*/false, is_reconfigurable);
  }

  void CheckBoolDefaultsDeviceCapture(
      const AudioSettingsBoolMembers& exclude_main_settings,
      const AudioPropertiesBoolMembers& exclude_audio_properties,
      const AudioCaptureSettings& result) {
    if (!Contains(exclude_main_settings,
                  &AudioCaptureSettings::disable_local_echo)) {
      EXPECT_TRUE(result.disable_local_echo());
    }
    if (!Contains(exclude_main_settings,
                  &AudioCaptureSettings::render_to_associated_sink)) {
      EXPECT_FALSE(result.render_to_associated_sink());
    }

    const auto& properties = result.audio_processing_properties();
    if (!Contains(exclude_audio_properties,
                  &AudioProcessingProperties::auto_gain_control)) {
      EXPECT_TRUE(properties.auto_gain_control);
    }
    if (!Contains(exclude_audio_properties,
                  &AudioProcessingProperties::noise_suppression)) {
      EXPECT_TRUE(properties.noise_suppression);
    }
  }

  void CheckBoolDefaultsContentCapture(
      const AudioSettingsBoolMembers& exclude_main_settings,
      const AudioPropertiesBoolMembers& exclude_audio_properties,
      const AudioCaptureSettings& result) {
    if (!Contains(exclude_main_settings,
                  &AudioCaptureSettings::disable_local_echo)) {
      EXPECT_EQ(GetMediaStreamSource() != blink::kMediaStreamSourceDesktop,
                result.disable_local_echo());
    }
    if (!Contains(exclude_main_settings,
                  &AudioCaptureSettings::render_to_associated_sink)) {
      EXPECT_FALSE(result.render_to_associated_sink());
    }

    const auto& properties = result.audio_processing_properties();
    if (!Contains(exclude_audio_properties,
                  &AudioProcessingProperties::auto_gain_control)) {
      EXPECT_FALSE(properties.auto_gain_control);
    }
    if (!Contains(exclude_audio_properties,
                  &AudioProcessingProperties::noise_suppression)) {
      EXPECT_FALSE(properties.noise_suppression);
    }
  }

  void CheckBoolDefaults(
      const AudioSettingsBoolMembers& exclude_main_settings,
      const AudioPropertiesBoolMembers& exclude_audio_properties,
      const AudioCaptureSettings& result) {
    if (IsDeviceCapture()) {
      CheckBoolDefaultsDeviceCapture(exclude_main_settings,
                                     exclude_audio_properties, result);
    } else {
      CheckBoolDefaultsContentCapture(exclude_main_settings,
                                      exclude_audio_properties, result);
    }
  }

  void CheckEchoCancellationTypeDefault(const AudioCaptureSettings& result) {
    const auto& properties = result.audio_processing_properties();
    if (IsDeviceCapture()) {
      EXPECT_EQ(properties.echo_cancellation_type,
                EchoCancellationType::kEchoCancellationAec3);
    } else {
      EXPECT_EQ(properties.echo_cancellation_type,
                EchoCancellationType::kEchoCancellationDisabled);
    }
  }

  void CheckProcessingType(const AudioCaptureSettings& result) {
    ProcessingType expected_type = ProcessingType::kUnprocessed;
    const auto& properties = result.audio_processing_properties();
    bool properties_value = false;
    for (WTF::wtf_size_t i = 0; i < GetAudioProcessingProperties().size();
         ++i) {
      properties_value |= properties.*GetAudioProcessingProperties()[i];
    }

    if (properties_value) {
      expected_type = ProcessingType::kApmProcessed;
    }

    // Finally, if the chosen echo cancellation type is either AEC3 or AEC2, the
    // only possible processing type to expect is kWebRtcProcessed.
    if (properties.echo_cancellation_type ==
        EchoCancellationType::kEchoCancellationAec3) {
      expected_type = ProcessingType::kApmProcessed;
    }
    EXPECT_EQ(result.processing_type(), expected_type);
  }

  void CheckDevice(const AudioDeviceCaptureCapability& expected_device,
                   const AudioCaptureSettings& result) {
    EXPECT_EQ(expected_device.DeviceID().Utf8(), result.device_id());
  }

  void CheckDeviceDefaults(const AudioCaptureSettings& result) {
    if (IsDeviceCapture())
      CheckDevice(*default_device_, result);
    else
      EXPECT_TRUE(result.device_id().empty());
  }

  void CheckAllDefaults(
      const AudioSettingsBoolMembers& exclude_main_settings,
      const AudioPropertiesBoolMembers& exclude_audio_properties,
      const AudioCaptureSettings& result) {
    CheckProcessingType(result);
    CheckBoolDefaults(exclude_main_settings, exclude_audio_properties, result);
    CheckEchoCancellationTypeDefault(result);
    CheckDeviceDefaults(result);
  }

  void CheckAudioProcessingPropertiesForIdealEchoCancellationType(
      const AudioCaptureSettings& result) {
    const AudioProcessingProperties& properties =
        result.audio_processing_properties();

    EXPECT_EQ(EchoCancellationType::kEchoCancellationSystem,
              properties.echo_cancellation_type);
    EXPECT_TRUE(properties.auto_gain_control);
    EXPECT_TRUE(properties.noise_suppression);

    // The following are not audio processing.
    EXPECT_EQ(GetMediaStreamSource() != blink::kMediaStreamSourceDesktop,
              result.disable_local_echo());
    EXPECT_FALSE(result.render_to_associated_sink());
    CheckDevice(*system_echo_canceller_device_, result);
  }

  EchoCancellationType GetEchoCancellationTypeFromConstraintString(
      const blink::WebString& constraint_string) {
    if (constraint_string == kEchoCancellationTypeValues[0])
      return EchoCancellationType::kEchoCancellationAec3;
    if (constraint_string == kEchoCancellationTypeValues[1])
      return EchoCancellationType::kEchoCancellationAec3;
    if (constraint_string == kEchoCancellationTypeValues[2])
      return EchoCancellationType::kEchoCancellationSystem;

    ADD_FAILURE() << "Invalid echo cancellation type constraint: "
                  << constraint_string.Ascii();
    return EchoCancellationType::kEchoCancellationDisabled;
  }

  void CheckLatencyConstraint(const AudioDeviceCaptureCapability* device,
                              double min_latency,
                              double max_latency) {
    constraint_factory_.Reset();
    constraint_factory_.basic().device_id.SetExact(device->DeviceID());
    constraint_factory_.basic().echo_cancellation.SetExact(false);
    constraint_factory_.basic().latency.SetExact(0.0);
    auto result = SelectSettings();
    EXPECT_FALSE(result.HasValue());

    constraint_factory_.Reset();
    constraint_factory_.basic().device_id.SetExact(device->DeviceID());
    constraint_factory_.basic().echo_cancellation.SetExact(false);
    constraint_factory_.basic().latency.SetMin(max_latency + 0.001);
    result = SelectSettings();
    EXPECT_FALSE(result.HasValue());

    constraint_factory_.Reset();
    constraint_factory_.basic().device_id.SetExact(device->DeviceID());
    constraint_factory_.basic().echo_cancellation.SetExact(false);
    constraint_factory_.basic().latency.SetMax(min_latency - 0.001);
    result = SelectSettings();
    EXPECT_FALSE(result.HasValue());

    CheckLocalMediaStreamAudioSourceLatency(
        device, 0.001, min_latency * device->Parameters().sample_rate());
    CheckLocalMediaStreamAudioSourceLatency(
        device, 1.0, max_latency * device->Parameters().sample_rate());
  }

  void CheckLocalMediaStreamAudioSourceLatency(
      const AudioDeviceCaptureCapability* device,
      double requested_latency,
      int expected_buffer_size) {
    constraint_factory_.Reset();
    constraint_factory_.basic().device_id.SetExact(device->DeviceID());
    constraint_factory_.basic().echo_cancellation.SetExact(false);
    constraint_factory_.basic().latency.SetIdeal(requested_latency);
    auto result = SelectSettings();
    EXPECT_TRUE(result.HasValue());

    std::unique_ptr<blink::LocalMediaStreamAudioSource> local_source =
        GetLocalMediaStreamAudioSource(
            false /* enable_system_echo_canceller */,
            false /* disable_local_echo */,
            false /* render_to_associated_sink */,
            base::OptionalToPtr(result.requested_buffer_size()));
    EXPECT_EQ(local_source->GetAudioParameters().frames_per_buffer(),
              expected_buffer_size);
  }

  blink::MockConstraintFactory constraint_factory_;
  AudioDeviceCaptureCapabilities capabilities_;
  raw_ptr<const AudioDeviceCaptureCapability> default_device_ = nullptr;
  raw_ptr<const AudioDeviceCaptureCapability> system_echo_canceller_device_ =
      nullptr;
  raw_ptr<const AudioDeviceCaptureCapability> four_channels_device_ = nullptr;
  raw_ptr<const AudioDeviceCaptureCapability> variable_latency_device_ =
      nullptr;
  std::unique_ptr<ProcessedLocalAudioSource> system_echo_canceller_source_;
  const WTF::Vector<media::Point> kMicPositions = {{8, 8, 8}, {4, 4, 4}};

  // TODO(grunell): Store these as separate constants and compare against those
  // in tests, instead of indexing the vector.
  const WTF::Vector<blink::WebString> kEchoCancellationTypeValues = {
      blink::WebString::FromASCII("browser"),
      blink::WebString::FromASCII("aec3"),
      blink::WebString::FromASCII("system")};

 private:
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport> platform_;
};

class MediaStreamConstraintsUtilAudioTest
    : public MediaStreamConstraintsUtilAudioTestBase,
      public testing::WithParamInterface<std::string> {
 public:
  void SetUp() override {
    MediaStreamConstraintsUtilAudioTestBase::SetUp();
    ResetFactory();
    if (IsDeviceCapture()) {
      capabilities_.emplace_back(
          "default_device", "fake_group1",
          media::AudioParameters(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                 media::ChannelLayoutConfig::Stereo(),
                                 media::AudioParameters::kAudioCDSampleRate,
                                 1000));

      media::AudioParameters system_echo_canceller_parameters(
          media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
          media::ChannelLayoutConfig::Stereo(),
          media::AudioParameters::kAudioCDSampleRate, 1000);
      system_echo_canceller_parameters.set_effects(
          media::AudioParameters::ECHO_CANCELLER);
      capabilities_.emplace_back("system_echo_canceller_device", "fake_group2",
                                 system_echo_canceller_parameters);

      capabilities_.emplace_back(
          "4_channels_device", "fake_group3",
          media::AudioParameters(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                 media::ChannelLayoutConfig::FromLayout<
                                     media::CHANNEL_LAYOUT_4_0>(),
                                 media::AudioParameters::kAudioCDSampleRate,
                                 1000));

      capabilities_.emplace_back(
          "8khz_sample_rate_device", "fake_group4",
          media::AudioParameters(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                                 media::ChannelLayoutConfig::Stereo(),
                                 webrtc::AudioProcessing::kSampleRate8kHz,
                                 1000));

      capabilities_.emplace_back(
          "variable_latency_device", "fake_group5",
          media::AudioParameters(
              media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
              media::ChannelLayoutConfig::Stereo(),
              media::AudioParameters::kAudioCDSampleRate, 512,
              media::AudioParameters::HardwareCapabilities(128, 4096)));

      default_device_ = &capabilities_[0];
      system_echo_canceller_device_ = &capabilities_[1];
      four_channels_device_ = &capabilities_[2];
      variable_latency_device_ = &capabilities_[4];
    } else {
      // For content capture, use a single capability that admits all possible
      // settings.
      capabilities_.emplace_back();
    }
  }

  std::string GetMediaStreamSource() override { return GetParam(); }
};

enum class ChromeWideAecExperiment { kDisabled, kEnabled };

class MediaStreamConstraintsRemoteAPMTest
    : public MediaStreamConstraintsUtilAudioTestBase,
      public testing::WithParamInterface<
          std::tuple<std::string, ChromeWideAecExperiment>> {
 protected:
  std::string GetMediaStreamSource() override {
    return std::get<0>(GetParam());
  }

  ChromeWideAecExperiment GetChromeWideAecExperiment() {
    return std::get<1>(GetParam());
  }

  testing::Message GetMessageForScopedTrace() {
    std::string experiment_string;
    switch (GetChromeWideAecExperiment()) {
      case ChromeWideAecExperiment::kDisabled:
        experiment_string = "disabled";
        break;
      case ChromeWideAecExperiment::kEnabled:
        experiment_string = "enabled";
        break;
    }
    return testing::Message()
           << "GetMediaStreamSource()=\"" << GetMediaStreamSource()
           << "\", GetChromeWideAecExperiment()=" << experiment_string;
  }

  // Indicates where and how audio processing is applied.
  enum class ApmLocation {
    kProcessedLocalAudioSource,
    kAudioService,
    kAudioServiceAvoidResampling
  };

  ApmLocation GetApmLocation() {
    if (GetMediaStreamType() !=
        mojom::blink::MediaStreamType::DEVICE_AUDIO_CAPTURE) {
      // Non-mic input sources cannot run APM in the audio service:
      // https://crbug.com/1328012
      return ApmLocation::kProcessedLocalAudioSource;
    }

    switch (GetChromeWideAecExperiment()) {
      case ChromeWideAecExperiment::kDisabled:
        return ApmLocation::kProcessedLocalAudioSource;
      case ChromeWideAecExperiment::kEnabled:
        return ApmLocation::kAudioService;
    }
    NOTREACHED();
  }

 private:
  void SetUp() override {
    MediaStreamConstraintsUtilAudioTestBase::SetUp();

#if BUILDFLAG(CHROME_WIDE_ECHO_CANCELLATION)
    switch (GetChromeWideAecExperiment()) {
      case ChromeWideAecExperiment::kDisabled:
        scoped_feature_list_.InitAndDisableFeature(
            media::kChromeWideEchoCancellation);
        break;
      case ChromeWideAecExperiment::kEnabled:
        scoped_feature_list_.InitAndEnableFeature(
            media::kChromeWideEchoCancellation);
        break;
    }
#endif

    // Setup the capabilities.
    ResetFactory();
    capabilities_.emplace_back(
        "default_device", "fake_group1",
        media::AudioParameters(media::AudioParameters::AUDIO_PCM_LOW_LATENCY,
                               media::ChannelLayoutConfig::Stereo(),
                               media::AudioParameters::kAudioCDSampleRate,
                               1000));
    default_device_ = &capabilities_[0];
  }

  base::test::ScopedFeatureList scoped_feature_list_;
};

// The Unconstrained test checks the default selection criteria.
TEST_P(MediaStreamConstraintsUtilAudioTest, Unconstrained) {
  auto result = SelectSettings();

  // All settings should have default values.
  EXPECT_TRUE(result.HasValue());
  CheckAllDefaults(AudioSettingsBoolMembers(), AudioPropertiesBoolMembers(),
                   result);
}

// This test checks all possible ways to set boolean constraints (except
// echo cancellation constraints, which are not mapped 1:1 to output audio
// processing properties).
TEST_P(MediaStreamConstraintsUtilAudioTest, SingleBoolConstraint) {
  AudioSettingsBoolMembers kMainSettings = {
      &AudioCaptureSettings::disable_local_echo,
      &AudioCaptureSettings::render_to_associated_sink};

  const WTF::Vector<blink::BooleanConstraint MediaTrackConstraintSetPlatform::*>
      kMainBoolConstraints = {
          &MediaTrackConstraintSetPlatform::disable_local_echo,
          &MediaTrackConstraintSetPlatform::render_to_associated_sink};

  ASSERT_EQ(kMainSettings.size(), kMainBoolConstraints.size());
  for (auto set_function : kBoolSetFunctions) {
    for (auto accessor : kFactoryAccessors) {
      // Ideal advanced is ignored by the SelectSettings algorithm.
      // Using array elements instead of pointer values due to the comparison
      // failing on some build configurations.
      if (set_function == kBoolSetFunctions[1] &&
          accessor == kFactoryAccessors[1]) {
        continue;
      }
      for (WTF::wtf_size_t i = 0; i < kMainSettings.size(); ++i) {
        for (bool value : kBoolValues) {
          ResetFactory();
          (((constraint_factory_.*accessor)().*kMainBoolConstraints[i]).*
           set_function)(value);
          auto result = SelectSettings();
          EXPECT_TRUE(result.HasValue());
          EXPECT_EQ(value, (result.*kMainSettings[i])());
          CheckAllDefaults({kMainSettings[i]}, AudioPropertiesBoolMembers(),
                           result);
        }
      }
    }
  }

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
        for (bool value : kBoolValues) {
          ResetFactory();
          (((constraint_factory_.*accessor)().*kAudioProcessingConstraints[i]).*
           set_function)(value);
          auto result = SelectSettings();
          EXPECT_TRUE(result.HasValue());
          EXPECT_EQ(value, result.audio_processing_properties().*
                               GetAudioProcessingProperties()[i]);
          CheckAllDefaults(AudioSettingsBoolMembers(),
                           {GetAudioProcessingProperties()[i]}, result);
        }
      }
    }
  }
}

TEST_P(MediaStreamConstraintsUtilAudioTest, SampleSize) {
  ResetFactory();
  constraint_factory_.basic().sample_size.SetExact(16);
  auto result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  ResetFactory();
  constraint_factory_.basic().sample_size.SetExact(0);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Only set a min value for the constraint.
  ResetFactory();
  constraint_factory_.basic().sample_size.SetMin(16);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  ResetFactory();
  constraint_factory_.basic().sample_size.SetMin(17);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Only set a max value for the constraint.
  ResetFactory();
  constraint_factory_.basic().sample_size.SetMax(16);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  ResetFactory();
  constraint_factory_.basic().sample_size.SetMax(15);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Define a bounded range for the constraint.
  ResetFactory();
  constraint_factory_.basic().sample_size.SetMin(10);
  constraint_factory_.basic().sample_size.SetMax(20);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  ResetFactory();
  constraint_factory_.basic().sample_size.SetMin(-10);
  constraint_factory_.basic().sample_size.SetMax(10);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  ResetFactory();
  constraint_factory_.basic().sample_size.SetMin(20);
  constraint_factory_.basic().sample_size.SetMax(30);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test ideal constraints.
  ResetFactory();
  constraint_factory_.basic().sample_size.SetIdeal(16);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  ResetFactory();
  constraint_factory_.basic().sample_size.SetIdeal(0);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
}

TEST_P(MediaStreamConstraintsUtilAudioTest, Channels) {
  int channel_count = kMinChannels;
  AudioCaptureSettings result;

  // Test set exact channelCount.
  for (; channel_count <= media::limits::kMaxChannels; ++channel_count) {
    ResetFactory();
    constraint_factory_.basic().channel_count.SetExact(channel_count);
    result = SelectSettings();

    if (!IsDeviceCapture()) {
      // The source capture configured above is actually using a channel count
      // set to 2 channels.
      if (channel_count <= 2)
        EXPECT_TRUE(result.HasValue());
      else
        EXPECT_FALSE(result.HasValue());
      continue;
    }

    if (channel_count == 3 || channel_count > 4) {
      EXPECT_FALSE(result.HasValue());
      continue;
    }

    EXPECT_TRUE(result.HasValue());
    if (channel_count == 4)
      EXPECT_EQ(result.device_id(), "4_channels_device");
    else
      EXPECT_EQ(result.device_id(), "default_device");
  }

  // Only set a min value for the constraint.
  ResetFactory();
  constraint_factory_.basic().channel_count.SetMin(media::limits::kMaxChannels +
                                                   1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  constraint_factory_.basic().channel_count.SetMin(kMinChannels);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  // Only set a max value for the constraint.
  ResetFactory();
  constraint_factory_.basic().channel_count.SetMax(kMinChannels - 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  constraint_factory_.basic().channel_count.SetMax(kMinChannels);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  // Define a bounded range for the constraint.
  ResetFactory();
  constraint_factory_.basic().channel_count.SetMin(kMinChannels);
  constraint_factory_.basic().channel_count.SetMax(media::limits::kMaxChannels);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());

  constraint_factory_.basic().channel_count.SetMin(kMinChannels - 10);
  constraint_factory_.basic().channel_count.SetMax(kMinChannels - 1);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  constraint_factory_.basic().channel_count.SetMin(media::limits::kMaxChannels +
                                                   1);
  constraint_factory_.basic().channel_count.SetMax(media::limits::kMaxChannels +
                                                   10);
  result = SelectSettings();
  EXPECT_FALSE(result.HasValue());

  // Test ideal constraints.
  for (; channel_count <= media::limits::kMaxChannels; ++channel_count) {
    ResetFactory();
    constraint_factory_.basic().channel_count.SetExact(channel_count);
    result = SelectSettings();

    EXPECT_TRUE(result.HasValue());
    if (IsDeviceCapture()) {
      if (channel_count == 4)
        EXPECT_EQ(result.device_id(), "4_channels_device");
      else
        EXPECT_EQ(result.device_id(), "default_device");
    }
  }
}

TEST_P(MediaStreamConstraintsUtilAudioTest, MultiChannelEchoCancellation) {
  if (!IsDeviceCapture())
    return;

  AudioCaptureSettings result;

  ResetFactory();
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(result.device_id(), "default_device");
  // By default, use the default deevice with echo cancellation enabled
  // and 1 channel,
  EXPECT_EQ(result.audio_processing_properties().echo_cancellation_type,
            EchoCancellationType::kEchoCancellationAec3);
  EXPECT_EQ(result.num_channels(), 1);

  ResetFactory();
  constraint_factory_.basic().device_id.SetExact("default_device");
  constraint_factory_.basic().echo_cancellation.SetExact(true);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(result.device_id(), "default_device");
  // By default, use 1 channel, even with a stereo device.
  EXPECT_EQ(result.audio_processing_properties().echo_cancellation_type,
            EchoCancellationType::kEchoCancellationAec3);
  EXPECT_EQ(result.num_channels(), 1);

  ResetFactory();
  constraint_factory_.basic().channel_count.SetExact(2);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(result.device_id(), "default_device");
  EXPECT_EQ(result.audio_processing_properties().echo_cancellation_type,
            EchoCancellationType::kEchoCancellationAec3);
  EXPECT_EQ(result.num_channels(), 2);

  ResetFactory();
  constraint_factory_.basic().channel_count.SetIdeal(2);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(result.device_id(), "default_device");
  EXPECT_EQ(result.audio_processing_properties().echo_cancellation_type,
            EchoCancellationType::kEchoCancellationAec3);
  EXPECT_EQ(result.num_channels(), 2);

  ResetFactory();
  constraint_factory_.basic().channel_count.SetIdeal(4);
  result = SelectSettings();
  EXPECT_TRUE(result.HasValue());
  EXPECT_EQ(result.device_id(), "4_channels_device");
  EXPECT_EQ(result.audio_processing_properties().echo_cancellation_type,
            EchoCancellationType::kEchoCancellationAec3);
  EXPECT_EQ(result.num_channels(), 4);
}

TEST_P(MediaStreamConstraintsUtilAudioTest, ChannelsWithSource) {
  if (!IsDeviceCapture())
    return;

  std::unique_ptr<blink::LocalMediaStreamAudioSource> source =
      GetLocalMediaStreamAudioSource(false /* enable_system_echo_canceller */,
```