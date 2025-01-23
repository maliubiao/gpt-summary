Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the *functionality* of the `ProcessedLocalAudioSource` class in Chromium's Blink rendering engine. It also asks about relationships to web technologies, logical reasoning (input/output), common errors, and how a user might reach this code.

2. **Initial Skim and Keyword Spotting:** Read through the code quickly, looking for keywords and familiar concepts:
    * `#include`:  Indicates dependencies on other parts of the codebase (like `media/`, `webrtc/`, platform-specific headers).
    * `namespace blink`:  Confirms this is Blink-specific code.
    * Class name: `ProcessedLocalAudioSource` suggests this class handles local audio sources with some kind of processing.
    * Methods like `EnsureSourceIsStarted`, `EnsureSourceIsStopped`, `Capture`, `DeliverProcessedAudio`, `SetVolume`, `ChangeSourceImpl`: These are key actions the class performs.
    * Variables like `source_`, `media_stream_audio_processor_`, `audio_processor_proxy_`: These represent core components.
    * Logging statements (`SendLogMessage`): Useful for understanding the flow and potential issues.
    * UMA histograms: Indicate performance tracking and data collection.
    * `AudioProcessingProperties`: Hints at configuration and customization.
    * References to WebRTC (`WebRtcAudioDeviceImpl`): Suggests integration with WebRTC for audio processing.

3. **Identify Core Functionality (The "What"):** Based on the skim, start listing the main responsibilities:
    * **Manages a local audio input source:** This is the primary purpose.
    * **Applies audio processing:**  Keywords like "processed" and the presence of `MediaStreamAudioProcessor` and `AudioServiceAudioProcessorProxy` strongly suggest this.
    * **Integrates with WebRTC:** The `WebRtcAudioDeviceImpl` connection is crucial.
    * **Handles audio constraints:**  The `AudioProcessingProperties` and the logic for enabling/disabling system audio effects point to constraint handling.
    * **Provides processed audio to consumers (likely `MediaStreamTrack`):**  The `DeliverProcessedAudio` method is the key here.
    * **Handles starting and stopping the audio source:**  `EnsureSourceIsStarted` and `EnsureSourceIsStopped` are explicit.
    * **Manages volume:** The `SetVolume` method.
    * **Handles source changes:** The `ChangeSourceImpl` method.

4. **Connect to Web Technologies (The "How" and the Examples):**  Think about how this backend code relates to frontend web technologies:
    * **JavaScript:**  The primary connection is through the `getUserMedia()` API. This JS API initiates the process of requesting media devices, and this C++ code is part of the implementation for handling audio. Specifically, the constraints passed to `getUserMedia()` influence the `AudioProcessingProperties`.
    * **HTML:** While not directly involved in *processing*, the audio source is used within a web page. The audio might be played through an `<audio>` element or used in a WebRTC peer connection, both of which are initiated by HTML.
    * **CSS:**  CSS has no direct functional relationship with this specific audio processing logic. It only affects the visual presentation of the webpage.

5. **Infer Logical Reasoning (Input/Output):** Focus on the key methods:
    * **`EnsureSourceIsStarted`:**
        * **Input:** `blink::MediaStreamDevice`, `blink::AudioProcessingProperties`.
        * **Output:** Starts the audio capture pipeline, potentially modifies the device settings, creates an audio processor (either local or remote).
    * **`Capture`:**
        * **Input:** Raw audio data (`media::AudioBus`), capture timestamp.
        * **Output:**  Passes the audio data to the audio processor (or directly delivers if using remote processing).
    * **`DeliverProcessedAudio`:**
        * **Input:** Processed audio data (`media::AudioBus`), capture timestamp.
        * **Output:** Delivers the processed audio to the `MediaStreamTrack` for consumption.

6. **Identify Potential User/Programming Errors (The "Gotchas"):** Consider common mistakes developers might make:
    * **Incorrect Constraints:**  Requesting combinations of audio processing features that are incompatible (e.g., browser-based AEC with system NS enabled).
    * **Calling methods in the wrong order:**  Trying to set volume before the source is started, for example.
    * **Relying on specific system effects:** Assuming a certain system effect is always available.
    * **Not handling errors:** Ignoring potential errors during source initialization.

7. **Trace User Actions (The "Path"):**  Think about the steps a user takes that lead to this code being executed:
    1. User opens a web page.
    2. JavaScript code on the page calls `navigator.mediaDevices.getUserMedia({ audio: true })`.
    3. The browser prompts the user for microphone permission.
    4. If the user grants permission, the browser selects an audio input device.
    5. Blink (the rendering engine) creates a `ProcessedLocalAudioSource` instance based on the selected device and requested constraints.
    6. This code is executed to initialize and manage the audio stream.

8. **Refine and Organize:** Structure the information logically. Start with a high-level summary of the class's purpose, then delve into specifics like functionality, relationships with web technologies, logical reasoning, errors, and user actions. Use clear headings and bullet points for readability.

9. **Review and Verify:**  Read through the explanation to ensure accuracy and completeness. Double-check the code to confirm the identified functionalities and relationships. Ensure the language is clear and understandable. For instance, initially, I might have just said "handles audio processing," but refining it to explicitly mention "either locally or via a remote service" adds more detail. Similarly, explicitly stating the role of `getUserMedia()` strengthens the connection to JavaScript.

By following this thought process, breaking down the code into manageable parts, and focusing on the "what," "how," and "why," we can generate a comprehensive and accurate explanation of the `ProcessedLocalAudioSource` class.
好的，让我们详细分析一下 `blink/renderer/modules/mediastream/processed_local_audio_source.cc` 这个文件。

**功能概述:**

`ProcessedLocalAudioSource` 类在 Chromium 的 Blink 渲染引擎中负责处理来自本地音频输入设备（例如麦克风）的音频流。它的主要功能是：

1. **管理本地音频源:** 它封装了一个底层的 `media::AudioCapturerSource` 对象，该对象实际负责从操作系统获取音频数据。
2. **应用音频处理:**  这是该类的核心功能。它可以配置并应用各种音频处理效果，例如：
    * **回声消除 (AEC):** 移除来自扬声器的音频在麦克风输入中的回声。
    * **噪声抑制 (NS):**  降低背景噪声。
    * **自动增益控制 (AGC):** 自动调整音频音量，使其处于合适的水平。
    * **语音隔离 (Voice Isolation):** (特定平台，如 ChromeOS) 尝试隔离用户的声音，减少其他声音的干扰。
3. **与 WebRTC 集成:**  该类与 WebRTC (Web Real-Time Communication) 紧密集成，特别是与 `WebRtcAudioDeviceImpl` 交互，以便利用 WebRTC 提供的音频处理能力。
4. **提供处理后的音频数据:** 将处理后的音频数据传递给 `MediaStreamTrack` 对象，以便浏览器可以播放或发送这些音频流。
5. **处理设备变更:** 允许在运行时切换音频输入设备。
6. **管理静音状态:** 控制音频源的静音状态。
7. **性能监控:** 使用 UMA (User Metrics Analysis) 收集音频处理相关的性能指标。

**与 JavaScript, HTML, CSS 的关系:**

`ProcessedLocalAudioSource` 本身是 C++ 代码，直接与 JavaScript、HTML 和 CSS 没有代码级别的交互。但是，它在浏览器处理音频流的过程中扮演着关键角色，而这些音频流通常是由 JavaScript API 触发和控制的。

**举例说明:**

* **JavaScript (getUserMedia):** 当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: true })` 请求访问用户的麦克风时，Blink 引擎会创建 `ProcessedLocalAudioSource` 的实例来管理这个音频流。 `getUserMedia` 的 `constraints` 参数可以影响 `ProcessedLocalAudioSource` 的音频处理配置（例如，请求回声消除或噪声抑制）。

   ```javascript
   navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true } })
     .then(function(stream) {
       // 使用 stream 对象，例如添加到 <audio> 元素或 WebRTC PeerConnection
     })
     .catch(function(err) {
       console.error('无法获取麦克风:', err);
     });
   ```

   在这个例子中，`echoCancellation: true` 和 `noiseSuppression: true` 会影响 `ProcessedLocalAudioSource` 如何配置其内部的音频处理器。

* **HTML (<audio>, <video>):**  通过 `getUserMedia` 获取的音频流可以被赋值给 HTML 的 `<audio>` 或 `<video>` 元素的 `srcObject` 属性，从而在网页上播放音频。`ProcessedLocalAudioSource` 确保了这些元素播放的是经过处理的音频。

   ```html
   <audio id="myAudio" controls></audio>
   <script>
     navigator.mediaDevices.getUserMedia({ audio: true })
       .then(function(stream) {
         document.getElementById('myAudio').srcObject = stream;
       });
   </script>
   ```

* **CSS:**  CSS 主要负责网页的样式和布局，与 `ProcessedLocalAudioSource` 的功能没有直接关系。CSS 可以用来控制 `<audio>` 或 `<video>` 元素的显示样式，但不会影响音频处理本身。

**逻辑推理 (假设输入与输出):**

假设用户在一个网页中请求了麦克风访问，并指定了以下约束：

* **输入 (假设):**
    * `blink::MediaStreamDevice`:  描述了麦克风设备的信息，例如设备 ID、采样率、声道布局等。
    * `blink::AudioProcessingProperties`:  包含了 JavaScript 请求的音频处理约束，例如 `{ echoCancellation: true, noiseSuppression: false }`。
    * 从麦克风捕获的原始音频数据 (未经过处理的音频样本)。

* **处理过程:**
    * `ProcessedLocalAudioSource` 根据 `AudioProcessingProperties` 配置内部的音频处理器，启用回声消除，禁用噪声抑制。
    * 当 `Capture` 方法被调用时，接收到原始音频数据。
    * 音频数据被传递给配置好的音频处理器。
    * 音频处理器执行回声消除算法。

* **输出 (假设):**
    * 处理后的音频数据：  消除了扬声器回声的音频样本。
    * 这些处理后的音频数据会被传递给 `MediaStreamTrack` 对象，最终可以被 `<audio>` 元素播放或通过 WebRTC 发送。

**用户或编程常见的使用错误:**

1. **请求冲突的音频处理选项:**  例如，同时请求浏览器内置的回声消除 (AEC3) 和操作系统级别的回声消除。 `ProcessedLocalAudioSource` 的代码会尝试解决这些冲突，例如优先使用浏览器内置的 AEC。
   * **错误示例 (JavaScript):**
     ```javascript
     navigator.mediaDevices.getUserMedia({
       audio: {
         echoCancellation: true, // 假设这会启用浏览器内置的 AEC
         deviceId: "system_aec_device_id" // 假设这是一个启用了系统 AEC 的虚拟设备
       }
     });
     ```
   * **后果:**  `ProcessedLocalAudioSource` 可能会忽略某些请求，或者按照其内部逻辑选择一种处理方式。开发者可能无法精确控制最终的音频处理流程。

2. **在音频源启动前进行配置:** 尝试在 `ProcessedLocalAudioSource` 启动之前（即 `EnsureSourceIsStarted` 被调用之前）设置某些属性或调用某些方法，可能会导致错误或配置不生效。

3. **假设所有系统效果都可用:** 某些音频处理效果（例如系统级别的噪声抑制或回声消除）可能只在特定的操作系统或硬件上可用。开发者不应假设这些效果总是存在。`ProcessedLocalAudioSource` 的代码会检查设备的功能，并根据可用性进行调整。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户打开一个网页:** 用户在浏览器中访问一个需要使用麦克风的网页（例如一个在线会议应用）。
2. **网页 JavaScript 请求麦克风权限:** 网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ audio: true, ...constraints })` 来请求用户的麦克风访问。
3. **浏览器显示权限提示:** 浏览器会弹出一个权限请求窗口，询问用户是否允许该网页访问麦克风。
4. **用户授予麦克风权限:** 用户点击“允许”按钮。
5. **Blink 引擎创建 MediaStream 对象:** 一旦权限被授予，Blink 引擎会开始创建 `MediaStream` 对象来表示捕获到的音频和/或视频流。
6. **创建 ProcessedLocalAudioSource 实例:**  对于音频流，Blink 引擎会根据请求的约束和选择的音频设备创建一个 `ProcessedLocalAudioSource` 实例。 这部分代码会在 `blink/renderer/modules/mediastream/media_devices.cc` 或相关的文件中被调用。
7. **EnsureSourceIsStarted 被调用:**  `ProcessedLocalAudioSource` 的 `EnsureSourceIsStarted` 方法会被调用，初始化音频捕获管道，包括创建 `media::AudioCapturerSource` 和配置音频处理器。
8. **音频数据开始流动:**  `media::AudioCapturerSource` 开始从操作系统捕获音频数据，并通过 `Capture` 方法将数据传递给 `ProcessedLocalAudioSource`。
9. **音频处理应用:** `ProcessedLocalAudioSource` 根据配置应用音频处理效果。
10. **DeliverProcessedAudio 被调用:** 处理后的音频数据通过 `DeliverProcessedAudio` 方法传递给 `MediaStreamTrack`。
11. **音频数据被网页使用:** 网页的 JavaScript 代码可以获取 `MediaStreamTrack` 中的音频数据，并将其用于播放、通过 WebRTC 发送等操作。

**调试线索:**

* **查看 `chrome://webrtc-internals`:**  这个 Chrome 内部页面提供了关于 WebRTC 会话的详细信息，包括音频处理器的配置、音频流的统计信息等。这可以帮助你了解 `ProcessedLocalAudioSource` 的实际运行状态。
* **使用开发者工具的断点:**  在 `blink/renderer/modules/mediastream/processed_local_audio_source.cc` 文件中设置断点，可以跟踪代码的执行流程，查看变量的值，了解音频处理的配置和数据流向。
* **查看 Chrome 的日志:**  通过启动带有特定命令行参数的 Chrome (例如 `--enable-logging --v=1`)，可以获取更详细的日志信息，包括 `ProcessedLocalAudioSource` 输出的调试信息 (通过 `SendLogMessage`)。
* **检查 `MediaStream` 对象的属性:** 在 JavaScript 中，可以检查 `MediaStreamTrack` 对象的属性（例如 `getSettings()`）来了解浏览器实际应用的音频处理配置。

希望这个详细的分析对您有所帮助！

### 提示词
```
这是目录为blink/renderer/modules/mediastream/processed_local_audio_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/processed_local_audio_source.h"

#include <algorithm>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "build/chromecast_buildflags.h"
#include "media/audio/audio_source_parameters.h"
#include "media/base/channel_layout.h"
#include "media/base/media_switches.h"
#include "media/base/sample_rates.h"
#include "media/media_buildflags.h"
#include "media/webrtc/webrtc_features.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_audio_processor.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/modules/webrtc/webrtc_audio_device_impl.h"
#include "third_party/blink/renderer/platform/mediastream/audio_service_audio_processor_proxy.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/webrtc/media/base/media_channel.h"

namespace blink {

using EchoCancellationType =
    blink::AudioProcessingProperties::EchoCancellationType;

namespace {

void SendLogMessage(const std::string& message) {
  blink::WebRtcLogMessage("PLAS::" + message);
}

// Used as an identifier for ProcessedLocalAudioSource::From().
void* const kProcessedLocalAudioSourceIdentifier =
    const_cast<void**>(&kProcessedLocalAudioSourceIdentifier);

std::string GetEnsureSourceIsStartedLogString(
    const blink::MediaStreamDevice& device) {
  return base::StringPrintf(
      "EnsureSourceIsStarted({session_id=%s}, {channel_layout=%d}, "
      "{sample_rate=%d}, {buffer_size=%d}, {effects=%d})",
      device.session_id().ToString().c_str(), device.input.channel_layout(),
      device.input.sample_rate(), device.input.frames_per_buffer(),
      device.input.effects());
}

std::string GetAudioProcesingPropertiesLogString(
    const blink::AudioProcessingProperties& properties) {
  auto aec_to_string =
      [](blink::AudioProcessingProperties::EchoCancellationType type) {
        using AEC = blink::AudioProcessingProperties::EchoCancellationType;
        switch (type) {
          case AEC::kEchoCancellationDisabled:
            return "disabled";
          case AEC::kEchoCancellationAec3:
            return "aec3";
          case AEC::kEchoCancellationSystem:
            return "system";
        }
      };
  auto bool_to_string = [](bool value) { return value ? "true" : "false"; };
  auto str = base::StringPrintf(
      "aec: %s, "
      "disable_hw_ns: %s, "
      "auto_gain_control: %s, "
      "noise_suppression: %s",
      aec_to_string(properties.echo_cancellation_type),
      bool_to_string(properties.disable_hw_noise_suppression),
      bool_to_string(properties.auto_gain_control),
      bool_to_string(properties.noise_suppression));
  return str;
}

// Returns whether system noise suppression is allowed to be used regardless of
// whether the noise suppression constraint is set, or whether a browser-based
// AEC is active. This is currently the default on at least MacOS but is not
// allowed for ChromeOS setups.
constexpr bool IsIndependentSystemNsAllowed() {
#if BUILDFLAG(IS_CHROMEOS)
  return false;
#else
  return true;
#endif
}

void LogInputDeviceParametersToUma(
    const media::AudioParameters& input_device_params) {
  UMA_HISTOGRAM_ENUMERATION("WebRTC.AudioInputChannelLayout",
                            input_device_params.channel_layout(),
                            media::CHANNEL_LAYOUT_MAX + 1);
  media::AudioSampleRate asr;
  if (media::ToAudioSampleRate(input_device_params.sample_rate(), &asr)) {
    UMA_HISTOGRAM_ENUMERATION("WebRTC.AudioInputSampleRate", asr,
                              media::kAudioSampleRateMax + 1);
  } else {
    UMA_HISTOGRAM_COUNTS_1M("WebRTC.AudioInputSampleRateUnexpected",
                            input_device_params.sample_rate());
  }
}

}  // namespace

ProcessedLocalAudioSource::ProcessedLocalAudioSource(
    LocalFrame& frame,
    const blink::MediaStreamDevice& device,
    bool disable_local_echo,
    const blink::AudioProcessingProperties& audio_processing_properties,
    int num_requested_channels,
    ConstraintsRepeatingCallback started_callback,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : blink::MediaStreamAudioSource(std::move(task_runner),
                                    true /* is_local_source */,
                                    disable_local_echo),
      // Remote APM is only enabled for mic input, other input sources have
      // conflicting requirements on echo cancellation:
      // https://crbug.com/1328012
      use_remote_apm_(media::IsChromeWideEchoCancellationEnabled() &&
                      device.type ==
                          mojom::blink::MediaStreamType::DEVICE_AUDIO_CAPTURE),
      consumer_frame_(&frame),
      dependency_factory_(
          PeerConnectionDependencyFactory::From(*frame.DomWindow())),
      audio_processing_properties_(audio_processing_properties),
      num_requested_channels_(num_requested_channels),
      started_callback_(std::move(started_callback)),
      allow_invalid_render_frame_id_for_testing_(false) {
  DCHECK(frame.DomWindow());
  SetDevice(device);
  DVLOG(1) << "ProcessedLocalAudioSource: system AEC available = "
           << !!(device.input.effects() &
                 media::AudioParameters::ECHO_CANCELLER)
           << " remote APM = " << use_remote_apm_
           << "\naudio_processing_properties_ : ["
           << GetAudioProcesingPropertiesLogString(audio_processing_properties_)
           << "]";
  SendLogMessage(
      base::StringPrintf("ProcessedLocalAudioSource({session_id=%s}, {APM:%s})",
                         device.session_id().ToString().c_str(),
                         use_remote_apm_ ? "remote" : "local"));
}

ProcessedLocalAudioSource::~ProcessedLocalAudioSource() {
  DVLOG(1) << "PLAS::~ProcessedLocalAudioSource()";
  EnsureSourceIsStopped();
}

// static
ProcessedLocalAudioSource* ProcessedLocalAudioSource::From(
    blink::MediaStreamAudioSource* source) {
  if (source &&
      source->GetClassIdentifier() == kProcessedLocalAudioSourceIdentifier)
    return static_cast<ProcessedLocalAudioSource*>(source);
  return nullptr;
}

void ProcessedLocalAudioSource::SendLogMessageWithSessionId(
    const std::string& message) const {
  SendLogMessage(message + " [session_id=" + device().session_id().ToString() +
                 "]");
}

std::optional<blink::AudioProcessingProperties>
ProcessedLocalAudioSource::GetAudioProcessingProperties() const {
  return audio_processing_properties_;
}

void* ProcessedLocalAudioSource::GetClassIdentifier() const {
  return kProcessedLocalAudioSourceIdentifier;
}

bool ProcessedLocalAudioSource::EnsureSourceIsStarted() {
  DCHECK(GetTaskRunner()->BelongsToCurrentThread());

  if (source_)
    return true;

  // Sanity-check that the consuming RenderFrame still exists. This is required
  // to initialize the audio source.
  if (!allow_invalid_render_frame_id_for_testing_ && !consumer_frame_) {
    SendLogMessageWithSessionId(
        "EnsureSourceIsStarted() => (ERROR: "
        " render frame does not exist)");
    return false;
  }

  SendLogMessage(GetEnsureSourceIsStartedLogString(device()));
  SendLogMessageWithSessionId(base::StringPrintf(
      "EnsureSourceIsStarted() => (audio_processing_properties=[%s])",
      GetAudioProcesingPropertiesLogString(audio_processing_properties_)
          .c_str()));

  blink::MediaStreamDevice modified_device(device());
  bool device_is_modified = false;

  // Disable system echo cancellation if available but not requested by
  // |audio_processing_properties_|. Also disable any system noise suppression
  // and automatic gain control to avoid those causing issues for the echo
  // cancellation.
  if (audio_processing_properties_.echo_cancellation_type !=
          EchoCancellationType::kEchoCancellationSystem &&
      device().input.effects() & media::AudioParameters::ECHO_CANCELLER) {
    DVLOG(1)
        << "ProcessedLocalAudioSource: resetting system echo cancellation flag";
    modified_device.input.set_effects(modified_device.input.effects() &
                                      ~media::AudioParameters::ECHO_CANCELLER);
    if (!IsIndependentSystemNsAllowed()) {
      modified_device.input.set_effects(
          modified_device.input.effects() &
          ~media::AudioParameters::NOISE_SUPPRESSION);
    }
    modified_device.input.set_effects(
        modified_device.input.effects() &
        ~media::AudioParameters::AUTOMATIC_GAIN_CONTROL);
    device_is_modified = true;
  }

  // Optionally disable system noise suppression.
  if (device().input.effects() & media::AudioParameters::NOISE_SUPPRESSION) {
    // Disable noise suppression on the device if the properties explicitly
    // specify to do so.
    bool disable_system_noise_suppression =
        audio_processing_properties_.disable_hw_noise_suppression;

    if (!IsIndependentSystemNsAllowed()) {
      // Disable noise suppression on the device if browser-based echo
      // cancellation is active, since that otherwise breaks the AEC.
      const bool browser_based_aec_active =
          audio_processing_properties_.echo_cancellation_type ==
          AudioProcessingProperties::EchoCancellationType::
              kEchoCancellationAec3;
      disable_system_noise_suppression =
          disable_system_noise_suppression || browser_based_aec_active;

      // Disable noise suppression on the device if the constraints
      // dictate that.
      disable_system_noise_suppression =
          disable_system_noise_suppression ||
          !audio_processing_properties_.noise_suppression;
    }

    if (disable_system_noise_suppression) {
      modified_device.input.set_effects(
          modified_device.input.effects() &
          ~media::AudioParameters::NOISE_SUPPRESSION);
      device_is_modified = true;
    }
  }

  // Optionally disable system automatic gain control.
  if (device().input.effects() &
      media::AudioParameters::AUTOMATIC_GAIN_CONTROL) {
    // Disable automatic gain control on the device if browser-based echo
    // cancellation is, since that otherwise breaks the AEC.
    const bool browser_based_aec_active =
        audio_processing_properties_.echo_cancellation_type ==
        AudioProcessingProperties::EchoCancellationType::kEchoCancellationAec3;
    bool disable_system_automatic_gain_control = browser_based_aec_active;

    // Disable automatic gain control on the device if the constraints dictates
    // that.
    disable_system_automatic_gain_control =
        disable_system_automatic_gain_control ||
        !audio_processing_properties_.auto_gain_control;

    if (disable_system_automatic_gain_control) {
      modified_device.input.set_effects(
          modified_device.input.effects() &
          ~media::AudioParameters::AUTOMATIC_GAIN_CONTROL);
      device_is_modified = true;
    }
  }

#if BUILDFLAG(IS_CHROMEOS)
  if (base::FeatureList::IsEnabled(media::kCrOSSystemVoiceIsolationOption) &&
      device().input.effects() &
          media::AudioParameters::VOICE_ISOLATION_SUPPORTED) {
    // Disable voice isolation on the device if browser-based echo
    // cancellation is, since that otherwise breaks the AEC.
    const bool browser_based_aec_active =
        audio_processing_properties_.echo_cancellation_type ==
        AudioProcessingProperties::EchoCancellationType::kEchoCancellationAec3;
    const bool disable_system_voice_isolation_due_to_browser_aec =
        browser_based_aec_active;

    if (disable_system_voice_isolation_due_to_browser_aec ||
        audio_processing_properties_.voice_isolation ==
            AudioProcessingProperties::VoiceIsolationType::
                kVoiceIsolationDisabled) {
      // Force voice isolation to be disabled.
      modified_device.input.set_effects(
          modified_device.input.effects() |
          media::AudioParameters::CLIENT_CONTROLLED_VOICE_ISOLATION);

      modified_device.input.set_effects(
          modified_device.input.effects() &
          ~media::AudioParameters::VOICE_ISOLATION);
    } else if (audio_processing_properties_.voice_isolation ==
               AudioProcessingProperties::VoiceIsolationType::
                   kVoiceIsolationEnabled) {
      // Force voice isolation to be enabled.
      modified_device.input.set_effects(
          modified_device.input.effects() |
          media::AudioParameters::CLIENT_CONTROLLED_VOICE_ISOLATION);

      modified_device.input.set_effects(
          modified_device.input.effects() |
          media::AudioParameters::VOICE_ISOLATION);
    } else {
      // Turn off voice isolation control.
      modified_device.input.set_effects(
          modified_device.input.effects() &
          ~media::AudioParameters::CLIENT_CONTROLLED_VOICE_ISOLATION);
    }

    if ((modified_device.input.effects() &
         media::AudioParameters::CLIENT_CONTROLLED_VOICE_ISOLATION) !=
            (device().input.effects() &
             media::AudioParameters::CLIENT_CONTROLLED_VOICE_ISOLATION) ||
        (modified_device.input.effects() &
         media::AudioParameters::VOICE_ISOLATION) ||
        (device().input.effects() & media::AudioParameters::VOICE_ISOLATION)) {
      device_is_modified = true;
    }
  }
#endif

#if BUILDFLAG(IS_CHROMEOS)
  if (base::FeatureList::IsEnabled(media::kIgnoreUiGains)) {
    // Ignore UI Gains if AGC is running in either browser or system
    if (audio_processing_properties_.GainControlEnabled()) {
      modified_device.input.set_effects(
          modified_device.input.effects() |
          media::AudioParameters::IGNORE_UI_GAINS);
      device_is_modified = true;
    }
  }
#endif

  if (device_is_modified)
    SetDevice(modified_device);

  // Create the audio processor.

  DCHECK(dependency_factory_);
  WebRtcAudioDeviceImpl* const rtc_audio_device =
      dependency_factory_->GetWebRtcAudioDevice();
  if (!rtc_audio_device) {
    SendLogMessageWithSessionId(
        "EnsureSourceIsStarted() => (ERROR: no WebRTC ADM instance)");
    return false;
  }

  // If system level echo cancellation is active, flag any other active system
  // level effects to the audio processor.
  if (audio_processing_properties_.echo_cancellation_type ==
      AudioProcessingProperties::EchoCancellationType::
          kEchoCancellationSystem) {
    if (!IsIndependentSystemNsAllowed()) {
      if (audio_processing_properties_.noise_suppression) {
        audio_processing_properties_.system_noise_suppression_activated =
            device().input.effects() &
            media::AudioParameters::NOISE_SUPPRESSION;
      }
    }

    if (audio_processing_properties_.auto_gain_control) {
      audio_processing_properties_.system_gain_control_activated =
          device().input.effects() &
          media::AudioParameters::AUTOMATIC_GAIN_CONTROL;
    }
  }

  // No more modifications of |audio_processing_properties_| after this line.
  media::AudioProcessingSettings audio_processing_settings(
      audio_processing_properties_.ToAudioProcessingSettings(
          num_requested_channels_ > 1));

  // Determine the audio format required of the AudioCapturerSource.
  const media::AudioParameters input_device_params = device().input;
  LogInputDeviceParametersToUma(input_device_params);
  auto maybe_audio_capture_params = media::AudioProcessor::ComputeInputFormat(
      input_device_params, audio_processing_settings);

  if (!maybe_audio_capture_params) {
    SendLogMessage(base::StringPrintf(
        "EnsureSourceIsStarted() => (ERROR: "
        "input device format (%s) is not supported.",
        input_device_params.AsHumanReadableString().c_str()));
    return false;
  }
  media::AudioParameters audio_capture_params = *maybe_audio_capture_params;

  media::AudioSourceParameters source_config(device().session_id());

  if (use_remote_apm_) {
    // Since audio processing will be applied in the audio service, we request
    // audio here in the audio processing output format to avoid forced
    // resampling.
    audio_capture_params = media::AudioProcessor::GetDefaultOutputFormat(
        audio_capture_params, audio_processing_settings);

    // Create a proxy to the audio processor in the audio service.
    audio_processor_proxy_ =
        new rtc::RefCountedObject<AudioServiceAudioProcessorProxy>();

    // The output format of this ProcessedLocalAudioSource is the audio capture
    // format.
    SetFormat(audio_capture_params);

    // Add processing to the AudioCapturerSource configuration.
    source_config.processing = audio_processing_settings;

  } else {
    // Create the MediaStreamAudioProcessor, bound to the WebRTC audio device
    // module.

    // This callback has to be valid until MediaStreamAudioProcessor is stopped,
    // which happens in EnsureSourceIsStopped().
    MediaStreamAudioProcessor::DeliverProcessedAudioCallback
        processing_callback =
            ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
                &ProcessedLocalAudioSource::DeliverProcessedAudio,
                CrossThreadUnretained(this)));

    media_stream_audio_processor_ =
        new rtc::RefCountedObject<MediaStreamAudioProcessor>(
            std::move(processing_callback), audio_processing_settings,
            audio_capture_params, rtc_audio_device);

    // The output format of this ProcessedLocalAudioSource is the audio
    // processor's output format.
    SetFormat(media_stream_audio_processor_->output_format());
  }

  SendLogMessageWithSessionId(
      base::StringPrintf("EnsureSourceIsStarted() => (using APM in %s process: "
                         "settings=[%s])",
                         audio_processor_proxy_ ? "audio" : "renderer",
                         audio_processing_settings.ToString().c_str()));

  // Start the source.
  SendLogMessageWithSessionId(base::StringPrintf(
      "EnsureSourceIsStarted() => (WebRTC audio source starts: "
      "input_parameters=[%s], output_parameters=[%s])",
      audio_capture_params.AsHumanReadableString().c_str(),
      GetAudioParameters().AsHumanReadableString().c_str()));
  auto* web_frame =
      static_cast<WebLocalFrame*>(WebFrame::FromCoreFrame(consumer_frame_));
  scoped_refptr<media::AudioCapturerSource> new_source =
      Platform::Current()->NewAudioCapturerSource(web_frame, source_config);
  new_source->Initialize(audio_capture_params, this);
  // We need to set the AGC control before starting the stream.
  new_source->SetAutomaticGainControl(true);
  source_ = std::move(new_source);
  source_->Start();

  // Register this source with the WebRtcAudioDeviceImpl.
  rtc_audio_device->AddAudioCapturer(this);

  return true;
}

void ProcessedLocalAudioSource::EnsureSourceIsStopped() {
  DCHECK(GetTaskRunner()->BelongsToCurrentThread());

  if (!source_)
    return;

  scoped_refptr<media::AudioCapturerSource> source_to_stop(std::move(source_));

  if (dependency_factory_) {
    dependency_factory_->GetWebRtcAudioDevice()->RemoveAudioCapturer(this);
  }

  source_to_stop->Stop();

  if (media_stream_audio_processor_) {
    // Stop the audio processor to avoid feeding render data into the processor.
    media_stream_audio_processor_->Stop();
  } else {
    // Stop the proxy, to detach from the processor controls.
    DCHECK(audio_processor_proxy_);
    audio_processor_proxy_->Stop();
  }

  DVLOG(1) << "Stopped WebRTC audio pipeline for consumption.";
}

scoped_refptr<webrtc::AudioProcessorInterface>
ProcessedLocalAudioSource::GetAudioProcessor() const {
  if (audio_processor_proxy_) {
    return static_cast<scoped_refptr<webrtc::AudioProcessorInterface>>(
        audio_processor_proxy_);
  }
  DCHECK(media_stream_audio_processor_);
  if (!media_stream_audio_processor_->has_webrtc_audio_processing())
    return nullptr;
  return static_cast<scoped_refptr<webrtc::AudioProcessorInterface>>(
      media_stream_audio_processor_);
}

void ProcessedLocalAudioSource::SetVolume(double volume) {
  DVLOG(1) << "ProcessedLocalAudioSource::SetVolume()";
  DCHECK_LE(volume, 1.0);
  if (source_)
    source_->SetVolume(volume);
}

void ProcessedLocalAudioSource::OnCaptureStarted() {
  SendLogMessageWithSessionId(base::StringPrintf("OnCaptureStarted()"));
  started_callback_.Run(this, mojom::blink::MediaStreamRequestResult::OK, "");
}

void ProcessedLocalAudioSource::Capture(
    const media::AudioBus* audio_bus,
    base::TimeTicks audio_capture_time,
    const media::AudioGlitchInfo& glitch_info,
    double volume) {
  TRACE_EVENT1("audio", "ProcessedLocalAudioSource::Capture", "capture-time",
               audio_capture_time);
  glitch_info_accumulator_.Add(glitch_info);
  // Maximum number of channels used by the sinks.
  int num_preferred_channels = NumPreferredChannels();
  if (media_stream_audio_processor_) {
    // Figure out if the pre-processed data has any energy or not. This
    // information will be passed to the level calculator to force it to report
    // energy in case the post-processed data is zeroed by the audio processing.
    force_report_nonzero_energy_ = !audio_bus->AreFramesZero();

    // Push the data to the processor for processing.
    // Passing audio to the audio processor is sufficient, the processor will
    // return it to DeliverProcessedAudio() via the registered callback.
    media_stream_audio_processor_->ProcessCapturedAudio(
        *audio_bus, audio_capture_time, num_preferred_channels, volume);
    return;
  }

  DCHECK(audio_processor_proxy_);
  audio_processor_proxy_->MaybeUpdateNumPreferredCaptureChannels(
      num_preferred_channels);

  // The audio is already processed in the audio service, just send it
  // along.
  force_report_nonzero_energy_ = false;
  DeliverProcessedAudio(*audio_bus, audio_capture_time,
                        /*new_volume=*/std::nullopt);
}

void ProcessedLocalAudioSource::OnCaptureError(
    media::AudioCapturerSource::ErrorCode code,
    const std::string& message) {
  SendLogMessageWithSessionId(
      base::StringPrintf("OnCaptureError({code=%d, message=%s})",
                         static_cast<int>(code), message.c_str()));
  StopSourceOnError(code, message);
}

void ProcessedLocalAudioSource::OnCaptureMuted(bool is_muted) {
  SendLogMessageWithSessionId(base::StringPrintf(
      "OnCaptureMuted({is_muted=%s})", is_muted ? "true" : "false"));
  SetMutedState(is_muted);
}

void ProcessedLocalAudioSource::OnCaptureProcessorCreated(
    media::AudioProcessorControls* controls) {
  SendLogMessageWithSessionId(
      base::StringPrintf("OnCaptureProcessorCreated()"));
  DCHECK_NE(!!media_stream_audio_processor_, !!audio_processor_proxy_);
  if (audio_processor_proxy_)
    audio_processor_proxy_->SetControls(controls);
}

void ProcessedLocalAudioSource::ChangeSourceImpl(
    const MediaStreamDevice& new_device) {
  DCHECK(GetTaskRunner()->BelongsToCurrentThread());
  WebRtcLogMessage("ProcessedLocalAudioSource::ChangeSourceImpl(new_device = " +
                   new_device.id + ")");
  EnsureSourceIsStopped();
  SetDevice(new_device);
  EnsureSourceIsStarted();
}

void ProcessedLocalAudioSource::SetOutputDeviceForAec(
    const std::string& output_device_id) {
  SendLogMessageWithSessionId(base::StringPrintf(
      "SetOutputDeviceForAec({device_id=%s})", output_device_id.c_str()));
  if (source_)
    source_->SetOutputDeviceForAec(output_device_id);
}

void ProcessedLocalAudioSource::DeliverProcessedAudio(
    const media::AudioBus& processed_audio,
    base::TimeTicks audio_capture_time,
    std::optional<double> new_volume) {
  TRACE_EVENT("audio", "ProcessedLocalAudioSource::DeliverProcessedAudio",
              "capture_time (ms)",
              (audio_capture_time - base::TimeTicks()).InMillisecondsF(),
              "capture_delay (ms)",
              (base::TimeTicks::Now() - audio_capture_time).InMillisecondsF());
  level_calculator_.Calculate(processed_audio, force_report_nonzero_energy_);
  DeliverDataToTracks(processed_audio, audio_capture_time,
                      glitch_info_accumulator_.GetAndReset());

  if (new_volume) {
    PostCrossThreadTask(
        *GetTaskRunner(), FROM_HERE,
        CrossThreadBindOnce(&ProcessedLocalAudioSource::SetVolume,
                            weak_factory_.GetWeakPtr(), *new_volume));
  }
}

}  // namespace blink
```