Response:
Let's break down the thought process for analyzing the `input_device_info.cc` file.

**1. Understanding the Core Functionality:**

* **Goal:** The filename and the included headers (`media/capture/mojom/video_capture_types.mojom-shared.h`, `third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h`) strongly suggest this file is about representing information about input devices, specifically audio and video input devices.
* **Constructor:** The `InputDeviceInfo` constructor takes `device_id`, `label`, `group_id`, and `device_type`. This immediately signals that it's a data structure holding properties of an input device.
* **Key Methods:** The presence of `SetVideoInputCapabilities` and `SetAudioInputCapabilities` clearly indicates the purpose is to store and manage the capabilities of these devices. The `getCapabilities` method further reinforces this idea – it's about retrieving this stored capability information.

**2. Deconstructing the Methods:**

* **`SetVideoInputCapabilities`:**
    * **Input:**  A `mojom::blink::VideoInputDeviceCapabilitiesPtr`. The `Ptr` suggests a pointer to a structure defined in a Mojo interface (inter-process communication in Chromium). Inspecting the members of this structure (via mental recall or looking up the definition) reveals information like `formats` (resolution and frame rate) and `facing_mode`.
    * **Logic:** The code iterates through the formats to find the maximum width, height, and frame rate. It maps the `facing_mode` enum. It also handles device availability.
    * **Output (Internal State):** It populates the `platform_capabilities_` member variable, specifically the fields related to video (width, height, aspect ratio, frame rate, facing mode, availability).
* **`SetAudioInputCapabilities`:**
    * **Input:** A `mojom::blink::AudioInputDeviceCapabilitiesPtr`. Similar to video, this Mojo structure holds audio-specific capabilities like `channels`, `sample_rate`, and `latency`.
    * **Logic:** It directly assigns the values to the `platform_capabilities_`, applying some min/max logic, particularly around `sample_rate` and `latency`. The constant `kFallbackAudioLatencyMs` suggests a default value is used if the device doesn't provide specific latency information.
    * **Output (Internal State):** Populates the `platform_capabilities_` member variable with audio-related fields.
* **`getCapabilities`:**
    * **Logic:** This is the most complex method.
        * **Permissions Check:** It checks if the `label` is empty. An empty label likely indicates that the user hasn't granted permission to access the device. It also checks `platform_capabilities_.is_available`.
        * **Capability Object Creation:** It creates a `MediaTrackCapabilities` object. This is a JavaScript-visible object.
        * **Device Type Handling:** It uses a conditional structure (`if (DeviceType() == ...)`) to handle audio and video devices differently.
        * **Audio Capabilities:**  It sets properties like `echoCancellation`, `autoGainControl`, `noiseSuppression`, `voiceIsolation`, `sampleSize`, `channelCount`, `sampleRate`, and `latency`. Notice the use of `LongRange` and `DoubleRange` for numerical values. The hardcoded values for audio processing features (`true, false`) are interesting.
        * **Video Capabilities:** It sets properties like `width`, `height`, `aspectRatio`, `frameRate`, `facingMode`, and `resizeMode`. The `facingMode` logic converts the internal enum to string values expected by JavaScript. The `resizeMode` suggests the browser might offer options for how video is resized.
    * **Output:** Returns a `MediaTrackCapabilities` object populated with the device's capabilities.

**3. Identifying Connections to Web Technologies (JavaScript, HTML, CSS):**

* **`MediaTrackCapabilities`:**  This class name strongly suggests a direct mapping to the JavaScript `MediaTrackCapabilities` API. This API allows web developers to query the supported capabilities of media tracks (audio and video).
* **Property Names:** The property names being set in `getCapabilities` (e.g., `deviceId`, `groupId`, `width`, `height`, `frameRate`, `facingMode`, `echoCancellation`, etc.) are the same or very similar to the properties exposed by the JavaScript `MediaTrackCapabilities` API.
* **Mojo Interfaces:** The use of Mojo interfaces indicates communication between the browser's renderer process (where Blink runs) and other browser processes (like the media or GPU process). This communication is essential for fetching device information from the operating system.

**4. Considering User and Programming Errors:**

* **Permissions:** The check for an empty `label` highlights a crucial aspect of media device access – user permissions. A common user error is denying permission, leading to limited or no capabilities being reported.
* **Assumptions about Device Capabilities:**  The hardcoded values for audio processing capabilities (`true, false`) might be a simplification or a default if the underlying platform doesn't provide more granular information. A programming error could involve incorrectly assuming a device supports a specific feature.
* **Data Handling:**  Incorrectly handling the ranges (min/max values) could lead to inaccurate capability reporting.

**5. Tracing User Interaction:**

* **`navigator.mediaDevices.enumerateDevices()`:** This is the primary JavaScript API that triggers the fetching of media device information.
* **`navigator.mediaDevices.getUserMedia()`:**  Requesting access to a specific device (identified by its `deviceId`) via `getUserMedia` also involves retrieving device capabilities.
* **Debugging:** Knowing that `InputDeviceInfo` is involved helps when debugging issues related to reported device capabilities. Setting breakpoints in `SetVideoInputCapabilities`, `SetAudioInputCapabilities`, or `getCapabilities` would be useful.

**Self-Correction/Refinement:**

* Initially, I might have just focused on the direct JavaScript API mapping. However, recognizing the importance of Mojo interfaces and the multi-process architecture of Chromium adds a deeper understanding.
* The `TODO` comment in `SetVideoInputCapabilities` is a valuable hint about potential code refactoring or improvement opportunities.
* Considering the "why" behind certain design choices (like the fallback latency for audio) adds more context.

By following this structured approach, analyzing the code snippets, and connecting the dots between C++, JavaScript APIs, and the underlying architecture, a comprehensive understanding of the `input_device_info.cc` file can be achieved.
好的，让我们来分析一下 `blink/renderer/modules/mediastream/input_device_info.cc` 文件的功能。

**文件功能概述**

`InputDeviceInfo.cc` 文件的主要职责是**封装和管理关于音频和视频输入设备的信息**。它作为 Blink 渲染引擎中处理媒体流的一部分，负责存储和提供关于可用输入设备的详细信息，例如设备 ID、标签、分组 ID 以及设备所支持的各种能力（capabilities）。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件中的代码虽然是 C++ 实现，但它所管理的数据和功能与前端的 JavaScript API 紧密相关，最终会影响到 Web 开发者在 HTML 页面中使用 JavaScript 和 CSS 来操作媒体设备的行为。

1. **JavaScript `navigator.mediaDevices.enumerateDevices()` API:**
   - **功能关系:** 当 JavaScript 代码调用 `navigator.mediaDevices.enumerateDevices()` 方法时，浏览器会底层调用 C++ 代码来枚举系统中可用的媒体设备（包括音频输入、音频输出、视频输入设备）。`InputDeviceInfo` 的实例就代表了其中一个音频或视频输入设备的信息。
   - **举例说明:**
     ```javascript
     navigator.mediaDevices.enumerateDevices()
       .then(function(devices) {
         devices.forEach(function(device) {
           console.log(device.kind + ": " + device.label + " id = " + device.deviceId);
         });
       })
       .catch(function(err) {
         console.log("发生错误: " + err.name + ": " + err.message);
       });
     ```
     在这个 JavaScript 代码中，`device.deviceId` 和 `device.label` 这些属性的值，就是由 `InputDeviceInfo` 对象中的相应成员变量提供的。

2. **JavaScript `MediaTrackConstraints` API (与 `getUserMedia` 结合使用):**
   - **功能关系:**  `InputDeviceInfo` 中的 `getCapabilities()` 方法返回一个 `MediaTrackCapabilities` 对象。这个对象描述了设备支持的各种媒体能力，例如视频的分辨率范围、帧率范围，音频的采样率、声道数等。这些信息可以被 JavaScript 的 `getUserMedia()` 方法用来设置媒体约束 (constraints)。
   - **举例说明:**
     ```javascript
     navigator.mediaDevices.getUserMedia({
       video: {
         deviceId: { exact: "your-video-device-id" }, // 指定设备 ID
         width: { min: 640, ideal: 1280, max: 1920 }, // 宽度约束
         frameRate: { min: 30 }                     // 帧率约束
       },
       audio: {
         deviceId: { exact: "your-audio-device-id" }, // 指定设备 ID
         echoCancellation: true                      // 回声消除约束
       }
     })
     .then(function(stream) {
       // 使用媒体流
     })
     .catch(function(err) {
       console.log("发生错误: " + err.name + ": " + err.message);
     });
     ```
     `InputDeviceInfo` 提供的 capabilities 信息帮助浏览器判断设备是否满足 `getUserMedia` 中指定的约束条件。例如，如果用户指定的 `width` 超出了设备的能力范围，`getUserMedia` 可能会失败。

3. **HTML `<video>` 和 `<audio>` 元素:**
   - **功能关系:**  虽然 `InputDeviceInfo` 不直接操作 HTML 元素，但它提供的设备信息是获取媒体流的基础。获取到的媒体流最终会赋值给 `<video>` 或 `<audio>` 元素的 `srcObject` 属性，从而在页面上显示或播放音视频。
   - **举例说明:**
     ```html
     <video id="myVideo" autoplay playsinline></video>
     <script>
       navigator.mediaDevices.getUserMedia({ video: true })
         .then(function(stream) {
           document.getElementById('myVideo').srcObject = stream;
         });
     </script>
     ```
     `InputDeviceInfo` 确保了 `getUserMedia` 可以找到可用的视频输入设备，并将其信息传递给上层 JavaScript 代码，最终让视频显示在 HTML 元素中。

4. **CSS (间接关系):**
   - **功能关系:** CSS 可以用来控制 `<video>` 和 `<audio>` 元素的样式和布局。`InputDeviceInfo` 间接地影响了最终呈现的媒体内容，因为它可以提供不同分辨率和帧率的视频流，而这些特性可能会影响到 CSS 样式的适配。
   - **举例说明:** 开发者可能会使用 CSS 的媒体查询 (media queries) 来根据视频的分辨率调整页面的布局或者视频播放器的样式。

**逻辑推理及假设输入与输出**

假设我们有一个视频输入设备，其硬件能力如下：

**假设输入:**

* `device_id`: "camera-123"
* `label`: "内置摄像头"
* `group_id`: "integrated-devices"
* `device_type`: `mojom::blink::MediaDeviceType::kMediaVideoInput`
* `video_input_capabilities->formats`: 包含以下格式信息:
    * 分辨率: 640x480, 帧率: 30
    * 分辨率: 1280x720, 帧率: 30
    * 分辨率: 1920x1080, 帧率: 60
* `video_input_capabilities->facing_mode`: `media::mojom::FacingMode::USER` (前置摄像头)
* `video_input_capabilities->availability`: `media::mojom::CameraAvailability::kAvailable`

**逻辑推理:**

`SetVideoInputCapabilities` 方法会遍历 `formats`，计算出最大宽度、最大高度和最大帧率。然后更新 `platform_capabilities_` 成员。

**假设输出 (部分 `platform_capabilities_`):**

* `platform_capabilities_.width`: `{1, 1920}`
* `platform_capabilities_.height`: `{1, 1080}`
* `platform_capabilities_.aspect_ratio`: `{1.0 / 1080, 1920.0}`
* `platform_capabilities_.frame_rate`: `{1.0, 60.0}`
* `platform_capabilities_.facing_mode`: `MediaStreamTrackPlatform::FacingMode::kUser`
* `platform_capabilities_.is_available`: `true`

当调用 `getCapabilities()` 方法时，它会基于 `platform_capabilities_` 创建并返回一个 `MediaTrackCapabilities` 对象，其中会包含以下信息：

**假设输出 (部分 `MediaTrackCapabilities`):**

* `width`: `{ min: 1, max: 1920 }`
* `height`: `{ min: 1, max: 1080 }`
* `frameRate`: `{ min: 1.0, max: 60.0 }`
* `facingMode`: `["user"]`
* `resizeMode`: `["none", "rescale"]`

**用户或编程常见的使用错误及举例说明**

1. **用户未授予媒体设备访问权限:**
   - **错误:**  在 JavaScript 中调用 `navigator.mediaDevices.getUserMedia()` 或 `navigator.mediaDevices.enumerateDevices()` 时，如果用户拒绝了浏览器请求的摄像头或麦克风权限，那么 `InputDeviceInfo` 对象中的 `label()` 可能会为空字符串，并且 `getCapabilities()` 方法返回的 capabilities 信息也会受限，甚至为空。
   - **调试线索:** 检查 JavaScript Promise 的 `catch` 语句，查看是否有 `NotAllowedError` 类型的错误。

2. **编程时假设设备总是支持某种能力:**
   - **错误:**  Web 开发者可能会错误地假设所有用户的摄像头都支持 1080p 分辨率，然后在 `getUserMedia` 中强制请求 `width: 1920, height: 1080`。如果用户的摄像头不支持，`getUserMedia` 调用将会失败。
   - **调试线索:**  在 JavaScript 中，先调用 `navigator.mediaDevices.enumerateDevices()` 获取设备信息，然后调用设备的 `getCapabilities()` 方法查看支持的能力范围，再根据这些信息设置合理的 constraints。

3. **处理异步操作不当:**
   - **错误:**  `navigator.mediaDevices.enumerateDevices()` 和 `navigator.mediaDevices.getUserMedia()` 都是异步操作。如果开发者没有正确使用 Promise 或 async/await 来处理异步结果，可能会在设备信息尚未加载完成时就尝试使用，导致错误。
   - **调试线索:** 检查 JavaScript 代码中是否正确使用了 `.then()` 和 `.catch()` 方法，或者使用了 `async` 和 `await` 关键字。

**用户操作如何一步步到达这里，作为调试线索**

以下是用户操作导致代码执行到 `InputDeviceInfo.cc` 的一种典型路径：

1. **用户访问一个需要使用摄像头或麦克风的网页。**
2. **网页上的 JavaScript 代码调用 `navigator.mediaDevices.enumerateDevices()` 或 `navigator.mediaDevices.getUserMedia()` 方法。**
3. **浏览器接收到 JavaScript 的请求，并开始枚举或请求访问媒体设备。**
4. **Blink 渲染引擎中的 C++ 代码（包括 `InputDeviceInfo.cc`）被调用来执行以下操作:**
   - **对于 `enumerateDevices()`:** 系统会查询可用的媒体设备，并为每个设备创建一个 `InputDeviceInfo` 对象，填充设备的 ID、标签等基本信息，并进一步调用平台相关的 API 获取设备的详细 capabilities，例如通过 `SetVideoInputCapabilities` 或 `SetAudioInputCapabilities` 方法填充。
   - **对于 `getUserMedia()`:** 系统会根据 JavaScript 提供的 constraints，查找匹配的媒体设备。这也会涉及到 `InputDeviceInfo` 对象及其 `getCapabilities()` 方法，来判断设备是否满足约束条件。
5. **如果用户尚未授予该网站的媒体权限，浏览器可能会弹出权限请求提示。** 用户允许或拒绝权限会影响 `InputDeviceInfo` 对象中 `label` 的值以及 capabilities 的完整性。
6. **最终，`enumerateDevices()` 返回一个包含 `MediaDeviceInfo` 对象（`InputDeviceInfo` 是其子类）的数组给 JavaScript，或者 `getUserMedia()` 返回一个 `MediaStream` 对象（如果成功）或一个错误（如果失败）。**

**调试线索:**

* **如果在使用 `enumerateDevices()` 时遇到问题:**
    - 检查浏览器控制台是否有关于枚举设备失败的错误信息。
    - 在 Blink 渲染引擎的设备枚举相关代码中设置断点，例如在创建 `InputDeviceInfo` 对象的代码处。
* **如果在使用 `getUserMedia()` 时遇到问题:**
    - 检查浏览器控制台是否有 `NotAllowedError`（权限被拒绝）、`NotFoundError`（找不到匹配的设备）、`OverconstrainedError`（没有设备满足所有约束）等错误。
    - 在 `InputDeviceInfo::getCapabilities()` 方法中设置断点，查看返回的 capabilities 是否符合预期，以及是否满足 JavaScript 中设置的 constraints。
    - 检查 `SetVideoInputCapabilities` 和 `SetAudioInputCapabilities` 方法是否正确地从底层平台获取了设备能力信息。

希望以上分析能够帮助你理解 `blink/renderer/modules/mediastream/input_device_info.cc` 文件的功能以及它在 Chromium 媒体流处理中的作用。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/input_device_info.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/input_device_info.h"

#include <algorithm>

#include "build/build_config.h"
#include "media/base/sample_format.h"
#include "media/capture/mojom/video_capture_types.mojom-shared.h"
#include "media/webrtc/constants.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_double_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_long_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_settings_range.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_capabilities.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_processor_options.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/webrtc/modules/audio_processing/include/audio_processing.h"

namespace blink {

InputDeviceInfo::InputDeviceInfo(const String& device_id,
                                 const String& label,
                                 const String& group_id,
                                 mojom::blink::MediaDeviceType device_type)
    : MediaDeviceInfo(device_id, label, group_id, device_type) {}

void InputDeviceInfo::SetVideoInputCapabilities(
    mojom::blink::VideoInputDeviceCapabilitiesPtr video_input_capabilities) {
  DCHECK_EQ(deviceId(), video_input_capabilities->device_id);
  // TODO(c.padhi): Merge the common logic below with
  // ComputeCapabilitiesForVideoSource() in media_stream_constraints_util.h, see
  // https://crbug.com/821668.
  platform_capabilities_.facing_mode =
      ToPlatformFacingMode(video_input_capabilities->facing_mode);
  if (!video_input_capabilities->formats.empty()) {
    int max_width = 1;
    int max_height = 1;
    float min_frame_rate = 1.0f;
    float max_frame_rate = min_frame_rate;
    for (const auto& format : video_input_capabilities->formats) {
      max_width = std::max(max_width, format.frame_size.width());
      max_height = std::max(max_height, format.frame_size.height());
      max_frame_rate = std::max(max_frame_rate, format.frame_rate);
    }
    platform_capabilities_.width = {1, static_cast<uint32_t>(max_width)};
    platform_capabilities_.height = {1, static_cast<uint32_t>(max_height)};
    platform_capabilities_.aspect_ratio = {1.0 / max_height,
                                           static_cast<double>(max_width)};
    platform_capabilities_.frame_rate = {min_frame_rate, max_frame_rate};
  }
  platform_capabilities_.is_available =
      !video_input_capabilities->availability ||
      (*video_input_capabilities->availability ==
       media::mojom::CameraAvailability::kAvailable);
}

void InputDeviceInfo::SetAudioInputCapabilities(
    mojom::blink::AudioInputDeviceCapabilitiesPtr audio_input_capabilities) {
  DCHECK_EQ(deviceId(), audio_input_capabilities->device_id);

  if (audio_input_capabilities->is_valid) {
    platform_capabilities_.channel_count = {1,
                                            audio_input_capabilities->channels};

    platform_capabilities_.sample_rate = {
        std::min(media::WebRtcAudioProcessingSampleRateHz(),
                 audio_input_capabilities->sample_rate),
        std::max(media::WebRtcAudioProcessingSampleRateHz(),
                 audio_input_capabilities->sample_rate)};
    double fallback_latency = kFallbackAudioLatencyMs / 1000;
    platform_capabilities_.latency = {
        std::min(fallback_latency,
                 audio_input_capabilities->latency.InSecondsF()),
        std::max(fallback_latency,
                 audio_input_capabilities->latency.InSecondsF())};
  }
}

MediaTrackCapabilities* InputDeviceInfo::getCapabilities() const {
  MediaTrackCapabilities* capabilities = MediaTrackCapabilities::Create();

  // If label is null, permissions have not been given and no capabilities
  // should be returned. Also, if the device is marked as not available, it
  // does not expose any capabilities.
  if (label().empty() || !platform_capabilities_.is_available) {
    return capabilities;
  }

  capabilities->setDeviceId(deviceId());
  capabilities->setGroupId(groupId());

  if (DeviceType() == mojom::blink::MediaDeviceType::kMediaAudioInput) {
    capabilities->setEchoCancellation({true, false});
    capabilities->setAutoGainControl({true, false});
    capabilities->setNoiseSuppression({true, false});
    capabilities->setVoiceIsolation({true, false});
    // Sample size.
    LongRange* sample_size = LongRange::Create();
    sample_size->setMin(
        media::SampleFormatToBitsPerChannel(media::kSampleFormatS16));
    sample_size->setMax(
        media::SampleFormatToBitsPerChannel(media::kSampleFormatS16));
    capabilities->setSampleSize(sample_size);
    // Channel count.
    if (!platform_capabilities_.channel_count.empty()) {
      LongRange* channel_count = LongRange::Create();
      channel_count->setMin(platform_capabilities_.channel_count[0]);
      channel_count->setMax(platform_capabilities_.channel_count[1]);
      capabilities->setChannelCount(channel_count);
    }
    // Sample rate.
    if (!platform_capabilities_.sample_rate.empty()) {
      LongRange* sample_rate = LongRange::Create();
      sample_rate->setMin(platform_capabilities_.sample_rate[0]);
      sample_rate->setMax(platform_capabilities_.sample_rate[1]);
      capabilities->setSampleRate(sample_rate);
    }
    // Latency.
    if (!platform_capabilities_.latency.empty()) {
      DoubleRange* latency = DoubleRange::Create();
      latency->setMin(platform_capabilities_.latency[0]);
      latency->setMax(platform_capabilities_.latency[1]);
      capabilities->setLatency(latency);
    }
  }

  if (DeviceType() == mojom::blink::MediaDeviceType::kMediaVideoInput) {
    if (!platform_capabilities_.width.empty()) {
      LongRange* width = LongRange::Create();
      width->setMin(platform_capabilities_.width[0]);
      width->setMax(platform_capabilities_.width[1]);
      capabilities->setWidth(width);
    }
    if (!platform_capabilities_.height.empty()) {
      LongRange* height = LongRange::Create();
      height->setMin(platform_capabilities_.height[0]);
      height->setMax(platform_capabilities_.height[1]);
      capabilities->setHeight(height);
    }
    if (!platform_capabilities_.aspect_ratio.empty()) {
      DoubleRange* aspect_ratio = DoubleRange::Create();
      aspect_ratio->setMin(platform_capabilities_.aspect_ratio[0]);
      aspect_ratio->setMax(platform_capabilities_.aspect_ratio[1]);
      capabilities->setAspectRatio(aspect_ratio);
    }
    if (!platform_capabilities_.frame_rate.empty()) {
      DoubleRange* frame_rate = DoubleRange::Create();
      frame_rate->setMin(platform_capabilities_.frame_rate[0]);
      frame_rate->setMax(platform_capabilities_.frame_rate[1]);
      capabilities->setFrameRate(frame_rate);
    }
    Vector<String> facing_mode;
    switch (platform_capabilities_.facing_mode) {
      case MediaStreamTrackPlatform::FacingMode::kUser:
        facing_mode.push_back("user");
        break;
      case MediaStreamTrackPlatform::FacingMode::kEnvironment:
        facing_mode.push_back("environment");
        break;
      case MediaStreamTrackPlatform::FacingMode::kLeft:
        facing_mode.push_back("left");
        break;
      case MediaStreamTrackPlatform::FacingMode::kRight:
        facing_mode.push_back("right");
        break;
      case MediaStreamTrackPlatform::FacingMode::kNone:
        break;
    }
    capabilities->setFacingMode(facing_mode);
    capabilities->setResizeMode({WebMediaStreamTrack::kResizeModeNone,
                                 WebMediaStreamTrack::kResizeModeRescale});
  }
  return capabilities;
}

}  // namespace blink
```