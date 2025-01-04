Response:
The user wants me to analyze the provided C++ source code file `user_media_processor.cc` from the Chromium Blink engine.

Here's a breakdown of what the user expects:

1. **Functionality Summary:** Describe what this code does.
2. **Relationship with Web Technologies:** Explain how this C++ code interacts with JavaScript, HTML, and CSS. Provide concrete examples.
3. **Logical Inference:** If the code performs logical reasoning, illustrate this with hypothetical inputs and outputs.
4. **Common Usage Errors:** Identify potential mistakes developers might make when using related APIs.
5. **Debugging Guidance:** Explain how a user action could lead to this code being executed, offering debugging tips.
6. **Part 1 Summary:**  Provide a concise summary of the functionality covered in this specific code snippet (since it's part 1 of 3).

**Mental Model:**

This file seems to be responsible for handling `getUserMedia` requests, which are initiated by JavaScript in web pages. It involves interacting with the underlying operating system to access audio and video input devices. The code likely manages device selection, applies constraints specified in the `getUserMedia` call, and manages the lifecycle of media streams.

**High-Level Plan:**

1. **Scan the code for key classes and functions:** Look for class names like `UserMediaProcessor`, `RequestInfo`, and functions related to setting up audio and video input.
2. **Identify the core purpose:** Determine the main responsibility of this file in the context of `getUserMedia`.
3. **Analyze interactions with web technologies:** Consider how JavaScript calls `getUserMedia`, how constraints are passed, and how the resulting media streams are used in HTML and potentially styled with CSS.
4. **Look for logical decision points:** Identify parts of the code where decisions are made based on input parameters or device capabilities.
5. **Think about potential errors:** Consider scenarios where permissions are denied, devices are not found, or constraints cannot be satisfied.
6. **Trace user actions:** Imagine a user clicking a button that triggers a `getUserMedia` call and follow the execution flow.
7. **Focus on the provided snippet:**  Since this is part 1, concentrate on the functionalities visible in this section.
```
这是目录为blink/renderer/modules/mediastream/user_media_processor.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

根据提供的代码片段，`user_media_processor.cc` 文件的主要功能是 **处理 `getUserMedia` API 的请求**。它负责协调获取用户指定的媒体输入（例如摄像头和麦克风），并根据请求的约束条件进行配置和管理。

以下是更详细的功能分解，并结合了与 JavaScript、HTML 和 CSS 的关系，以及可能的逻辑推理、用户错误和调试线索：

**功能列举:**

1. **接收和管理 `getUserMedia` 请求:** 该文件中的类 `UserMediaProcessor` 接收由 JavaScript 发起的 `navigator.mediaDevices.getUserMedia()` 请求。它会创建一个 `RequestInfo` 对象来存储和管理与特定请求相关的信息。
2. **处理音频输入:**  `SetupAudioInput()` 函数负责处理音频输入请求。它会检查请求的约束条件，并与底层的媒体设备交互来获取音频输入能力。
3. **处理视频输入 (初步):** 虽然在提供的部分没有详细的视频处理逻辑，但可以推断出它也会有相应的函数（后续部分可能会有 `SetupVideoInput()` 的实现）来处理视频输入请求，获取视频设备能力。
4. **约束条件处理:**  代码中包含了对 `MediaConstraints` 的处理，例如在 `SetupAudioInput` 中检查音频约束条件。它会根据 JavaScript 中指定的约束（如音频采样率、声道数等）来配置音频设备。
5. **设备能力查询:**  `GetMediaDevicesDispatcher()->GetAudioInputCapabilities()` 表明该文件会与一个负责枚举和查询媒体设备能力的模块进行交互。
6. **异步操作管理:**  由于媒体设备的访问和配置可能需要时间，该文件使用回调函数（例如 `WTF::BindOnce`）来处理异步操作的结果。
7. **日志记录和性能监控:** 代码中使用了 `base::logging` 和 `base::metrics::histogram_functions` 进行日志记录和性能指标收集，例如记录摄像头能力 (`LogCameraCaptureCapability`)。
8. **错误处理:** 代码中定义了 `MediaStreamRequestResult` 枚举，用于表示 `getUserMedia` 请求的不同结果，包括成功和各种错误情况（例如权限被拒绝、硬件未找到等）。 `MediaStreamRequestResultToString` 函数用于将这些结果转换为字符串进行日志记录。
9. **多线程处理:**  使用了 `scoped_refptr<base::SingleThreadTaskRunner>`，表明某些操作可能需要在特定的线程上执行。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  `getUserMedia` API 是 JavaScript 的一部分。当网页中的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia(constraints)` 时，这个调用最终会触发 Blink 引擎中的 `UserMediaProcessor` 来处理请求。`constraints` 对象中包含了请求的音频和/或视频类型以及各种约束条件。
   * **示例:**
     ```javascript
     navigator.mediaDevices.getUserMedia({ audio: true, video: { width: 640, height: 480 } })
       .then(function(stream) {
         // 使用 stream
       })
       .catch(function(err) {
         // 处理错误
         console.error("Error accessing media devices:", err);
       });
     ```
* **HTML:**  HTML 主要用于呈现媒体流。一旦 `getUserMedia` 成功获取到 `MediaStream` 对象，JavaScript 可以将其分配给 HTML5 `<video>` 或 `<audio>` 元素的 `srcObject` 属性，从而在网页上显示或播放媒体流。
   * **示例:**
     ```html
     <video id="myVideo" autoplay playsinline></video>
     <script>
       navigator.mediaDevices.getUserMedia({ video: true })
         .then(function(stream) {
           const videoElement = document.getElementById('myVideo');
           videoElement.srcObject = stream;
         });
     </script>
     ```
* **CSS:** CSS 可以用于控制 `<video>` 和 `<audio>` 元素的样式，例如大小、边框、滤镜等。虽然 CSS 不直接参与 `getUserMedia` 的处理过程，但它负责最终呈现媒体流的外观。
   * **示例:**
     ```css
     #myVideo {
       width: 320px;
       height: 240px;
       border: 1px solid black;
     }
     ```

**逻辑推理 (假设输入与输出):**

假设 JavaScript 发起以下 `getUserMedia` 请求：

**假设输入 (JavaScript Constraints):**

```javascript
{
  audio: {
    echoCancellation: true
  },
  video: true
}
```

**逻辑推理 (基于代码片段):**

1. `ProcessRequest` 被调用，`current_request_info_` 被创建，包含请求 ID 和约束信息。
2. 由于 `audio` 为 `true`，`SetupAudioInput` 被调用。
3. `SetupAudioInput` 解析音频约束，发现需要开启回声消除 (`echoCancellation: true`)。
4. `GetMediaDevicesDispatcher()->GetAudioInputCapabilities()` 被调用，请求获取可用的音频输入设备及其能力。

**可能的输出 (假设设备支持回声消除):**

* `SelectAudioDeviceSettings` 被调用，接收到音频设备能力列表。
* `SelectAudioSettings` 被调用，根据请求的约束和设备能力，选择合适的音频设备和配置。
* (在后续部分) 如果视频也成功获取，则会创建一个包含音频和视频轨道的 `MediaStream` 对象，并通过回调返回给 JavaScript。

**用户或编程常见的使用错误:**

1. **未处理权限请求:**  `getUserMedia` 需要用户授权访问媒体设备。如果开发者没有正确处理权限被拒绝的情况，可能会导致网页功能异常。
   * **示例:**  JavaScript 代码中缺少 `.catch()` 块来处理 `getUserMedia` promise 被拒绝的情况。
2. **错误的约束条件:**  指定的约束条件与用户的硬件不匹配，例如请求一个不存在的摄像头 ID 或不支持的音频采样率。这会导致 `CONSTRAINT_NOT_SATISFIED` 错误。
   * **示例:**  请求 `{ video: { deviceId: "non-existent-camera-id" } }`。
3. **在不安全的上下文中使用 `getUserMedia`:**  `getUserMedia` 通常需要在安全上下文 (HTTPS) 中使用。在非安全上下文中使用可能会导致请求失败。
4. **过早访问媒体流对象:**  在 `getUserMedia` 的 Promise resolve 之前就尝试访问 `MediaStream` 对象可能会导致错误。
5. **忘记停止媒体流:**  在不再需要媒体流时，没有调用 `stream.getTracks().forEach(track => track.stop())` 来释放资源，可能导致设备占用或其他问题。

**用户操作如何到达这里 (调试线索):**

1. **用户访问包含 `getUserMedia` 调用的网页:** 用户在浏览器中打开一个网页，该网页的 JavaScript 代码中使用了 `navigator.mediaDevices.getUserMedia()`。
2. **JavaScript 代码执行 `getUserMedia`:** 当网页加载或用户执行某些操作（例如点击按钮）时，JavaScript 代码会调用 `getUserMedia`。
3. **浏览器提示用户授权:**  浏览器会弹出一个权限请求，询问用户是否允许该网站访问摄像头和/或麦克风。
4. **用户授权或拒绝:**
   * **授权:** 如果用户点击“允许”，浏览器会将请求传递给 Blink 引擎的 `UserMediaProcessor` 进行处理。
   * **拒绝:** 如果用户点击“拒绝”，`getUserMedia` 的 Promise 会被 reject，JavaScript 代码中的 `.catch()` 块会被执行。
5. **Blink 引擎处理请求:** `UserMediaProcessor` 接收到请求，开始查询和配置媒体设备。

**作为调试线索:**

* **检查浏览器的开发者工具控制台:** 查看是否有与 `getUserMedia` 相关的错误信息或警告。
* **查看浏览器的权限设置:** 确认网站是否有访问摄像头和麦克风的权限。
* **使用 `chrome://webrtc-internals`:**  这个 Chrome 内部页面提供了关于 WebRTC 和 MediaStream 的详细信息，可以查看 `getUserMedia` 请求的详细过程和结果。
* **在 `user_media_processor.cc` 中添加日志:**  开发者可以在 `user_media_processor.cc` 中添加额外的 `LOG(INFO)` 或 `DVLOG` 语句来跟踪代码执行流程，查看关键变量的值，以便更深入地理解请求的处理过程。例如，可以记录 `request->AudioConstraints().ToString()` 的值来查看 JavaScript 传递的约束条件。

**第 1 部分功能归纳:**

在提供的代码片段中，`user_media_processor.cc` 的主要功能是 **接收和初步处理来自 JavaScript 的 `getUserMedia` 音频输入请求**。它负责：

* 创建和管理 `UserMediaRequest` 的上下文 (`RequestInfo`)。
* 解析音频相关的约束条件。
* 请求获取可用的音频输入设备及其能力。
* 为后续的音频设备选择和配置做准备。
```
Prompt: 
```
这是目录为blink/renderer/modules/mediastream/user_media_processor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/user_media_processor.h"

#include <stddef.h>

#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/types/optional_util.h"
#include "build/build_config.h"
#include "media/base/audio_parameters.h"
#include "media/capture/video_capture_types.h"
#include "media/webrtc/constants.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/mediastream/media_stream_controls.h"
#include "third_party/blink/public/common/mediastream/media_stream_request.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_source.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/modules/mediastream/web_media_stream_device_observer.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/local_media_stream_audio_source.h"
#include "third_party/blink/renderer/modules/mediastream/local_video_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_audio_processor.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_audio.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/processed_local_audio_source.h"
#include "third_party/blink/renderer/modules/mediastream/scoped_media_stream_tracer.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

using blink::mojom::MediaStreamRequestResult;
using blink::mojom::MediaStreamType;
using EchoCancellationType =
    blink::AudioProcessingProperties::EchoCancellationType;
using AudioSourceErrorCode = media::AudioCapturerSource::ErrorCode;

namespace {

void LogCameraCaptureCapability(CameraCaptureCapability capability) {
  base::UmaHistogramEnumeration(
      "Media.MediaDevices.GetUserMedia.CameraCaptureCapability", capability);
}

const char* MediaStreamRequestResultToString(MediaStreamRequestResult value) {
  switch (value) {
    case MediaStreamRequestResult::OK:
      return "OK";
    case MediaStreamRequestResult::PERMISSION_DENIED:
      return "PERMISSION_DENIED";
    case MediaStreamRequestResult::PERMISSION_DISMISSED:
      return "PERMISSION_DISMISSED";
    case MediaStreamRequestResult::INVALID_STATE:
      return "INVALID_STATE";
    case MediaStreamRequestResult::NO_HARDWARE:
      return "NO_HARDWARE";
    case MediaStreamRequestResult::INVALID_SECURITY_ORIGIN:
      return "INVALID_SECURITY_ORIGIN";
    case MediaStreamRequestResult::TAB_CAPTURE_FAILURE:
      return "TAB_CAPTURE_FAILURE";
    case MediaStreamRequestResult::SCREEN_CAPTURE_FAILURE:
      return "SCREEN_CAPTURE_FAILURE";
    case MediaStreamRequestResult::CAPTURE_FAILURE:
      return "CAPTURE_FAILURE";
    case MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED:
      return "CONSTRAINT_NOT_SATISFIED";
    case MediaStreamRequestResult::TRACK_START_FAILURE_AUDIO:
      return "TRACK_START_FAILURE_AUDIO";
    case MediaStreamRequestResult::TRACK_START_FAILURE_VIDEO:
      return "TRACK_START_FAILURE_VIDEO";
    case MediaStreamRequestResult::NOT_SUPPORTED:
      return "NOT_SUPPORTED";
    case MediaStreamRequestResult::FAILED_DUE_TO_SHUTDOWN:
      return "FAILED_DUE_TO_SHUTDOWN";
    case MediaStreamRequestResult::KILL_SWITCH_ON:
      return "KILL_SWITCH_ON";
    case MediaStreamRequestResult::SYSTEM_PERMISSION_DENIED:
      return "SYSTEM_PERMISSION_DENIED";
    case MediaStreamRequestResult::DEVICE_IN_USE:
      return "DEVICE_IN_USE";
    case MediaStreamRequestResult::REQUEST_CANCELLED:
      return "REQUEST_CANCELLED";
    case MediaStreamRequestResult::START_TIMEOUT:
      return "START_TIMEOUT";
    case MediaStreamRequestResult::NUM_MEDIA_REQUEST_RESULTS:
      return "NUM_MEDIA_REQUEST_RESULTS";
    default:
      NOTREACHED();
  }
}

void SendLogMessage(const std::string& message) {
  blink::WebRtcLogMessage("UMP::" + message);
}

void MaybeLogStreamDevice(const int32_t& request_id,
                          const String& label,
                          const std::optional<MediaStreamDevice>& device) {
  if (!device.has_value()) {
    return;
  }

  SendLogMessage(base::StringPrintf(
      "OnStreamsGenerated({request_id=%d}, {label=%s}, {device=[id: %s, "
      "name: "
      "%s]})",
      request_id, label.Utf8().c_str(), device->id.c_str(),
      device->name.c_str()));
}

std::string GetTrackLogString(MediaStreamComponent* component,
                              bool is_pending) {
  String str = String::Format(
      "StartAudioTrack({track=[id: %s, enabled: %d]}, "
      "{is_pending=%d})",
      component->Id().Utf8().c_str(), component->Enabled(), is_pending);
  return str.Utf8();
}

std::string GetTrackSourceLogString(blink::MediaStreamAudioSource* source) {
  const MediaStreamDevice& device = source->device();
  StringBuilder builder;
  builder.AppendFormat("StartAudioTrack(source: {session_id=%s}, ",
                       device.session_id().ToString().c_str());
  builder.AppendFormat("{is_local_source=%d}, ", source->is_local_source());
  builder.AppendFormat("{device=[id: %s", device.id.c_str());
  if (device.group_id.has_value()) {
    builder.AppendFormat(", group_id: %s", device.group_id.value().c_str());
  }
  builder.AppendFormat(", name: %s", device.name.c_str());
  builder.Append(String("]})"));
  return builder.ToString().Utf8();
}

std::string GetOnTrackStartedLogString(
    blink::WebPlatformMediaStreamSource* source,
    MediaStreamRequestResult result) {
  const MediaStreamDevice& device = source->device();
  String str = String::Format("OnTrackStarted({session_id=%s}, {result=%s})",
                              device.session_id().ToString().c_str(),
                              MediaStreamRequestResultToString(result));
  return str.Utf8();
}

bool IsSameDevice(const MediaStreamDevice& device,
                  const MediaStreamDevice& other_device) {
  return device.id == other_device.id && device.type == other_device.type &&
         device.session_id() == other_device.session_id();
}

bool IsSameSource(MediaStreamSource* source, MediaStreamSource* other_source) {
  WebPlatformMediaStreamSource* const source_extra_data =
      source->GetPlatformSource();
  const MediaStreamDevice& device = source_extra_data->device();

  WebPlatformMediaStreamSource* const other_source_extra_data =
      other_source->GetPlatformSource();
  const MediaStreamDevice& other_device = other_source_extra_data->device();

  return IsSameDevice(device, other_device);
}

void SurfaceAudioProcessingSettings(MediaStreamSource* source) {
  auto* source_impl =
      static_cast<blink::MediaStreamAudioSource*>(source->GetPlatformSource());

  // If the source is a processed source, get the properties from it.
  if (auto* processed_source =
          blink::ProcessedLocalAudioSource::From(source_impl)) {
    blink::AudioProcessingProperties properties =
        processed_source->audio_processing_properties();

    source->SetAudioProcessingProperties(
        properties.echo_cancellation_type !=
            EchoCancellationType::kEchoCancellationDisabled,
        properties.auto_gain_control, properties.noise_suppression,
        properties.voice_isolation ==
            AudioProcessingProperties::VoiceIsolationType::
                kVoiceIsolationEnabled);
  } else {
    // If the source is not a processed source, it could still support system
    // echo cancellation or voice. Surface that if it does.
    media::AudioParameters params = source_impl->GetAudioParameters();
    source->SetAudioProcessingProperties(
        params.IsValid() &&
            (params.effects() & media::AudioParameters::ECHO_CANCELLER),
        false, false,
        params.IsValid() &&
            (params.effects() &
             media::AudioParameters::VOICE_ISOLATION_SUPPORTED) &&
            (params.effects() & media::AudioParameters::VOICE_ISOLATION));
  }
}

// TODO(crbug.com/704136): Check all places where this helper is used.
// Change their types from using std::vector to WTF::Vector, so this
// extra conversion round is not needed.
template <typename T>
std::vector<T> ToStdVector(const Vector<T>& format_vector) {
  std::vector<T> formats;
  base::ranges::copy(format_vector, std::back_inserter(formats));
  return formats;
}

Vector<blink::VideoInputDeviceCapabilities> ToVideoInputDeviceCapabilities(
    const Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>&
        input_capabilities) {
  Vector<blink::VideoInputDeviceCapabilities> capabilities;
  for (const auto& capability : input_capabilities) {
    capabilities.emplace_back(capability->device_id, capability->group_id,
                              capability->control_support, capability->formats,
                              capability->facing_mode);
  }

  return capabilities;
}

String ErrorCodeToString(MediaStreamRequestResult result) {
  switch (result) {
    case MediaStreamRequestResult::PERMISSION_DENIED:
      return "Permission denied";
    case MediaStreamRequestResult::PERMISSION_DISMISSED:
      return "Permission dismissed";
    case MediaStreamRequestResult::INVALID_STATE:
      return "Invalid state";
    case MediaStreamRequestResult::NO_HARDWARE:
      return "Requested device not found";
    case MediaStreamRequestResult::INVALID_SECURITY_ORIGIN:
      return "Invalid security origin";
    case MediaStreamRequestResult::TAB_CAPTURE_FAILURE:
      return "Error starting tab capture";
    case MediaStreamRequestResult::SCREEN_CAPTURE_FAILURE:
      return "Error starting screen capture";
    case MediaStreamRequestResult::CAPTURE_FAILURE:
      return "Error starting capture";
    case MediaStreamRequestResult::TRACK_START_FAILURE_AUDIO:
      return "Could not start audio source";
    case MediaStreamRequestResult::TRACK_START_FAILURE_VIDEO:
      return "Could not start video source";
    case MediaStreamRequestResult::NOT_SUPPORTED:
      return "Not supported";
    case MediaStreamRequestResult::FAILED_DUE_TO_SHUTDOWN:
      return "Failed due to shutdown";
    case MediaStreamRequestResult::KILL_SWITCH_ON:
      return "";
    case MediaStreamRequestResult::SYSTEM_PERMISSION_DENIED:
      return "Permission denied by system";
    case MediaStreamRequestResult::DEVICE_IN_USE:
      return "Device in use";
    case MediaStreamRequestResult::REQUEST_CANCELLED:
      return "Request was cancelled";
    case MediaStreamRequestResult::START_TIMEOUT:
      return "Timeout starting video source";
    default:
      NOTREACHED();
  }
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS) && !BUILDFLAG(IS_FUCHSIA)
// Returns true if `kGetUserMediaDeferredDeviceSettingsSelection` is enabled,
// but gates it on `kCameraMicPreview` also being being enabled. This only
// applies to user media requests.
bool ShouldDeferDeviceSettingsSelection(
    UserMediaRequestType request_type,
    mojom::blink::MediaStreamType media_stream_type,
    const ExecutionContext* execution_context) {
  // The new behavior shouldn't be applied for anything except for user media
  // requests.
  // TODO(crbug.com/341136036): Find a better long-term solution for keeping
  // both code paths happy.
  if (request_type != UserMediaRequestType::kUserMedia) {
    return false;
  }

  // The new behavior shouldn't be applied for anything except for device
  // capture streams
  // TODO(crbug.com/343505105): Find a better long-term solution for keeping
  // both code paths happy.
  if (media_stream_type !=
          mojom::blink::MediaStreamType::DEVICE_AUDIO_CAPTURE &&
      media_stream_type !=
          mojom::blink::MediaStreamType::DEVICE_VIDEO_CAPTURE) {
    return false;
  }

  if (RuntimeEnabledFeatures::MediaPreviewsOptOutEnabled(execution_context)) {
    return false;
  }

  // Enables camera preview in permission bubble and site settings.
  return base::FeatureList::IsEnabled(features::kCameraMicPreview) &&
         base::FeatureList::IsEnabled(
             features::kGetUserMediaDeferredDeviceSettingsSelection);
}
#else
bool ShouldDeferDeviceSettingsSelection(
    UserMediaRequestType request_type,
    mojom::blink::MediaStreamType media_stream_type,
    const ExecutionContext* execution_context) {
  return false;
}
#endif

}  // namespace

// Class for storing state of the the processing of getUserMedia requests.
class UserMediaProcessor::RequestInfo final
    : public GarbageCollected<UserMediaProcessor::RequestInfo> {
 public:
  using ResourcesReady =
      base::OnceCallback<void(RequestInfo* request_info,
                              MediaStreamRequestResult result,
                              const String& result_name)>;
  enum class State {
    kNotSentForGeneration,
    kSentForGeneration,
    kGenerated,
  };

  explicit RequestInfo(UserMediaRequest* request);

  void StartAudioTrack(MediaStreamComponent* component, bool is_pending);
  MediaStreamComponent* CreateAndStartVideoTrack(MediaStreamSource* source);

  // Triggers |callback| when all sources used in this request have either
  // successfully started, or a source has failed to start.
  void CallbackOnTracksStarted(ResourcesReady callback);

  // Called when a local audio source has finished (or failed) initializing.
  void OnAudioSourceStarted(blink::WebPlatformMediaStreamSource* source,
                            MediaStreamRequestResult result,
                            const String& result_name);

  UserMediaRequest* request() { return request_.Get(); }
  int32_t request_id() const { return request_->request_id(); }

  State state() const { return state_; }
  void set_state(State state) { state_ = state; }

  const blink::AudioCaptureSettings& audio_capture_settings() const {
    return audio_capture_settings_;
  }
  void SetAudioCaptureSettings(const blink::AudioCaptureSettings& settings,
                               bool is_content_capture) {
    DCHECK(settings.HasValue());
    is_audio_content_capture_ = is_content_capture;
    audio_capture_settings_ = settings;
  }
  const blink::VideoCaptureSettings& video_capture_settings() const {
    return video_capture_settings_;
  }
  bool is_video_content_capture() const {
    return video_capture_settings_.HasValue() && is_video_content_capture_;
  }
  bool is_video_device_capture() const {
    return video_capture_settings_.HasValue() && !is_video_content_capture_;
  }
  void SetVideoCaptureSettings(const blink::VideoCaptureSettings& settings,
                               bool is_content_capture) {
    DCHECK(settings.HasValue());
    is_video_content_capture_ = is_content_capture;
    video_capture_settings_ = settings;
  }

  void SetDevices(mojom::blink::StreamDevicesSetPtr stream_devices_set) {
    stream_devices_set_.stream_devices =
        std::move(stream_devices_set->stream_devices);
  }

  void AddNativeVideoFormats(const String& device_id,
                             Vector<media::VideoCaptureFormat> formats) {
    video_formats_map_.insert(device_id, std::move(formats));
  }

  // Do not store or delete the returned pointer.
  Vector<media::VideoCaptureFormat>* GetNativeVideoFormats(
      const String& device_id) {
    auto it = video_formats_map_.find(device_id);
    CHECK(it != video_formats_map_.end());
    return &it->value;
  }

  void InitializeWebStreams(
      const String& label,
      const MediaStreamsComponentsVector& streams_components) {
    DCHECK(!streams_components.empty());

    // TODO(crbug.com/1313021): Refactor descriptors to make the assumption of
    // at most one audio and video track explicit.
    descriptors_ = MakeGarbageCollected<MediaStreamDescriptorVector>();
    for (const MediaStreamComponents* tracks : streams_components) {
      descriptors_->push_back(MakeGarbageCollected<MediaStreamDescriptor>(
          label,
          !tracks->audio_track_
              ? MediaStreamComponentVector()
              : MediaStreamComponentVector{tracks->audio_track_},
          !tracks->video_track_
              ? MediaStreamComponentVector()
              : MediaStreamComponentVector{tracks->video_track_}));
    }
  }

  void StartTrace(const String& event_name) {
    traces_.insert(event_name,
                   std::make_unique<ScopedMediaStreamTracer>(event_name));
  }

  void EndTrace(const String& event_name) { traces_.erase(event_name); }

  bool CanStartTracks() const {
    return video_formats_map_.size() == count_video_devices();
  }

  MediaStreamDescriptorVector* descriptors() {
    DCHECK(descriptors_);
    return descriptors_.Get();
  }

  const mojom::blink::StreamDevicesSet& devices_set() const {
    return stream_devices_set_;
  }

  StreamControls* stream_controls() { return &stream_controls_; }

  bool is_processing_user_gesture() const {
    return request_->has_transient_user_activation();
  }

  bool pan_tilt_zoom_allowed() const { return pan_tilt_zoom_allowed_; }
  void set_pan_tilt_zoom_allowed(bool pan_tilt_zoom_allowed) {
    pan_tilt_zoom_allowed_ = pan_tilt_zoom_allowed;
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(request_);
    visitor->Trace(descriptors_);
    visitor->Trace(sources_);
  }

  const Vector<AudioCaptureSettings>& eligible_audio_settings() {
    return eligible_audio_capture_settings_;
  }

  void SetEligibleAudioCaptureSettings(Vector<AudioCaptureSettings> settings) {
    eligible_audio_capture_settings_ = std::move(settings);
  }

  const Vector<VideoCaptureSettings>& eligible_video_settings() {
    return eligible_video_capture_settings_;
  }

  void SetEligibleVideoCaptureSettings(Vector<VideoCaptureSettings> settings) {
    eligible_video_capture_settings_ = std::move(settings);
  }

 private:
  void OnTrackStarted(blink::WebPlatformMediaStreamSource* source,
                      MediaStreamRequestResult result,
                      const blink::WebString& result_name);

  // Checks if the sources for all tracks have been started and if so,
  // invoke the |ready_callback_|.  Note that the caller should expect
  // that |this| might be deleted when the function returns.
  void CheckAllTracksStarted();

  size_t count_video_devices() const;

  Member<UserMediaRequest> request_;
  State state_ = State::kNotSentForGeneration;
  blink::AudioCaptureSettings audio_capture_settings_;
  bool is_audio_content_capture_ = false;
  blink::VideoCaptureSettings video_capture_settings_;
  bool is_video_content_capture_ = false;
  Member<MediaStreamDescriptorVector> descriptors_;
  StreamControls stream_controls_;
  ResourcesReady ready_callback_;
  MediaStreamRequestResult request_result_ = MediaStreamRequestResult::OK;
  String request_result_name_;
  // Sources used in this request.
  HeapVector<Member<MediaStreamSource>> sources_;
  HashMap<String, std::unique_ptr<ScopedMediaStreamTracer>> traces_;
  Vector<blink::WebPlatformMediaStreamSource*> sources_waiting_for_callback_;
  HashMap<String, Vector<media::VideoCaptureFormat>> video_formats_map_;
  mojom::blink::StreamDevicesSet stream_devices_set_;
  bool pan_tilt_zoom_allowed_ = false;
  Vector<AudioCaptureSettings> eligible_audio_capture_settings_;
  Vector<VideoCaptureSettings> eligible_video_capture_settings_;
};

// TODO(guidou): Initialize request_result_name_ as a null WTF::String.
// https://crbug.com/764293
UserMediaProcessor::RequestInfo::RequestInfo(UserMediaRequest* request)
    : request_(request), request_result_name_("") {}

void UserMediaProcessor::RequestInfo::StartAudioTrack(
    MediaStreamComponent* component,
    bool is_pending) {
  DCHECK(component->GetSourceType() == MediaStreamSource::kTypeAudio);
  DCHECK(request()->Audio());
#if DCHECK_IS_ON()
  DCHECK(audio_capture_settings_.HasValue());
#endif
  SendLogMessage(GetTrackLogString(component, is_pending));
  auto* native_source = MediaStreamAudioSource::From(component->Source());
  SendLogMessage(GetTrackSourceLogString(native_source));
  // Add the source as pending since OnTrackStarted will expect it to be there.
  sources_waiting_for_callback_.push_back(native_source);

  sources_.push_back(component->Source());
  bool connected = native_source->ConnectToInitializedTrack(component);
  if (!is_pending) {
    OnTrackStarted(native_source,
                   connected
                       ? MediaStreamRequestResult::OK
                       : MediaStreamRequestResult::TRACK_START_FAILURE_AUDIO,
                   "");
  }
}

MediaStreamComponent* UserMediaProcessor::RequestInfo::CreateAndStartVideoTrack(
    MediaStreamSource* source) {
  DCHECK(source->GetType() == MediaStreamSource::kTypeVideo);
  DCHECK(request()->Video());
  DCHECK(video_capture_settings_.HasValue());
  SendLogMessage(base::StringPrintf(
      "UMP::RI::CreateAndStartVideoTrack({request_id=%d})", request_id()));

  MediaStreamVideoSource* native_source =
      MediaStreamVideoSource::GetVideoSource(source);
  DCHECK(native_source);
  sources_.push_back(source);
  sources_waiting_for_callback_.push_back(native_source);
  return MediaStreamVideoTrack::CreateVideoTrack(
      native_source, video_capture_settings_.track_adapter_settings(),
      video_capture_settings_.noise_reduction(), is_video_content_capture_,
      video_capture_settings_.min_frame_rate(),
      video_capture_settings_.image_capture_device_settings()
          ? &*video_capture_settings_.image_capture_device_settings()
          : nullptr,
      pan_tilt_zoom_allowed(),
      WTF::BindOnce(&UserMediaProcessor::RequestInfo::OnTrackStarted,
                    WrapWeakPersistent(this)),
      true);
}

void UserMediaProcessor::RequestInfo::CallbackOnTracksStarted(
    ResourcesReady callback) {
  DCHECK(ready_callback_.is_null());
  ready_callback_ = std::move(callback);
  CheckAllTracksStarted();
}

void UserMediaProcessor::RequestInfo::OnTrackStarted(
    blink::WebPlatformMediaStreamSource* source,
    MediaStreamRequestResult result,
    const blink::WebString& result_name) {
  SendLogMessage(GetOnTrackStartedLogString(source, result));
  auto it = base::ranges::find(sources_waiting_for_callback_, source);
  CHECK(it != sources_waiting_for_callback_.end(), base::NotFatalUntil::M130);
  sources_waiting_for_callback_.erase(it);
  // All tracks must be started successfully. Otherwise the request is a
  // failure.
  if (result != MediaStreamRequestResult::OK) {
    request_result_ = result;
    request_result_name_ = result_name;
  }

  if (IsAudioInputMediaType(source->device().type)) {
    EndTrace("CreateAudioTrack");
  } else {
    EndTrace("CreateVideoTrack");
  }
  CheckAllTracksStarted();
}

void UserMediaProcessor::RequestInfo::CheckAllTracksStarted() {
  if (ready_callback_ && sources_waiting_for_callback_.empty()) {
    std::move(ready_callback_).Run(this, request_result_, request_result_name_);
    // NOTE: |this| might now be deleted.
  }
}

size_t UserMediaProcessor::RequestInfo::count_video_devices() const {
  return base::ranges::count_if(
      stream_devices_set_.stream_devices.begin(),
      stream_devices_set_.stream_devices.end(),
      [](const mojom::blink::StreamDevicesPtr& stream_devices) {
        return stream_devices->video_device.has_value();
      });
}

void UserMediaProcessor::RequestInfo::OnAudioSourceStarted(
    blink::WebPlatformMediaStreamSource* source,
    MediaStreamRequestResult result,
    const String& result_name) {
  // Check if we're waiting to be notified of this source.  If not, then we'll
  // ignore the notification.
  if (base::Contains(sources_waiting_for_callback_, source)) {
    OnTrackStarted(source, result, result_name);
  }
}

UserMediaProcessor::UserMediaProcessor(
    LocalFrame* frame,
    MediaDevicesDispatcherCallback media_devices_dispatcher_cb,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : dispatcher_host_(frame->DomWindow()),
      media_devices_dispatcher_cb_(std::move(media_devices_dispatcher_cb)),
      frame_(frame),
      task_runner_(std::move(task_runner)) {}

UserMediaProcessor::~UserMediaProcessor() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Ensure StopAllProcessing() has been called by UserMediaClient.
  DCHECK(!current_request_info_ && !request_completed_cb_ &&
         !local_sources_.size());
}

UserMediaRequest* UserMediaProcessor::CurrentRequest() {
  return current_request_info_ ? current_request_info_->request() : nullptr;
}

void UserMediaProcessor::ProcessRequest(UserMediaRequest* request,
                                        base::OnceClosure callback) {
  DCHECK(!request_completed_cb_);
  DCHECK(!current_request_info_);
  request_completed_cb_ = std::move(callback);
  current_request_info_ = MakeGarbageCollected<RequestInfo>(request);
  SendLogMessage(
      base::StringPrintf("ProcessRequest({request_id=%d}, {audio=%d}, "
                         "{video=%d})",
                         current_request_info_->request_id(),
                         current_request_info_->request()->Audio(),
                         current_request_info_->request()->Video()));
  // TODO(guidou): Set up audio and video in parallel.
  if (current_request_info_->request()->Audio()) {
    SetupAudioInput();
    return;
  }
  SetupVideoInput();
}

void UserMediaProcessor::SetupAudioInput() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  DCHECK(current_request_info_->request()->Audio());

  UserMediaRequest* const request = current_request_info_->request();

  SendLogMessage(base::StringPrintf(
      "SetupAudioInput({request_id=%d}, {constraints=%s})",
      current_request_info_->request_id(),
      request->AudioConstraints().ToString().Utf8().c_str()));

  StreamControls* const stream_controls =
      current_request_info_->stream_controls();
  stream_controls->exclude_system_audio = request->exclude_system_audio();

  stream_controls->suppress_local_audio_playback =
      request->suppress_local_audio_playback();

  TrackControls& audio_controls = stream_controls->audio;
  audio_controls.stream_type =
      (request->MediaRequestType() == UserMediaRequestType::kAllScreensMedia)
          ? MediaStreamType::NO_SERVICE
          : request->AudioMediaStreamType();

  if (audio_controls.stream_type == MediaStreamType::DISPLAY_AUDIO_CAPTURE) {
    SelectAudioSettings(request, {blink::AudioDeviceCaptureCapability()});
    return;
  }

  if (blink::IsDeviceMediaType(audio_controls.stream_type)) {
    SendLogMessage(
        base::StringPrintf("SetupAudioInput({request_id=%d}) => "
                           "(Requesting device capabilities)",
                           current_request_info_->request_id()));
    current_request_info_->StartTrace("GetAudioInputCapabilities");
    GetMediaDevicesDispatcher()->GetAudioInputCapabilities(
        WTF::BindOnce(&UserMediaProcessor::SelectAudioDeviceSettings,
                      WrapWeakPersistent(this), WrapPersistent(request)));
  } else {
    if (!blink::IsAudioInputMediaType(audio_controls.stream_type)) {
      String failed_constraint_name = String(
          request->AudioConstraints().Basic().media_stream_source.GetName());
      MediaStreamRequestResult result =
          MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED;
      GetUserMediaRequestFailed(result, failed_constraint_name);
      return;
    }
    SelectAudioSettings(request, {blink::AudioDeviceCaptureCapability()});
  }
}

void UserMediaProcessor::SelectAudioDeviceSettings(
    UserMediaRequest* user_media_request,
    Vector<mojom::blink::AudioInputDeviceCapabilitiesPtr>
        audio_input_capabilities) {
  blink::AudioDeviceCaptureCapabilities capabilities;

  if (current_request_info_) {
    current_request_info_->EndTrace("GetAudioInputCapabilities");
  }

  for (const auto& device : audio_input_capabilities) {
    // Find the first occurrence of blink::ProcessedLocalAudioSource that
    // matches the same device ID as |device|. If more than one exists, any
    // such source will contain the same non-reconfigurable settings that limit
    // the associated capabilities.
    blink::MediaStreamAudioSource* audio_source = nullptr;
    auto it = base::ranges::find_if(
        local_sources_, [&device](MediaStreamSource* source) {
          DCHECK(source);
          MediaStreamAudioSource* platform_source =
              MediaStreamAudioSource::From(source);
          ProcessedLocalAudioSource* processed_source =
              ProcessedLocalAudioSource::From(platform_source);
          return processed_source && source->Id() == device->device_id;
        });
    if (it != local_sources_.end()) {
      WebPlatformMediaStreamSource* const source = (*it)->GetPlatformSource();
      if (source->device().type == MediaStreamType::DEVICE_AUDIO_CAPTURE) {
        audio_source = static_cast<MediaStreamAudioSource*>(source);
      }
    }
    if (audio_source) {
      capabilities.emplace_back(audio_source);
    } else {
      capabilities.emplace_back(device->device_id, device->group_id,
                                device->parameters);
    }
  }

  SelectAudioSettings(user_media_request, capabilities);
}

void UserMediaProcessor::SelectAudioSettings(
    UserMediaRequest* user_media_request,
    const blink::AudioDeviceCaptureCapabilities& capabilities) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // The frame might reload or |user_media_request| might be cancelled while
  // capabilities are queried. Do nothing if a different request is being
  // processed at this point.
  if (!IsCurrentRequestInfo(user_media_request)) {
    return;
  }

  DCHECK(current_request_info_->stream_controls()->audio.requested());
  SendLogMessage(base::StringPrintf("SelectAudioSettings({request_id=%d})",
                                    current_request_info_->request_id()));
  if (ShouldDeferDeviceSettingsSelection(
          user_media_request->MediaRequestType(),
          user_media_request->AudioMediaStreamType(),
          user_media_request->GetExecutionContext())) {
    base::expected<Vector<blink::AudioCaptureSettings>, std::string>
        eligible_settings = SelectEligibleSettingsAudioCapture(
            capabilities, user_media
"""


```