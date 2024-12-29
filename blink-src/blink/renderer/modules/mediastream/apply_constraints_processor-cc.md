Response:
Let's break down the thought process for analyzing this code and generating the detailed explanation.

1. **Understand the Core Purpose:** The first step is to quickly grasp the file's name and the surrounding context (Chromium, Blink, `mediastream`). "apply_constraints_processor" strongly suggests it deals with the `applyConstraints()` API for media streams. The `.cc` extension confirms it's C++ source code.

2. **Identify Key Components and Concepts:**  Scan the code for important classes, functions, and data structures. Keywords like `ApplyConstraintsProcessor`, `ProcessRequest`, `ProcessAudioRequest`, `ProcessVideoRequest`, `MediaStreamTrack`, `MediaStreamSource`, `constraints`, `VideoCaptureFormat`, `MediaDevicesDispatcher`, `Restart`, `ReconfigureTrack`, `StopForRestart`, and the various `SelectSettings` functions stand out. This gives a high-level overview of the involved entities.

3. **Trace the Main Execution Flow:** Follow the execution path of the `ProcessRequest` function. Notice it branches based on audio or video tracks. Then, trace the respective audio and video processing paths (`ProcessAudioRequest`, `ProcessVideoRequest`).

4. **Deep Dive into Video Processing:** The video processing path is significantly more complex. Notice the different branches based on the source type (device vs. content capture) and the `kApplyConstraintsRestartsVideoContentSources` feature flag. Pay close attention to the logic involving stopping and restarting the video source (`StopForRestart`, `MaybeDeviceSourceStoppedForRestart`, `MaybeRestartStoppedVideoContentSource`, `Restart`). Understand why these restarts are necessary (to apply new constraints).

5. **Analyze Helper Functions:** Examine the `SelectSettingsAudioCapture`, `SelectSettingsVideoDeviceCapture`, and `SelectSettingsVideoContentCapture` functions. Recognize their role in comparing current settings with requested constraints and available capabilities.

6. **Identify Interactions with External Components:** Observe the use of `MediaDevicesDispatcher` and its methods like `GetAllVideoInputDeviceFormats` and `GetAvailableVideoInputDeviceFormats`. Realize this component interacts with the underlying operating system or hardware to get information about media devices.

7. **Connect to Web APIs:** Now, link the C++ code back to the JavaScript `getUserMedia()` and `MediaStreamTrack.applyConstraints()` APIs. Understand that this C++ code is the engine that implements the logic behind these web APIs.

8. **Consider User Interactions and Errors:** Think about how a user might trigger this code. A user granting camera/microphone access and then a web page calling `applyConstraints()` are the primary scenarios. Consider common errors: invalid constraints, no available devices, and the implications of asynchronous operations.

9. **Map to HTML/CSS (Limited Relevance):**  Acknowledge that while media streams are *displayed* in HTML using elements like `<video>` and potentially styled with CSS, this specific C++ code primarily deals with the *internal logic* of constraint application and doesn't directly manipulate the DOM or CSS. The connection is more about the overall media pipeline.

10. **Construct Assumptions and Scenarios:** Create hypothetical inputs and outputs for specific functions to illustrate their behavior. Focus on demonstrating successful and failed constraint applications.

11. **Outline Debugging Steps:**  Think about how a developer might debug issues related to `applyConstraints()`. Emphasize logging, breakpoints within this C++ code, and examining the constraint objects. Highlight the asynchronous nature of the process.

12. **Structure the Explanation:** Organize the findings into logical sections: functionality, relationship to web technologies, logical reasoning, common errors, and debugging. Use clear and concise language. Provide code snippets where helpful.

13. **Refine and Review:** Read through the explanation to ensure accuracy, clarity, and completeness. Check for any ambiguities or missing information. For example, initially, I might have overlooked the details of why video content sources are handled differently, and would then go back and refine that section. Similarly, ensuring the connection to the web APIs is explicitly stated is crucial.

**Self-Correction Example during the process:**

Initially, I might have just said "This code handles applying constraints to media tracks."  However, that's too vague. I would then ask myself, "What *specifically* does it do?". This would lead me to break down the process into audio and video handling, the potential for source restarts, the role of `SelectSettings`, and the interaction with `MediaDevicesDispatcher`. This iterative process of asking "What more?" and "How does it work?" is crucial for a thorough analysis.
这个文件 `blink/renderer/modules/mediastream/apply_constraints_processor.cc` 的主要功能是处理对 `MediaStreamTrack` 对象应用约束（constraints）的请求。  它负责评估新的约束条件，并根据这些条件调整底层媒体源的配置。

下面是对其功能的详细列举，以及与 JavaScript、HTML、CSS 的关系、逻辑推理、用户错误和调试线索的说明：

**功能列举：**

1. **接收约束应用请求:**  `ApplyConstraintsProcessor` 类接收来自 `MediaStreamTrack` 对象的 `applyConstraints()` 方法的请求。这个请求包含了要应用的新约束。

2. **区分音频和视频轨道:**  根据请求应用约束的 `MediaStreamTrack` 的类型（音频或视频），它会调用不同的处理函数 (`ProcessAudioRequest` 或 `ProcessVideoRequest`)。

3. **处理音频约束:**
   - `ProcessAudioRequest` 函数负责处理音频轨道的约束。
   - 它会调用 `SelectSettingsAudioCapture` 函数，根据当前音频源的特性和新的约束条件，选择合适的音频捕获设置。
   - 如果找到了满足约束的设置，则认为约束应用成功。否则，会报告约束失败。

4. **处理视频约束:**
   - `ProcessVideoRequest` 函数负责处理视频轨道的约束，这部分逻辑更为复杂。
   - 它会根据视频源的类型（摄像头设备或屏幕/窗口/标签页共享）采取不同的处理方式。
   - **设备视频源 (摄像头):**
     -  `ProcessVideoDeviceRequest` 函数处理摄像头设备的约束。
     - 它会获取当前设备支持的所有视频格式。
     - 调用 `SelectVideoDeviceSettings` 函数，根据支持的格式和新的约束条件，选择最佳的视频格式和轨道适配器设置。
     - 如果当前格式已经满足新的约束，则直接应用新的轨道适配器设置 (`ReconfigureTrack`)。
     - 否则，可能需要重启视频源 (`StopForRestart`) 以应用新的格式。重启后会再次选择新的格式并应用。
   - **内容视频源 (屏幕/窗口/标签页共享):**
     - `ProcessVideoContentRequest` 函数处理屏幕/窗口/标签页共享的约束。
     - 它会调用 `SelectVideoContentSettings` 函数，根据新的约束条件和屏幕尺寸，选择合适的视频格式。
     - 类似于设备视频源，如果需要，会重启视频源 (`StopForRestart`)。

5. **选择合适的媒体设置:**  `SelectSettingsAudioCapture`, `SelectSettingsVideoDeviceCapture`, `SelectSettingsVideoContentCapture` 等函数是核心逻辑，它们根据可用的硬件能力和请求的约束，选择最合适的媒体格式和参数。这些函数实现了约束的匹配和优先级排序逻辑。

6. **重启媒体源:**  在某些情况下（例如，需要改变视频分辨率或帧率，而当前源的配置无法满足），需要先停止当前的媒体源，然后使用新的配置重新启动。这个过程保证了新的约束可以生效。

7. **应用轨道适配器设置:**  对于视频轨道，可以使用 `ReconfigureTrack` 方法应用一些不涉及源重启的设置更改。

8. **通知约束应用结果:**  无论成功还是失败，`ApplyConstraintsProcessor` 都会通过回调通知 `MediaStreamTrack` 对象约束应用的结果。

**与 JavaScript, HTML, CSS 的关系：**

- **JavaScript:**  `applyConstraints_processor.cc` 的功能直接支持了 JavaScript 中的 `MediaStreamTrack.applyConstraints()` 方法。当 JavaScript 代码调用 `track.applyConstraints(constraints)` 时，Blink 引擎会将这个请求传递给 `ApplyConstraintsProcessor` 进行处理。
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(stream => {
       const videoTrack = stream.getVideoTracks()[0];
       videoTrack.applyConstraints({ width: { min: 640 } })
         .then(() => {
           console.log('Constraints applied successfully');
         })
         .catch(error => {
           console.error('Failed to apply constraints:', error);
         });
     });
   ```
   在这个例子中，`applyConstraints()` 的调用最终会触发 `ApplyConstraintsProcessor` 的工作。

- **HTML:** HTML 中的 `<video>` 或 `<audio>` 元素用于显示或播放媒体流。`applyConstraints()` 的成功应用可能会改变这些元素接收到的视频或音频的特性（例如，视频分辨率），从而影响在 HTML 中渲染的效果。

- **CSS:** CSS 可以用来样式化 `<video>` 或 `<audio>` 元素，例如设置其大小、边框等。然而，`applyConstraints_processor.cc` 的功能主要关注媒体流本身的配置，而不是如何渲染它。CSS 不会直接触发或影响 `applyConstraints_processor.cc` 的执行，但约束的应用可能会间接影响到 CSS 样式的效果，例如，更高的分辨率可能需要更大的显示区域。

**逻辑推理（假设输入与输出）：**

**假设输入（视频轨道）：**

- 当前视频源是摄像头，分辨率为 640x480。
- `applyConstraints()` 被调用，请求的约束是 `{ width: { exact: 1280 }, height: { exact: 720 } }`。
- 摄像头支持 1280x720 的分辨率。

**输出：**

1. `ApplyConstraintsProcessor` 判断需要应用新的分辨率。
2. 它可能会先停止当前的视频源。
3. 然后，使用 1280x720 的配置重新启动视频源。
4. 最终，`applyConstraints()` 的 Promise 会 resolve，表示约束应用成功。

**假设输入（音频轨道）：**

- 当前音频源的采样率为 48000 Hz。
- `applyConstraints()` 被调用，请求的约束是 `{ sampleRate: { max: 44100 } }`。
- 音频源支持 44100 Hz 的采样率。

**输出：**

1. `ApplyConstraintsProcessor` 调用 `SelectSettingsAudioCapture`。
2. `SelectSettingsAudioCapture` 发现可以将采样率调整到 44100 Hz 以满足约束。
3. 音频源的采样率被调整。
4. `applyConstraints()` 的 Promise 会 resolve。

**涉及用户或编程常见的使用错误：**

1. **请求的约束无法满足:**  用户或开发者可能请求了设备不支持的约束。例如，请求一个摄像头不支持的分辨率或帧率。这会导致 `applyConstraints()` 的 Promise 被 reject。
   ```javascript
   videoTrack.applyConstraints({ frameRate: { min: 120 } }) // 如果摄像头不支持 120fps
     .catch(error => {
       console.error('Failed to apply constraints:', error.name); // error.name 可能是 "OverconstrainedError"
     });
   ```

2. **在轨道停止后尝试应用约束:**  如果 `MediaStreamTrack` 已经被停止（`stop()` 方法被调用），则无法应用新的约束。
   ```javascript
   videoTrack.stop();
   videoTrack.applyConstraints({ width: 640 }) // 这会失败
     .catch(error => {
       console.error('Failed to apply constraints:', error);
     });
   ```

3. **约束对象的格式错误:**  `applyConstraints()` 接受的约束参数必须是符合规范的对象。格式错误会导致方法调用失败。
   ```javascript
   videoTrack.applyConstraints("invalid constraint"); // 错误的参数类型
   ```

4. **期望立即生效的约束:**  应用约束可能需要一些时间，特别是当需要重启媒体源时。开发者不应期望约束立即生效并在下一帧中体现出来。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在一个网页上使用需要访问摄像头的应用：

1. **用户打开网页:** 用户在浏览器中打开一个使用了 `getUserMedia` API 的网页。
2. **网页请求摄像头权限:** 网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 请求用户的摄像头权限。
3. **用户授权摄像头:** 用户在浏览器提示中点击允许，授予网页访问摄像头的权限。
4. **获取 MediaStreamTrack:** `getUserMedia` 成功后，网页获得了包含视频轨道的 `MediaStream` 对象，可以通过 `stream.getVideoTracks()[0]` 获取 `MediaStreamTrack` 对象。
5. **调用 applyConstraints():** 网页的 JavaScript 代码调用 `videoTrack.applyConstraints(constraints)`，例如设置特定的分辨率或帧率。
6. **Blink 引擎处理请求:** 浏览器内核（Blink 引擎）接收到 `applyConstraints()` 的调用。
7. **创建 ApplyConstraintsRequest:**  Blink 引擎会创建一个 `ApplyConstraintsRequest` 对象来封装这个请求。
8. **ApplyConstraintsProcessor 处理请求:**  `ApplyConstraintsProcessor` 接收到这个 `ApplyConstraintsRequest` 对象。
9. **逻辑判断和媒体源调整:**  `ApplyConstraintsProcessor` 根据请求的约束和当前媒体源的状态，执行相应的逻辑，例如选择合适的格式、重启媒体源等。
10. **通知结果:**  `ApplyConstraintsProcessor` 完成操作后，会通知 `MediaStreamTrack` 对象约束应用的结果（成功或失败）。
11. **JavaScript Promise 的状态更新:** `applyConstraints()` 返回的 Promise 会根据操作结果 resolve 或 reject。

**调试线索:**

- **Console 输出:** 在 Chrome 浏览器的开发者工具的 Console 中查看可能的错误信息，例如 `OverconstrainedError`，可以了解哪些约束无法满足。
- **`chrome://webrtc-internals`:**  这个页面提供了 WebRTC 相关的内部信息，包括 `getUserMedia` 的过程、媒体流的轨道信息、以及 `applyConstraints` 的尝试和结果。查看 `PeerConnection` -> "Get Media Device Capabilities" 可以看到设备支持的能力。
- **断点调试:** 如果需要深入了解 `applyConstraints_processor.cc` 的执行流程，可以在 Chromium 源码中设置断点，并使用调试器（如 gdb 或 lldb）来跟踪代码的执行。
- **日志输出:**  Blink 引擎中可能包含相关的日志输出，可以通过配置 Chromium 的日志级别来查看更详细的信息。
- **检查约束对象:**  确保传递给 `applyConstraints()` 的约束对象格式正确，并且请求的属性是有效的。

总而言之，`blink/renderer/modules/mediastream/apply_constraints_processor.cc` 是 Blink 引擎中处理 `MediaStreamTrack.applyConstraints()` 核心逻辑的 C++ 代码，它负责根据请求的约束调整底层的媒体源配置，是 WebRTC 功能的重要组成部分。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/apply_constraints_processor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/apply_constraints_processor.h"

#include <utility>

#include "base/location.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_audio.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {
namespace {

void RequestFailed(blink::ApplyConstraintsRequest* request,
                   const String& constraint,
                   const String& message) {
  DCHECK(request);
  request->RequestFailed(constraint, message);
}

void RequestSucceeded(blink::ApplyConstraintsRequest* request) {
  DCHECK(request);
  request->RequestSucceeded();
}

}  // namespace

BASE_FEATURE(kApplyConstraintsRestartsVideoContentSources,
             "ApplyConstraintsRestartsVideoContentSources",
             base::FEATURE_ENABLED_BY_DEFAULT);

ApplyConstraintsProcessor::ApplyConstraintsProcessor(
    LocalFrame* frame,
    MediaDevicesDispatcherCallback media_devices_dispatcher_cb,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : frame_(frame),
      media_devices_dispatcher_cb_(std::move(media_devices_dispatcher_cb)),
      task_runner_(std::move(task_runner)) {
  DCHECK(frame_);
}

ApplyConstraintsProcessor::~ApplyConstraintsProcessor() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

void ApplyConstraintsProcessor::ProcessRequest(
    blink::ApplyConstraintsRequest* request,
    base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!request_completed_cb_);
  DCHECK(!current_request_);
  DCHECK(request->Track());
  if (!request->Track()->Source()) {
    CannotApplyConstraints(
        "Track has no source. ApplyConstraints not possible.");
    return;
  }
  request_completed_cb_ = std::move(callback);
  current_request_ = request;
  if (current_request_->Track()->GetSourceType() ==
      MediaStreamSource::kTypeVideo) {
    ProcessVideoRequest();
  } else {
    DCHECK_EQ(current_request_->Track()->GetSourceType(),
              MediaStreamSource::kTypeAudio);
    ProcessAudioRequest();
  }
}

void ApplyConstraintsProcessor::ProcessAudioRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_);
  DCHECK_EQ(current_request_->Track()->GetSourceType(),
            MediaStreamSource::kTypeAudio);
  DCHECK(request_completed_cb_);
  blink::MediaStreamAudioSource* audio_source = GetCurrentAudioSource();
  if (!audio_source) {
    CannotApplyConstraints("The track is not connected to any source");
    return;
  }

  blink::AudioCaptureSettings settings =
      SelectSettingsAudioCapture(audio_source, current_request_->Constraints());
  if (settings.HasValue()) {
    ApplyConstraintsSucceeded();
  } else {
    ApplyConstraintsFailed(settings.failed_constraint_name());
  }
}

void ApplyConstraintsProcessor::ProcessVideoRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_);
  DCHECK_EQ(current_request_->Track()->GetSourceType(),
            MediaStreamSource::kTypeVideo);
  DCHECK(request_completed_cb_);
  video_source_ = GetCurrentVideoSource();
  if (!video_source_) {
    CannotApplyConstraints("The track is not connected to any source");
    return;
  }

  // The sub-capture-target version is lost if the capture is restarted, because
  // of this we don't try to restart the source if cropTo() has ever been
  // called.
  const blink::MediaStreamDevice& device_info = video_source_->device();
  if (device_info.type == blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE) {
    ProcessVideoDeviceRequest();
  } else if (base::FeatureList::IsEnabled(
                 kApplyConstraintsRestartsVideoContentSources) &&
             video_source_->GetSubCaptureTargetVersion() == 0 &&
             (device_info.type ==
                  mojom::blink::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE ||
              device_info.type ==
                  mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE ||
              device_info.type == mojom::blink::MediaStreamType::
                                      DISPLAY_VIDEO_CAPTURE_THIS_TAB)) {
    ProcessVideoContentRequest();
  } else {
    FinalizeVideoRequest();
  }
}

void ApplyConstraintsProcessor::ProcessVideoDeviceRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  video_device_request_trace_ =
      ScopedMediaStreamTrace::CreateIfEnabled("VideoDeviceRequest");

  if (AbortIfVideoRequestStateInvalid())
    return;

  // TODO(crbug.com/768205): Support restarting the source even if there is more
  // than one track in the source.
  if (video_source_->NumTracks() > 1U) {
    FinalizeVideoRequest();
    return;
  }

  if (video_device_request_trace_)
    video_device_request_trace_->AddStep("GetAllVideoInputDeviceFormats");

  // It might be necessary to restart the video source. Before doing that,
  // check if the current format is the best format to satisfy the new
  // constraints. If this is the case, then the source does not need to be
  // restarted. To determine if the current format is the best, it is necessary
  // to know all the formats potentially supported by the source.
  GetMediaDevicesDispatcher()->GetAllVideoInputDeviceFormats(
      String(video_source_->device().id.data()),
      WTF::BindOnce(
          &ApplyConstraintsProcessor::MaybeStopVideoDeviceSourceForRestart,
          WrapWeakPersistent(this)));
}

void ApplyConstraintsProcessor::ProcessVideoContentRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (AbortIfVideoRequestStateInvalid()) {
    return;
  }

  // TODO(crbug.com/768205): Support restarting the source even if there is more
  // than one track in the source.
  if (video_source_->NumTracks() > 1U) {
    FinalizeVideoRequest();
    return;
  }

  MaybeStopVideoContentSourceForRestart();
}

void ApplyConstraintsProcessor::MaybeStopVideoDeviceSourceForRestart(
    const Vector<media::VideoCaptureFormat>& formats) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (AbortIfVideoRequestStateInvalid())
    return;

  blink::VideoCaptureSettings settings = SelectVideoDeviceSettings(formats);
  if (!settings.HasValue()) {
    ApplyConstraintsFailed(settings.failed_constraint_name());
    return;
  }

  if (video_source_->GetCurrentFormat() == settings.Format()) {
    video_source_->ReconfigureTrack(GetCurrentVideoTrack(),
                                    settings.track_adapter_settings());
    ApplyConstraintsSucceeded();
    GetCurrentVideoTrack()->NotifyConstraintsConfigurationComplete();
  } else {
    if (video_device_request_trace_)
      video_device_request_trace_->AddStep("StopForRestart");

    video_source_->StopForRestart(WTF::BindOnce(
        &ApplyConstraintsProcessor::MaybeDeviceSourceStoppedForRestart,
        WrapWeakPersistent(this)));
  }
}

void ApplyConstraintsProcessor::MaybeStopVideoContentSourceForRestart() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (AbortIfVideoRequestStateInvalid()) {
    return;
  }

  blink::VideoCaptureSettings settings = SelectVideoContentSettings();

  if (!settings.HasValue()) {
    ApplyConstraintsFailed(settings.failed_constraint_name());
    return;
  }

  if (video_source_->GetCurrentFormat() == settings.Format()) {
    if (settings.min_frame_rate().has_value()) {
      GetCurrentVideoTrack()->SetMinimumFrameRate(
          settings.min_frame_rate().value());
    }
    video_source_->ReconfigureTrack(GetCurrentVideoTrack(),
                                    settings.track_adapter_settings());
    ApplyConstraintsSucceeded();
    GetCurrentVideoTrack()->NotifyConstraintsConfigurationComplete();
  } else {
    video_source_->StopForRestart(WTF::BindOnce(
        &ApplyConstraintsProcessor::MaybeRestartStoppedVideoContentSource,
        WrapWeakPersistent(this)));
  }
}

void ApplyConstraintsProcessor::MaybeDeviceSourceStoppedForRestart(
    blink::MediaStreamVideoSource::RestartResult result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (AbortIfVideoRequestStateInvalid())
    return;

  if (result == blink::MediaStreamVideoSource::RestartResult::IS_RUNNING) {
    FinalizeVideoRequest();
    return;
  }

  if (video_device_request_trace_)
    video_device_request_trace_->AddStep("GetAvailableVideoInputDeviceFormats");

  DCHECK_EQ(result, blink::MediaStreamVideoSource::RestartResult::IS_STOPPED);
  GetMediaDevicesDispatcher()->GetAvailableVideoInputDeviceFormats(
      String(video_source_->device().id.data()),
      WTF::BindOnce(
          &ApplyConstraintsProcessor::FindNewFormatAndRestartDeviceSource,
          WrapWeakPersistent(this)));
}

void ApplyConstraintsProcessor::MaybeRestartStoppedVideoContentSource(
    blink::MediaStreamVideoSource::RestartResult result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (AbortIfVideoRequestStateInvalid()) {
    return;
  }

  if (result == blink::MediaStreamVideoSource::RestartResult::IS_RUNNING) {
    FinalizeVideoRequest();
    return;
  }

  DCHECK_EQ(result, blink::MediaStreamVideoSource::RestartResult::IS_STOPPED);

  blink::VideoCaptureSettings settings = SelectVideoContentSettings();
  // |settings| should have a value. If it does not due to some unexpected
  // reason (perhaps a race with another renderer process), restart the source
  // with the old format.
  DCHECK(video_source_->GetCurrentFormat());
  video_source_->Restart(
      settings.HasValue() ? settings.Format()
                          : *video_source_->GetCurrentFormat(),
      WTF::BindOnce(&ApplyConstraintsProcessor::MaybeSourceRestarted,
                    WrapWeakPersistent(this)));
}

void ApplyConstraintsProcessor::FindNewFormatAndRestartDeviceSource(
    const Vector<media::VideoCaptureFormat>& formats) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (AbortIfVideoRequestStateInvalid())
    return;

  if (video_device_request_trace_)
    video_device_request_trace_->AddStep("Restart");

  blink::VideoCaptureSettings settings = SelectVideoDeviceSettings(formats);
  DCHECK(video_source_->GetCurrentFormat());
  // |settings| should have a value. If it does not due to some unexpected
  // reason (perhaps a race with another renderer process), restart the source
  // with the old format.
  video_source_->Restart(
      settings.HasValue() ? settings.Format()
                          : *video_source_->GetCurrentFormat(),
      WTF::BindOnce(&ApplyConstraintsProcessor::MaybeSourceRestarted,
                    WrapWeakPersistent(this)));
}

void ApplyConstraintsProcessor::MaybeSourceRestarted(
    blink::MediaStreamVideoSource::RestartResult result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (AbortIfVideoRequestStateInvalid())
    return;

  if (result == blink::MediaStreamVideoSource::RestartResult::IS_RUNNING) {
    FinalizeVideoRequest();
  } else {
    if (video_device_request_trace_)
      video_device_request_trace_->AddStep("StopSource");

    DCHECK_EQ(result, blink::MediaStreamVideoSource::RestartResult::IS_STOPPED);
    CannotApplyConstraints("Source failed to restart");
    video_source_->StopSource();
  }
}

void ApplyConstraintsProcessor::FinalizeVideoRequest() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (video_device_request_trace_)
    video_device_request_trace_->AddStep(__func__);

  if (AbortIfVideoRequestStateInvalid())
    return;

  media::VideoCaptureFormat format;
  if (video_source_->GetCurrentFormat()) {
    format = *video_source_->GetCurrentFormat();
  } else {
    format = GetCurrentVideoTrack()->GetComputedSourceFormat();
  }
  blink::VideoCaptureSettings settings = SelectVideoDeviceSettings({format});

  if (settings.HasValue()) {
    if (settings.min_frame_rate().has_value()) {
      GetCurrentVideoTrack()->SetMinimumFrameRate(
          settings.min_frame_rate().value());
    }
    video_source_->ReconfigureTrack(GetCurrentVideoTrack(),
                                    settings.track_adapter_settings());
    ApplyConstraintsSucceeded();
    GetCurrentVideoTrack()->NotifyConstraintsConfigurationComplete();
  } else {
    ApplyConstraintsFailed(settings.failed_constraint_name());
  }
}

blink::VideoCaptureSettings
ApplyConstraintsProcessor::SelectVideoDeviceSettings(
    Vector<media::VideoCaptureFormat> formats) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_);
  DCHECK_EQ(current_request_->Track()->GetSourceType(),
            MediaStreamSource::kTypeVideo);
  DCHECK(request_completed_cb_);
  DCHECK_GT(formats.size(), 0U);

  blink::VideoInputDeviceCapabilities device_capabilities;
  device_capabilities.device_id = current_request_->Track()->Source()->Id();
  device_capabilities.group_id = current_request_->Track()->Source()->GroupId();
  device_capabilities.facing_mode =
      GetCurrentVideoSource()
          ? static_cast<mojom::blink::FacingMode>(
                GetCurrentVideoSource()->device().video_facing)
          : mojom::blink::FacingMode::kNone;
  device_capabilities.formats = std::move(formats);

  blink::VideoDeviceCaptureCapabilities video_capabilities;
  video_capabilities.noise_reduction_capabilities.push_back(
      GetCurrentVideoTrack()->noise_reduction());
  video_capabilities.device_capabilities.push_back(
      std::move(device_capabilities));

  // Run SelectSettings using the track's current settings as the default
  // values. However, initialize |settings| with the default values as a
  // fallback in case GetSettings returns nothing and leaves |settings|
  // unmodified.
  MediaStreamTrackPlatform::Settings settings;
  settings.width = blink::MediaStreamVideoSource::kDefaultWidth;
  settings.height = blink::MediaStreamVideoSource::kDefaultHeight;
  settings.frame_rate = blink::MediaStreamVideoSource::kDefaultFrameRate;
  GetCurrentVideoTrack()->GetSettings(settings);

  return SelectSettingsVideoDeviceCapture(
      video_capabilities, current_request_->Constraints(), settings.width,
      settings.height, settings.frame_rate);
}

blink::VideoCaptureSettings
ApplyConstraintsProcessor::SelectVideoContentSettings() {
  DCHECK(video_source_);
  gfx::Size screen_size = MediaStreamUtils::GetScreenSize(frame_);
  return blink::SelectSettingsVideoContentCapture(
      current_request_->Constraints(), video_source_->device().type,
      screen_size.width(), screen_size.height());
}

blink::MediaStreamAudioSource*
ApplyConstraintsProcessor::GetCurrentAudioSource() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_);
  DCHECK(current_request_->Track());
  return blink::MediaStreamAudioSource::From(
      current_request_->Track()->Source());
}

blink::MediaStreamVideoTrack*
ApplyConstraintsProcessor::GetCurrentVideoTrack() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  MediaStreamVideoTrack* track =
      MediaStreamVideoTrack::From(current_request_->Track());
  DCHECK(track);
  return track;
}

blink::MediaStreamVideoSource*
ApplyConstraintsProcessor::GetCurrentVideoSource() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return GetCurrentVideoTrack()->source();
}

bool ApplyConstraintsProcessor::AbortIfVideoRequestStateInvalid() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_);
  DCHECK_EQ(current_request_->Track()->GetSourceType(),
            MediaStreamSource::kTypeVideo);
  DCHECK(request_completed_cb_);

  if (GetCurrentVideoSource() != video_source_) {
    if (video_device_request_trace_)
      video_device_request_trace_->AddStep("Aborted");
    CannotApplyConstraints(
        "Track stopped or source changed. ApplyConstraints not possible.");
    return true;
  }
  return false;
}

void ApplyConstraintsProcessor::ApplyConstraintsSucceeded() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&ApplyConstraintsProcessor::CleanupRequest,
                    WrapWeakPersistent(this),
                    WTF::BindOnce(&RequestSucceeded,
                                  WrapPersistent(current_request_.Get()))));
}

void ApplyConstraintsProcessor::ApplyConstraintsFailed(
    const char* failed_constraint_name) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(
          &ApplyConstraintsProcessor::CleanupRequest, WrapWeakPersistent(this),
          WTF::BindOnce(&RequestFailed, WrapPersistent(current_request_.Get()),
                        String(failed_constraint_name),
                        String("Cannot satisfy constraints"))));
}

void ApplyConstraintsProcessor::CannotApplyConstraints(const String& message) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(
          &ApplyConstraintsProcessor::CleanupRequest, WrapWeakPersistent(this),
          WTF::BindOnce(&RequestFailed, WrapPersistent(current_request_.Get()),
                        String(), message)));
}

void ApplyConstraintsProcessor::CleanupRequest(
    base::OnceClosure user_media_request_callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_);
  DCHECK(request_completed_cb_);
  std::move(request_completed_cb_).Run();
  std::move(user_media_request_callback).Run();
  current_request_ = nullptr;
  video_source_ = nullptr;
  video_device_request_trace_.reset();
}

blink::mojom::blink::MediaDevicesDispatcherHost*
ApplyConstraintsProcessor::GetMediaDevicesDispatcher() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return media_devices_dispatcher_cb_.Run();
}

}  // namespace blink

"""

```