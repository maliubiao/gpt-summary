Response:
The user wants to understand the functionality of the `media_devices.cc` file in the Chromium Blink engine.

Here's a breakdown of how to address each of the user's requests:

1. **List the functionalities:** This requires analyzing the code and identifying the main actions and responsibilities of the `MediaDevices` class. Keywords like `enumerateDevices`, `getUserMedia`, `getDisplayMedia`, `selectAudioOutput`, and `setCaptureHandleConfig` point to key features. The inclusion of other classes like `UserMediaClient`, `CaptureController`, and the use of Mojo interfaces are also important to note.

2. **Relationship with Javascript, HTML, CSS:**  This involves connecting the C++ code to the web platform APIs that developers use. The names of the methods often directly correspond to JavaScript APIs. Understanding how these C++ functions are invoked by JavaScript and how they might affect the DOM (though this file doesn't directly manipulate the DOM) is crucial.

3. **Logical reasoning (with assumptions and I/O):**  For specific functions, I can create hypothetical scenarios to illustrate the input (parameters passed to the functions) and output (the returned Promise and potential side effects). For example, with `getUserMedia`, I can consider different constraint scenarios.

4. **Common usage errors:** This requires considering how developers might misuse the JavaScript APIs that are backed by this C++ code. Examples include incorrect constraints, calling functions in insecure contexts, or not handling Promises correctly.

5. **User steps to reach the code (debugging):** This involves tracing the user's actions in a web page that would lead to the execution of the code in `media_devices.cc`. Starting with user interaction (e.g., clicking a button) and following the flow through JavaScript calls is necessary.

6. **Summarize the functionality:**  Provide a concise overview of the file's purpose based on the points above.

**Mental Sandbox Simulation:**

* **Scanning the code:** I see methods related to media device enumeration, user media acquisition (`getUserMedia`), display media capture (`getDisplayMedia`), audio output selection, and setting capture handle configurations. The presence of `ScriptPromise` indicates asynchronous operations initiated by JavaScript.
* **Identifying key classes:** `MediaDevices`, `UserMediaClient`, `CaptureController` are central. Mojo interfaces suggest communication with other browser processes.
* **Connecting to web APIs:** The method names strongly suggest connections to JavaScript APIs like `navigator.mediaDevices.enumerateDevices()`, `navigator.mediaDevices.getUserMedia()`, and `navigator.mediaDevices.getDisplayMedia()`.
* **Considering error conditions:** The code includes checks for secure contexts, permissions, and valid input. This will be useful for generating examples of common usage errors.
* **Thinking about user flow:**  A user clicking a button that triggers a JavaScript call to `getUserMedia` seems like a good starting point for the "how to reach here" section.

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes
2. Relation to JS/HTML/CSS: Yes
3. Logical reasoning (I/O): Yes
4. Common usage errors: Yes
5. User steps for debugging: Yes
6. Summarize functionality: Yes

Confidence Score: 5/5

Strategizing complete. I will now proceed with generating the response based on the insights gained from this thought process.
这是 `blink/renderer/modules/mediastream/media_devices.cc` 文件的功能归纳，它是 Chromium Blink 引擎中负责处理媒体设备相关操作的核心组件。

**功能归纳:**

该文件主要实现了 `MediaDevices` 接口，这个接口是 Web API `navigator.mediaDevices` 的具体实现。它的主要功能可以概括为以下几点：

1. **枚举媒体设备 (enumerateDevices):**
   - 允许网页获取当前系统中可用的音频输入、视频输入和音频输出设备的列表。
   - 返回一个 `Promise`，该 Promise 会在设备信息获取成功后 resolve，并提供一个 `MediaDeviceInfo` 对象的数组，每个对象包含设备的 `deviceId`、`label` (设备名称) 和 `kind` (设备类型，如 "audioinput"、"videoinput"、"audiooutput")。
   -  会根据权限策略和安全上下文限制返回的设备信息，例如，未获得麦克风或摄像头权限的网站可能无法获取到详细的设备 `label`。

2. **获取用户媒体流 (getUserMedia):**
   - 允许网页请求用户的音频或视频输入流。
   - 接收一个 `MediaStreamConstraints` 对象作为参数，用于指定需要的媒体类型（音频、视频）以及更详细的约束条件（例如，分辨率、帧率、设备 ID 等）。
   - 返回一个 `Promise`，成功后 resolve 为一个 `MediaStream` 对象，包含用户授权的音频或视频轨道。
   - 如果用户拒绝授权或发生其他错误，Promise 会 reject。

3. **获取显示媒体流 (getDisplayMedia):**
   - 允许网页捕获用户的屏幕、特定窗口或浏览器标签的内容。
   - 接收一个 `DisplayMediaStreamOptions` 对象作为参数，用于指定捕获的类型（屏幕、窗口、标签）、是否包含音频等。
   - 返回一个 `Promise`，成功后 resolve 为一个 `MediaStream` 对象，包含捕获的视频轨道（可能包含音频轨道）。
   - 需要用户授权，并且在某些情况下需要用户激活（用户手势）。

4. **获取所有屏幕媒体流 (getAllScreensMedia):**
   - 允许网页捕获用户的所有屏幕。
   - 返回一个 `Promise`，成功后 resolve 为一个包含多个 `MediaStream` 对象的数组，每个对象代表一个屏幕。
   -  此功能通常受到权限策略的限制，需要在特定的安全上下文中使用。

5. **选择音频输出设备 (selectAudioOutput):**
   - 允许网页请求切换音频输出设备。
   - 接收一个 `AudioOutputOptions` 对象作为参数，用于指定要选择的设备的 `deviceId`。
   - 返回一个 `Promise`，成功后 resolve 为一个表示所选音频输出设备的 `MediaDeviceInfo` 对象。
   - 需要用户激活 (user gesture)。

6. **设置捕获句柄配置 (setCaptureHandleConfig):**
   - 允许网页为当前的捕获会话设置一个句柄（handle）。
   - 接收一个 `CaptureHandleConfig` 对象作为参数，包含要设置的句柄字符串和是否公开原始来源（origin）。
   -  这个功能主要用于在屏幕共享等场景下，让接收方能够识别捕获来源。

**与 Javascript, HTML, CSS 的关系及举例说明:**

`media_devices.cc` 文件是 Blink 引擎中实现 Web API 的一部分，直接与 JavaScript 交互。开发者通过 JavaScript 调用 `navigator.mediaDevices` 上的方法，最终会触发 `media_devices.cc` 中相应的 C++ 代码执行。

* **JavaScript 调用 `enumerateDevices()`:**
  ```javascript
  navigator.mediaDevices.enumerateDevices()
    .then(devices => {
      devices.forEach(device => {
        console.log(device.kind + ": " + device.label + " id = " + device.deviceId);
      });
    })
    .catch(error => {
      console.error("Error enumerating devices:", error);
    });
  ```
  这段 JavaScript 代码会调用 `MediaDevices::enumerateDevices()` 函数，C++ 代码会查询系统设备信息并返回给 JavaScript。

* **JavaScript 调用 `getUserMedia()` 获取摄像头视频:**
  ```javascript
  navigator.mediaDevices.getUserMedia({ video: true })
    .then(stream => {
      const videoElement = document.getElementById('myVideo');
      videoElement.srcObject = stream;
    })
    .catch(error => {
      console.error("Error accessing webcam:", error);
    });
  ```
  这段 JavaScript 代码会调用 `MediaDevices::getUserMedia()`，并传递 `{ video: true }` 作为约束条件。C++ 代码会请求用户授权，如果授权成功，则创建一个包含摄像头视频轨道的 `MediaStream` 对象返回给 JavaScript，然后 JavaScript 可以将这个流赋给 HTML `<video>` 元素。

* **JavaScript 调用 `getDisplayMedia()` 捕获屏幕:**
  ```javascript
  navigator.mediaDevices.getDisplayMedia({ video: true })
    .then(stream => {
      const videoElement = document.getElementById('screenShare');
      videoElement.srcObject = stream;
    })
    .catch(error => {
      console.error("Error capturing display:", error);
    });
  ```
  这段 JavaScript 代码会调用 `MediaDevices::getDisplayMedia()`。C++ 代码会请求用户选择要共享的屏幕或窗口，并返回相应的 `MediaStream`。

* **HTML:** HTML 提供了 `<video>` 和 `<audio>` 元素，用于展示和播放从 `getUserMedia` 或 `getDisplayMedia` 获取的媒体流。

* **CSS:** CSS 可以用于控制 `<video>` 和 `<audio>` 元素的样式和布局。

**逻辑推理 (假设输入与输出):**

假设输入一个 JavaScript 调用：

```javascript
navigator.mediaDevices.getUserMedia({ audio: true, video: { facingMode: 'user' } })
```

**假设输入:**
- `script_state`: 当前 JavaScript 的执行状态。
- `options`: 一个 `UserMediaStreamConstraints` 对象，包含 `audio: true` 和 `video: { facingMode: 'user' }`。

**逻辑推理过程:**
1. `MediaDevices::getUserMedia()` 被调用。
2. C++ 代码会将 JavaScript 的约束对象转换为内部的 `MediaStreamConstraints` 对象。
3. 代码会检查安全上下文，确保当前页面是安全的 (HTTPS)。
4. 代码会向浏览器内核发起请求，以获取用户的音频和前置摄像头权限。
5. 用户可能会被提示允许或拒绝访问其麦克风和摄像头。

**可能输出:**
- **成功:** 如果用户允许了权限，C++ 代码会创建一个包含麦克风音频轨道和前置摄像头视频轨道的 `MediaStream` 对象，并通过 Promise resolve 返回给 JavaScript。
- **失败 (用户拒绝):** 如果用户拒绝了任何一个权限，Promise 会 reject，并返回一个 `DOMException` 对象，例如 `NotAllowedError`。
- **失败 (设备不存在):** 如果系统中没有可用的麦克风或前置摄像头，Promise 可能会 reject，并返回一个 `DOMException` 对象，例如 `NotFoundError`。

**用户或编程常见的使用错误:**

1. **在非安全上下文 (HTTP) 中调用 `getUserMedia` 或 `getDisplayMedia`:** 这些 API 需要在安全上下文 (HTTPS) 中才能使用。如果尝试在 HTTP 页面上调用，Promise 会 reject 并抛出 `NotAllowedError`。

   ```javascript
   // 在 HTTP 页面上调用
   navigator.mediaDevices.getUserMedia({ video: true })
     .catch(error => {
       console.error(error.name); // 可能输出 "NotAllowedError"
     });
   ```

2. **未处理 Promise 的 rejection:** 如果用户拒绝权限或发生其他错误，Promise 会 reject。如果开发者没有正确地使用 `.catch()` 或 `async/await` 的 try-catch 结构来处理 rejection，可能会导致未捕获的错误。

   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true }); // 缺少 .catch()
   ```

3. **请求无效的约束条件:**  例如，请求一个不存在的设备 ID 或不支持的分辨率。这会导致 Promise reject，并可能抛出 `OverconstrainedError`。

   ```javascript
   navigator.mediaDevices.getUserMedia({ video: { deviceId: 'non-existent-id' } })
     .catch(error => {
       console.error(error.name); // 可能输出 "OverconstrainedError"
     });
   ```

4. **在 `getDisplayMedia` 中没有用户激活 (某些情况下):**  为了防止恶意网站滥用屏幕共享，`getDisplayMedia` 通常需要在用户手势（例如，点击按钮）触发后才能调用。

5. **滥用 `getAllScreensMedia`:**  这个 API 权限较高，不应在没有充分理由的情况下使用，因为它会暴露用户的所有屏幕内容。浏览器可能会有额外的安全提示来警告用户。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户访问一个网页:** 用户在浏览器中打开一个包含使用媒体设备功能的网页。
2. **网页 JavaScript 代码执行:** 网页的 JavaScript 代码开始执行。
3. **调用 `navigator.mediaDevices` 上的方法:** JavaScript 代码调用了 `navigator.mediaDevices.enumerateDevices()`, `navigator.mediaDevices.getUserMedia()`, `navigator.mediaDevices.getDisplayMedia()` 或其他相关方法。
4. **Blink 引擎接收到请求:** 浏览器内核（Blink 引擎）接收到来自 JavaScript 的请求。
5. **路由到 `media_devices.cc`:**  请求被路由到 `blink/renderer/modules/mediastream/media_devices.cc` 文件中的相应函数实现。
6. **C++ 代码执行:**  `media_devices.cc` 中的 C++ 代码开始执行，例如：
   - 查询系统设备信息。
   - 请求用户权限。
   - 与操作系统交互以获取媒体流。
7. **结果返回给 JavaScript:**  C++ 代码执行完毕后，将结果（例如，设备列表或 `MediaStream` 对象）通过 Promise resolve 或 reject 返回给 JavaScript。
8. **JavaScript 处理结果:**  JavaScript 代码根据 Promise 的结果更新网页 UI 或执行其他操作。

**调试线索:**

如果在调试媒体设备相关的问题，可以按照以下步骤追踪：

1. **检查 JavaScript 控制台:** 查看是否有 JavaScript 错误或 Promise rejection 的信息。
2. **使用浏览器的开发者工具:**
   - **Sources 面板:**  查看 JavaScript 代码的执行流程，确认 `navigator.mediaDevices` 方法是否被正确调用。
   - **Network 面板:**  查看是否有与媒体相关的网络请求（虽然 `enumerateDevices` 等通常不需要网络请求）。
   - **Application 面板 (Permissions):**  查看当前网站的媒体设备权限状态。
3. **Blink 渲染器调试 (如果需要深入分析):**  可以设置断点在 `media_devices.cc` 中的相关函数，例如 `MediaDevices::enumerateDevices` 或 `MediaDevices::getUserMedia`，以跟踪 C++ 代码的执行过程。这通常需要 Chromium 的开发环境。
4. **查看浏览器日志:** 浏览器可能会记录与媒体设备相关的错误或信息。

总而言之，`media_devices.cc` 是 Blink 引擎中实现 Web 媒体设备功能的核心 C++ 文件，它响应 JavaScript 的请求，与操作系统交互，管理用户权限，并返回媒体设备信息或媒体流给网页。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_devices.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_devices.h"

#include <utility>

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/uuid.h"
#include "build/build_config.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/mediastream/media_devices.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/mojom/media/capture_handle_config.mojom-blink.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver_with_tracker.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_output_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_capture_handle_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_display_media_stream_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_device_kind.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_supported_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_boolean_mediatrackconstraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_domexception_overconstrainederror.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_user_media_stream_constraints.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/modules/mediastream/crop_target.h"
#include "third_party/blink/renderer/modules/mediastream/identifiability_metrics.h"
#include "third_party/blink/renderer/modules/mediastream/input_device_info.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream.h"
#include "third_party/blink/renderer/modules/mediastream/navigator_media_stream.h"
#include "third_party/blink/renderer/modules/mediastream/restriction_target.h"
#include "third_party/blink/renderer/modules/mediastream/scoped_media_stream_tracer.h"
#include "third_party/blink/renderer/modules/mediastream/sub_capture_target.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/region_capture_crop_id.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

BASE_FEATURE(kEnumerateDevicesRequestAudioCapabilities,
             "EnumerateDevicesRequestAudioCapabilities",
#if BUILDFLAG(IS_MAC)
             base::FEATURE_DISABLED_BY_DEFAULT
#else
             base::FEATURE_ENABLED_BY_DEFAULT
#endif
);

namespace {

template <typename IDLResolvedType>
class PromiseResolverCallbacks final : public UserMediaRequest::Callbacks {
 public:
  PromiseResolverCallbacks(
      UserMediaRequestType media_type,
      ScriptPromiseResolverWithTracker<UserMediaRequestResult, IDLResolvedType>*
          resolver,
      base::OnceCallback<void(const String&, CaptureController*)>
          on_success_follow_up,
      std::unique_ptr<ScopedMediaStreamTracer> tracer)
      : media_type_(media_type),
        resolver_(resolver),
        on_success_follow_up_(std::move(on_success_follow_up)),
        tracer_(std::move(tracer)) {}
  ~PromiseResolverCallbacks() override = default;

  void OnSuccess(const MediaStreamVector& streams,
                 CaptureController* capture_controller) override {
    OnSuccessImpl<IDLResolvedType>(streams, capture_controller);
    if (tracer_) {
      tracer_->End();
    }
  }

  template <typename T>
  void OnSuccessImpl(const MediaStreamVector&, CaptureController*);

  void OnError(ScriptWrappable* callback_this_value,
               const V8MediaStreamError* error,
               CaptureController* capture_controller,
               UserMediaRequestResult result) override {
    if (capture_controller) {
      capture_controller->FinalizeFocusDecision();
    }
    resolver_->template Reject<V8MediaStreamError>(error, result);
    if (tracer_) {
      tracer_->End();
    }
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resolver_);
    UserMediaRequest::Callbacks::Trace(visitor);
  }

 private:
  const UserMediaRequestType media_type_;

  Member<
      ScriptPromiseResolverWithTracker<UserMediaRequestResult, IDLResolvedType>>
      resolver_;
  base::OnceCallback<void(const String&, CaptureController*)>
      on_success_follow_up_;
  std::unique_ptr<ScopedMediaStreamTracer> tracer_;
};

template <>
template <>
void PromiseResolverCallbacks<MediaStream>::OnSuccessImpl<MediaStream>(
    const MediaStreamVector& streams,
    CaptureController* capture_controller) {
  DCHECK_EQ(streams.size(), 1u);
  MediaStream* stream = streams[0];

  if (on_success_follow_up_) {
    // Only getDisplayMedia() calls set |on_success_follow_up_|.
    // Successful invocations of getDisplayMedia() always have exactly
    // one video track, except for the case when the permission
    // `DISPLAY_MEDIA_SYSTEM_AUDIO` is set, which will lead to 0 video track.
    //
    // Extension API calls that are followed by a getUserMedia() call with
    // chromeMediaSourceId are treated liked getDisplayMedia() calls.
    MediaStreamTrackVector video_tracks = stream->getVideoTracks();
    if (capture_controller && video_tracks.size() > 0) {
      capture_controller->SetVideoTrack(video_tracks[0], stream->id().Utf8());
    }
  }

  // Resolve Promise<MediaStream> on a microtask.
  resolver_->Resolve(stream);

  // Enqueue the follow-up microtask, if any is intended.
  if (on_success_follow_up_) {
    std::move(on_success_follow_up_).Run(stream->id(), capture_controller);
  }
}

template <>
template <>
void PromiseResolverCallbacks<IDLSequence<MediaStream>>::OnSuccessImpl<
    IDLSequence<MediaStream>>(const MediaStreamVector& streams,
                              CaptureController* capture_controller) {
  DCHECK(!streams.empty());
  DCHECK_EQ(UserMediaRequestType::kAllScreensMedia, media_type_);
  resolver_->Resolve(streams);
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class DisplayCapturePolicyResult {
  kDisallowed = 0,
  kAllowed = 1,
  kMaxValue = kAllowed
};

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class ProduceTargetFunctionResult {
  kPromiseProduced = 0,
  kGenericError = 1,
  kInvalidContext = 2,
  kDuplicateCallBeforePromiseResolution = 3,
  kDuplicateCallAfterPromiseResolution = 4,
  kElementAndMediaDevicesNotInSameExecutionContext = 5,
  kMaxValue = kElementAndMediaDevicesNotInSameExecutionContext
};

void RecordUma(SubCaptureTarget::Type type,
               ProduceTargetFunctionResult result) {
  if (type == SubCaptureTarget::Type::kCropTarget) {
    base::UmaHistogramEnumeration(
        "Media.RegionCapture.ProduceCropTarget.Function.Result", result);
  } else if (type == SubCaptureTarget::Type::kRestrictionTarget) {
    base::UmaHistogramEnumeration(
        "Media.ElementCapture.ProduceTarget.Function.Result", result);
  } else {
    NOTREACHED();
  }
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class ProduceTargetPromiseResult {
  kPromiseResolved = 0,
  kPromiseRejected = 1,
  kMaxValue = kPromiseRejected
};

void RecordUma(SubCaptureTarget::Type type, ProduceTargetPromiseResult result) {
  if (type == SubCaptureTarget::Type::kCropTarget) {
    base::UmaHistogramEnumeration(
        "Media.RegionCapture.ProduceCropTarget.Promise.Result", result);
  } else if (type == SubCaptureTarget::Type::kRestrictionTarget) {
    base::UmaHistogramEnumeration(
        "Media.ElementCapture.ProduceTarget.Promise.Result", result);
  } else {
    NOTREACHED();
  }
}

#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)

// When `blink::features::kGetDisplayMediaRequiresUserActivation` is enabled,
// calls to `getDisplayMedia()` will require a transient user activation. This
// can be bypassed with the `ScreenCaptureWithoutGestureAllowedForOrigins`
// policy though.
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class GetDisplayMediaTransientActivation {
  kPresent = 0,
  kMissing = 1,
  kMissingButFeatureDisabled = 2,
  kMissingButPolicyOverrides = 3,
  kMaxValue = kMissingButPolicyOverrides
};

void RecordUma(GetDisplayMediaTransientActivation activation) {
  base::UmaHistogramEnumeration(
      "Media.GetDisplayMedia.RequiresUserActivationResult", activation);
}

bool TransientActivationRequirementSatisfied(LocalDOMWindow* window) {
  DCHECK(window);

  LocalFrame* const frame = window->GetFrame();
  if (!frame) {
    return false;  // Err on the side of caution. Intentionally neglect UMA.
  }

  const Settings* const settings = frame->GetSettings();
  if (!settings) {
    return false;  // Err on the side of caution. Intentionally neglect UMA.
  }

  if (LocalFrame::HasTransientUserActivation(frame) ||
      (RuntimeEnabledFeatures::
           CapabilityDelegationDisplayCaptureRequestEnabled() &&
       window->IsDisplayCaptureRequestTokenActive())) {
    RecordUma(GetDisplayMediaTransientActivation::kPresent);
    return true;
  }

  if (!RuntimeEnabledFeatures::GetDisplayMediaRequiresUserActivationEnabled()) {
    RecordUma(GetDisplayMediaTransientActivation::kMissingButFeatureDisabled);
    return true;
  }

  if (!settings->GetRequireTransientActivationForGetDisplayMedia()) {
    RecordUma(GetDisplayMediaTransientActivation::kMissingButPolicyOverrides);
    return true;
  }

  RecordUma(GetDisplayMediaTransientActivation::kMissing);
  return false;
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
bool IsExtensionScreenSharingFunctionCall(const MediaStreamConstraints* options,
                                          ExceptionState& exception_state) {
  DCHECK(!exception_state.HadException());

  if (!options) {
    return false;
  }

  const V8UnionBooleanOrMediaTrackConstraints* const video = options->video();
  if (!video || video->GetContentType() !=
                    V8UnionBooleanOrMediaTrackConstraints::ContentType::
                        kMediaTrackConstraints) {
    return false;
  }

  const MediaTrackConstraints* const constraints =
      video->GetAsMediaTrackConstraints();
  if (!constraints || !constraints->hasMandatory()) {
    return false;
  }

  const HashMap<String, String> map =
      blink::Dictionary(constraints->mandatory())
          .GetOwnPropertiesAsStringHashMap(exception_state);

  return !exception_state.HadException() && map.Contains("chromeMediaSourceId");
}
#endif

MediaStreamConstraints* ToMediaStreamConstraints(
    const UserMediaStreamConstraints* source) {
  DCHECK(source);

  MediaStreamConstraints* const constraints = MediaStreamConstraints::Create();

  if (source->hasAudio()) {
    constraints->setAudio(source->audio());
  }

  if (source->hasVideo()) {
    constraints->setVideo(source->video());
  }

  return constraints;
}

MediaStreamConstraints* ToMediaStreamConstraints(
    const DisplayMediaStreamOptions* source) {
  MediaStreamConstraints* const constraints = MediaStreamConstraints::Create();
  if (source->hasAudio()) {
    constraints->setAudio(source->audio());
  }
  if (source->hasVideo()) {
    constraints->setVideo(source->video());
  }
  if (source->hasPreferCurrentTab()) {
    constraints->setPreferCurrentTab(source->preferCurrentTab());
  }
  if (source->hasController()) {
    constraints->setController(source->controller());
  }
  if (source->hasSelfBrowserSurface()) {
    constraints->setSelfBrowserSurface(source->selfBrowserSurface());
  }
  if (source->hasSystemAudio()) {
    constraints->setSystemAudio(source->systemAudio());
  }
  if (source->hasSurfaceSwitching()) {
    constraints->setSurfaceSwitching(source->surfaceSwitching());
  }
  if (source->hasMonitorTypeSurfaces()) {
    constraints->setMonitorTypeSurfaces(source->monitorTypeSurfaces());
  }
  return constraints;
}

bool EqualDeviceForDeviceChange(const WebMediaDeviceInfo& lhs,
                                const WebMediaDeviceInfo& rhs) {
  return lhs.device_id == rhs.device_id && lhs.label == rhs.label &&
         lhs.group_id == rhs.group_id && lhs.IsAvailable() == rhs.IsAvailable();
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
base::Token SubCaptureTargetIdToToken(const WTF::String& id) {
  if (id.empty()) {
    return base::Token();
  }

  const base::Uuid guid = base::Uuid::ParseLowercase(id.Ascii());
  DCHECK(guid.is_valid());

  const base::Token token = blink::GUIDToToken(guid);
  DCHECK(!token.is_zero());
  return token;
}
#endif  // !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)

}  // namespace

const char MediaDevices::kSupplementName[] = "MediaDevices";

MediaDevices* MediaDevices::mediaDevices(Navigator& navigator) {
  MediaDevices* supplement =
      Supplement<Navigator>::From<MediaDevices>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<MediaDevices>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

MediaDevices::MediaDevices(Navigator& navigator)
    : ActiveScriptWrappable<MediaDevices>({}),
      Supplement<Navigator>(navigator),
      ExecutionContextLifecycleObserver(navigator.DomWindow()),
      stopped_(false),
      dispatcher_host_(navigator.GetExecutionContext()),
      receiver_(this, navigator.DomWindow()) {}

MediaDevices::~MediaDevices() = default;

ScriptPromise<IDLSequence<MediaDeviceInfo>> MediaDevices::enumerateDevices(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  UpdateWebRTCMethodCount(RTCAPIName::kEnumerateDevices);
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Current frame is detached.");
    return ScriptPromise<IDLSequence<MediaDeviceInfo>>();
  }

  auto tracer = std::make_unique<ScopedMediaStreamTracer>(
      "MediaDevices.EnumerateDevices");
  auto* result_tracker = MakeGarbageCollected<ScriptPromiseResolverWithTracker<
      EnumerateDevicesResult, IDLSequence<MediaDeviceInfo>>>(
      script_state, "Media.MediaDevices.EnumerateDevices", base::Seconds(4));
  const auto promise = result_tracker->Promise();

  enumerate_device_requests_.insert(result_tracker);

  LocalFrame* frame = LocalDOMWindow::From(script_state)->GetFrame();
  GetDispatcherHost(frame).EnumerateDevices(
      /*request_audio_input=*/true, /*request_video_input=*/true,
      /*request_audio_output=*/true,
      /*request_video_input_capabilities=*/true,
      /*request_audio_input_capabilities=*/
      base::FeatureList::IsEnabled(kEnumerateDevicesRequestAudioCapabilities),
      WTF::BindOnce(&MediaDevices::DevicesEnumerated, WrapPersistent(this),
                    WrapPersistent(result_tracker), std::move(tracer)));
  return promise;
}

MediaTrackSupportedConstraints* MediaDevices::getSupportedConstraints() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return MediaTrackSupportedConstraints::Create();
}

ScriptPromise<MediaStream> MediaDevices::getUserMedia(
    ScriptState* script_state,
    const UserMediaStreamConstraints* options,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto tracer =
      std::make_unique<ScopedMediaStreamTracer>("MediaDevices.GetUserMedia");

  // This timeout of base::Seconds(8) is an initial value and based on the data
  // in Media.MediaDevices.GetUserMedia.Latency, it should be iterated upon.
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolverWithTracker<UserMediaRequestResult, MediaStream>>(
      script_state, "Media.MediaDevices.GetUserMedia", base::Seconds(8));
  const auto promise = resolver->Promise();

  DCHECK(options);  // Guaranteed by the default value in the IDL.
  DCHECK(!exception_state.HadException());

  MediaStreamConstraints* const constraints = ToMediaStreamConstraints(options);
  if (!constraints) {
    DCHECK(exception_state.HadException());
    resolver->RecordAndDetach(UserMediaRequestResult::kInvalidConstraints);
    return promise;
  }

  return SendUserMediaRequest(UserMediaRequestType::kUserMedia, resolver,
                              constraints, exception_state, std::move(tracer));
}

template <typename IDLResolvedType>
ScriptPromise<IDLResolvedType> MediaDevices::SendUserMediaRequest(
    UserMediaRequestType media_type,
    ScriptPromiseResolverWithTracker<UserMediaRequestResult, IDLResolvedType>*
        resolver,
    const MediaStreamConstraints* options,
    ExceptionState& exception_state,
    std::unique_ptr<ScopedMediaStreamTracer> tracer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!exception_state.HadException());

  auto promise = resolver->Promise();
  ScriptState* script_state = resolver->GetScriptState();
  if (!script_state->ContextIsValid()) {
    resolver->RecordAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotSupportedError,
        "No media device client available; "
        "is this a detached window?",
        UserMediaRequestResult::kContextDestroyed);
    return promise;
  }

  base::OnceCallback<void(const String&, CaptureController*)>
      on_success_follow_up;
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  if (media_type == UserMediaRequestType::kDisplayMedia ||
      IsExtensionScreenSharingFunctionCall(options, exception_state)) {
    if (options->hasController()) {
      on_success_follow_up = WTF::BindOnce(
          &MediaDevices::EnqueueMicrotaskToCloseFocusWindowOfOpportunity,
          WrapWeakPersistent(this));
    } else {
      // TODO(crbug.com/1381949): Don't wait until the IPC round-trip and have
      // the browser process focus-switch upon starting the capture.
      on_success_follow_up =
          WTF::BindOnce(&MediaDevices::CloseFocusWindowOfOpportunity,
                        WrapWeakPersistent(this));
    }
  }

  if (exception_state.HadException()) {
    resolver->RecordAndDetach(UserMediaRequestResult::kInvalidConstraints);
    return promise;
  }
#endif

  auto* callbacks =
      MakeGarbageCollected<PromiseResolverCallbacks<IDLResolvedType>>(
          media_type, resolver, std::move(on_success_follow_up),
          std::move(tracer));

  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  UserMediaClient* user_media_client = UserMediaClient::From(window);
  constexpr IdentifiableSurface::Type surface_type =
      IdentifiableSurface::Type::kMediaDevices_GetUserMedia;
  IdentifiableSurface surface;
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(surface_type)) {
    surface = IdentifiableSurface::FromTypeAndToken(
        surface_type, TokenFromConstraints(options));
  }

  UserMediaRequest* request =
      UserMediaRequest::Create(window, user_media_client, media_type, options,
                               callbacks, exception_state, surface);
  if (!request) {
    DCHECK(exception_state.HadException());
    resolver->RecordAndDetach(UserMediaRequestResult::kInvalidConstraints);
    return promise;
  }

  String error_message;
  if (!request->IsSecureContextUse(error_message)) {
    resolver->RecordAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotSupportedError, error_message,
        UserMediaRequestResult::kInsecureContext);
    return promise;
  }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  if (media_type == UserMediaRequestType::kDisplayMedia) {
    window->ConsumeDisplayCaptureRequestToken();
  }
#endif

  request->Start();
  return promise;
}

ScriptPromise<IDLSequence<MediaStream>> MediaDevices::getAllScreensMedia(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto tracer = std::make_unique<ScopedMediaStreamTracer>(
      "MediaDevices.GetAllScreensMedia");

  // This timeout of base::Seconds(6) is an initial value and based on the data
  // in Media.MediaDevices.GetAllScreensMedia.Latency, it should be iterated
  // upon.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolverWithTracker<
      UserMediaRequestResult, IDLSequence<MediaStream>>>(
      script_state, "Media.MediaDevices.GetAllScreensMedia", base::Seconds(6));
  auto promise = resolver->Promise();

  ExecutionContext* const context = GetExecutionContext();
  if (!context) {
    resolver->RecordAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "No media device client available; is this a detached window?",
        UserMediaRequestResult::kContextDestroyed);
    return promise;
  }

  const bool capture_allowed_by_permissions_policy = context->IsFeatureEnabled(
      mojom::blink::PermissionsPolicyFeature::kAllScreensCapture,
      ReportOptions::kReportOnFailure);

  base::UmaHistogramEnumeration(
      "Media.Ui.GetAllScreensMedia.AllScreensCapturePolicyResult",
      capture_allowed_by_permissions_policy
          ? DisplayCapturePolicyResult::kAllowed
          : DisplayCapturePolicyResult::kDisallowed);

  if (context->IsIsolatedContext() && !capture_allowed_by_permissions_policy) {
    resolver->RecordAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotAllowedError,
        "Access to the feature \"all-screenscapture\" is disallowed by "
        "permissions policy.",
        UserMediaRequestResult::kNotAllowedError);
    return promise;
  }

  // This API is available either in isolated contexts or, temporarily, on web
  // pages with strict CSP and trusted types. In isolated contexts, an explicit
  // check for strict CSP is not required as it enforces a restriction
  // equivalent to strict CSP (i.e. `script-src self` in combination with
  // packaging). Since we limit the exposure of the feature through the
  // [InjectionMitigated] IDL attribute, we can get away with a DCHECK here to
  // validate that restriction.
  DCHECK(context->IsIsolatedContext() || context->IsInjectionMitigatedContext());

  MediaStreamConstraints* constraints = MediaStreamConstraints::Create();
  constraints->setVideo(
      MakeGarbageCollected<V8UnionBooleanOrMediaTrackConstraints>(true));
  return SendUserMediaRequest(UserMediaRequestType::kAllScreensMedia, resolver,
                              constraints, exception_state, std::move(tracer));
}

ScriptPromise<MediaStream> MediaDevices::getDisplayMedia(
    ScriptState* script_state,
    const DisplayMediaStreamOptions* options,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LocalDOMWindow* const window = DomWindow();

  auto tracer =
      std::make_unique<ScopedMediaStreamTracer>("MediaDevices.GetDisplayMedia");

  // Using timeout of base::Seconds(12) based on the
  // Media.MediaDevices.GetDisplayMedia.Latency values. With the earlier value
  // of base::Seconds(6), we got about 25% of results counted as kTimeout.
  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolverWithTracker<UserMediaRequestResult, MediaStream>>(
      script_state, "Media.MediaDevices.GetDisplayMedia", base::Seconds(12));
  auto promise = resolver->Promise();

  if (!window) {
    resolver->RecordAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "No local DOM window; is this a detached window?",
        UserMediaRequestResult::kContextDestroyed);
    return promise;
  }

  const bool capture_allowed_by_permissions_policy = window->IsFeatureEnabled(
      mojom::blink::PermissionsPolicyFeature::kDisplayCapture,
      ReportOptions::kReportOnFailure);

  base::UmaHistogramEnumeration(
      "Media.Ui.GetDisplayMedia.DisplayCapturePolicyResult",
      capture_allowed_by_permissions_policy
          ? DisplayCapturePolicyResult::kAllowed
          : DisplayCapturePolicyResult::kDisallowed);

  if (!capture_allowed_by_permissions_policy) {
    resolver->RecordAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotAllowedError,
        "Access to the feature \"display-capture\" is disallowed by "
        "permissions policy.",
        UserMediaRequestResult::kNotAllowedError);
    return promise;
  }

  if (!TransientActivationRequirementSatisfied(window)) {
    resolver->RecordAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "getDisplayMedia() requires transient activation (user gesture).",
        UserMediaRequestResult::kInvalidStateError);
    return promise;
  }

  if (CaptureController* const capture_controller =
          options->getControllerOr(nullptr)) {
    if (capture_controller->IsBound()) {
      resolver->RecordAndThrowDOMException(
          exception_state, DOMExceptionCode::kInvalidStateError,
          "A CaptureController object may only be used with a single "
          "getDisplayMedia() invocation.",
          UserMediaRequestResult::kInvalidStateError);
      return promise;
    }
    capture_controller->SetIsBound(true);
  }

  MediaStreamConstraints* const constraints = ToMediaStreamConstraints(options);
  if (!options->hasSelfBrowserSurface() &&
      (!options->hasPreferCurrentTab() || !options->preferCurrentTab())) {
    constraints->setSelfBrowserSurface("exclude");
  }

  if (options->hasPreferCurrentTab() && options->preferCurrentTab()) {
    UseCounter::Count(window,
                      WebFeature::kGetDisplayMediaWithPreferCurrentTabTrue);
  }

  return SendUserMediaRequest(UserMediaRequestType::kDisplayMedia, resolver,
                              constraints, exception_state, std::move(tracer));
}

ScriptPromise<MediaDeviceInfo> MediaDevices::selectAudioOutput(
    ScriptState* script_state,
    const AudioOutputOptions* options,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LocalDOMWindow* window = LocalDOMWindow::From(script_state);

  if (!script_state->ContextIsValid() || !window || !window->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kAbortError,
        "No local DOM window; is this a detached window?");
    return EmptyPromise();
  }
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolverWithTracker<
      AudioOutputSelectionResult, MediaDeviceInfo>>(
      script_state, "Media.MediaDevices.SelectAudioOutput", base::Seconds(8));
  if (!LocalFrame::HasTransientUserActivation(window->GetFrame())) {
    resolver->Reject<DOMException>(
        MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kInvalidStateError,
            "selectAudioOutput() requires transient "
            "activation (user gesture)."),
        AudioOutputSelectionResult::kNoUserActivation);
    return resolver->Promise();
  }

  GetDispatcherHost(window->GetFrame())
      .SelectAudioOutput(
          options->hasDeviceId() ? options->deviceId() : String(),
          WTF::BindOnce(&MediaDevices::OnSelectAudioOutputResult,
                        WrapPersistent(this), WrapPersistent(resolver)));

  return resolver->Promise();
}

void MediaDevices::OnSelectAudioOutputResult(
    ScriptPromiseResolverWithTracker<AudioOutputSelectionResult,
                                     MediaDeviceInfo>* resolver,
    mojom::blink::SelectAudioOutputResultPtr result) {
  if (result->status == mojom::blink::AudioOutputStatus::kSuccess) {
    MediaDeviceInfo* media_device_info = MakeGarbageCollected<MediaDeviceInfo>(
        String::FromUTF8(result->device_info.device_id),
        String::FromUTF8(result->device_info.label),
        String::FromUTF8(result->device_info.group_id),
        mojom::MediaDeviceType::kMediaAudioOutput);
    resolver->Resolve(media_device_info, AudioOutputSelectionResult::kSuccess);
    return;
  } else {
    String error_message;
    DOMExceptionCode exception_code = DOMExceptionCode::kUnknownError;
    AudioOutputSelectionResult result_enum =
        AudioOutputSelectionResult::kOtherError;

    switch (result->status) {
      case mojom::blink::AudioOutputStatus::kNoPermission:
        error_message = "Permission denied to select audio output.";
        exception_code = DOMExceptionCode::kNotAllowedError;
        result_enum = AudioOutputSelectionResult::kPermissionDenied;
        break;
      case mojom::blink::AudioOutputStatus::kNoDevices:
        error_message = "No audio output devices found.";
        exception_code = DOMExceptionCode::kNotFoundError;
        result_enum = AudioOutputSelectionResult::kNoDevices;
        break;
      case mojom::blink::AudioOutputStatus::kNotSupported:
        error_message = "Audio output is not supported.";
        exception_code = DOMExceptionCode::kInvalidStateError;
        result_enum = AudioOutputSelectionResult::kNotSupported;
        break;
      case mojom::blink::AudioOutputStatus::kNoUserActivation:
        error_message =
            "selectAudioOutput() requires transient activation (user gesture).";
        exception_code = DOMExceptionCode::kInvalidStateError;
        result_enum = AudioOutputSelectionResult::kNoUserActivation;
        break;
      default:
        error_message =
            "An unknown error occurred during audio output selection.";
        exception_code = DOMExceptionCode::kUnknownError;
        result_enum = AudioOutputSelectionResult::kOtherError;
    }

    resolver->Reject<DOMException>(
        MakeGarbageCollected<DOMException>(exception_code, error_message),
        result_enum);
  }
}

void MediaDevices::setCaptureHandleConfig(ScriptState* script_state,
                                          const CaptureHandleConfig* config,
                                          ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(config->hasExposeOrigin());
  DCHECK(config->hasHandle());

  if (config->handle().length() > 1024) {
    exception_state.ThrowTypeError(
        "Handle length exceeds 1024 16-bit characters.");
    return;
  }

  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Current frame is detached.");
 
"""


```