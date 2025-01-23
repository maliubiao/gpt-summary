Response:
The user wants me to analyze the provided C++ code snippet from the Chromium Blink engine.
The goal is to understand the functionality of the `user_media_request.cc` file.
I need to break down its responsibilities, identify connections to web technologies (JavaScript, HTML, CSS), illustrate logical flow with examples, point out potential user or programming errors, explain user interaction leading to this code, and finally summarize the file's purpose.

Here's a plan:
1. **Identify Core Functionality:** Analyze the class `UserMediaRequest` and its methods to understand its main responsibilities. Look for keywords related to media streams, constraints, and user requests.
2. **Relate to Web Technologies:**  Determine how the concepts in the code (like media streams, audio/video constraints) map to JavaScript APIs (e.g., `getUserMedia`, `getDisplayMedia`) used in web development.
3. **Illustrate Logic with Examples:**  Create hypothetical scenarios of JavaScript calls and trace how the parameters might be processed by the C++ code. Show input constraints and the expected outcome (e.g., requesting audio with specific sample rate).
4. **Identify Potential Errors:** Think about common mistakes developers might make when using the related JavaScript APIs and how the C++ code handles or might be affected by those errors (e.g., requesting both audio and video as `false`).
5. **Describe User Interaction:**  Outline the steps a user takes in a web browser that would trigger the `getUserMedia` or `getDisplayMedia` calls, ultimately leading to this C++ code being executed.
6. **Summarize Functionality:** Concisely describe the overall purpose of the `user_media_request.cc` file based on the analysis.
这是对 `blink/renderer/modules/mediastream/user_media_request.cc` 文件的功能归纳，基于提供的代码片段：

**功能归纳：**

`user_media_request.cc` 文件主要负责处理来自网页 JavaScript 的 `getUserMedia` 和 `getDisplayMedia` 请求。它将这些请求中指定的媒体约束（audio 和 video）解析并转化为内部的数据结构，以便 Blink 引擎能够理解和处理。该文件还负责进行一些初步的参数校验和错误处理，并记录一些使用情况的统计信息。

**具体功能点：**

1. **创建 `UserMediaRequest` 对象:**  `UserMediaRequest::Create` 方法是该文件的核心，负责根据 JavaScript 传递的 `MediaStreamConstraints` 对象创建 `UserMediaRequest` 实例。这个过程包括：
    * **解析媒体约束:** 将 JavaScript 的 `MediaTrackConstraints` 对象（分别对应 audio 和 video）解析为 Blink 内部的 `MediaConstraints` 对象。
    * **参数校验:** 检查约束的有效性，例如确保至少请求了 audio 或 video 中的一个，以及针对 `getDisplayMedia` 请求的特定约束限制（例如不允许使用 `advanced` 约束，不允许 `min` 或 `exact` 等）。
    * **错误处理:**  如果解析或校验过程中发现错误，会抛出 JavaScript 异常 (`TypeError`)。
    * **记录使用统计:** 使用 `UseCounter` 记录各种约束的使用情况，例如是否使用了 `sampleRate`、`facingMode` 等约束，以及是否请求了无约束的音视频流。
    * **处理 `getDisplayMedia` 特有参数:** 处理 `getDisplayMedia` 的特殊参数，如 `systemAudio`、`selfBrowserSurface`、`preferCurrentTab`、`surfaceSwitching`、`monitorTypeSurfaces` 和 `suppressLocalAudioPlayback`，并进行相应的校验和设置。

2. **管理媒体请求类型:** 区分 `getUserMedia` 和 `getDisplayMedia`/`getAllScreensMedia` 请求，并用 `UserMediaRequestType` 枚举表示。

3. **存储媒体约束:**  `UserMediaRequest` 对象内部存储了解析后的 audio 和 video 的 `MediaConstraints` 对象，供后续处理使用。

4. **确定媒体流类型:**  根据请求类型和约束条件，判断请求的媒体流类型（例如 `DEVICE_AUDIO_CAPTURE`、`DISPLAY_VIDEO_CAPTURE` 等），这对于后续的媒体设备选择和权限管理至关重要。

5. **检查安全上下文:**  `IsSecureContextUse` 方法用于检查发起 `getUserMedia` 请求的页面是否处于安全上下文（HTTPS），并在非安全上下文中记录弃用警告。

6. **启动媒体请求:** `Start` 方法会调用 `UserMediaClient` 的 `RequestUserMedia` 方法，将请求传递给更底层的媒体管理模块。

7. **处理请求成功回调:**  `Succeed` 方法在媒体设备成功获取后被调用，它会根据获取到的 `MediaStreamDescriptor` 创建 `MediaStreamSet` 对象，并触发后续的媒体流初始化流程。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** 该文件直接响应 JavaScript 的 `navigator.mediaDevices.getUserMedia()` 和 `navigator.mediaDevices.getDisplayMedia()` 方法调用。JavaScript 代码中传递的约束对象会被该文件解析。
    * **举例:**
        * **JavaScript 输入:**
          ```javascript
          navigator.mediaDevices.getUserMedia({ audio: true, video: { facingMode: "user" } })
            .then(stream => { /* 使用 stream */ })
            .catch(error => { /* 处理错误 */ });
          ```
        * **C++ 处理:** `UserMediaRequest::Create` 会接收到 `audio: true` 和 `video: { facingMode: "user" }` 对应的约束信息，解析并存储在 `UserMediaRequest` 对象的 `audio_` 和 `video_` 成员中。`facingMode: "user"` 会被识别并记录到使用统计中。

* **HTML:**  HTML 页面通过 `<script>` 标签引入 JavaScript 代码，这些 JavaScript 代码可以调用 `getUserMedia` 或 `getDisplayMedia`。
    * **举例:** 用户在 HTML 页面上点击一个按钮，触发一个 JavaScript 函数，该函数调用 `getUserMedia` 请求摄像头权限。

* **CSS:**  CSS 本身与 `user_media_request.cc` 的直接功能关联较弱。CSS 主要负责页面的样式和布局，但媒体流最终可能会被渲染到 HTML 的 `<video>` 或 `<a>` (作为下载) 元素中，而这些元素的样式可以通过 CSS 控制。

**逻辑推理的假设输入与输出：**

**假设输入：**

* **场景 1 (getUserMedia):** JavaScript 请求同时获取音频和视频，并指定了理想的视频宽度和高度。
    ```javascript
    navigator.mediaDevices.getUserMedia({
      audio: true,
      video: { width: { ideal: 1280 }, height: { ideal: 720 } }
    });
    ```
* **场景 2 (getDisplayMedia):** JavaScript 请求屏幕共享，并指定排除系统音频。
    ```javascript
    navigator.mediaDevices.getDisplayMedia({ video: true, audio: { systemAudio: "exclude" } });
    ```

**逻辑推理与输出 (部分):**

* **场景 1:**
    * **输入:**  `options->audio()` 为真，`options->video()` 为真，视频约束包含 `width: { ideal: 1280 }` 和 `height: { ideal: 720 }`。
    * **C++ 处理:** `UserMediaRequest::Create` 会成功解析约束，创建 `UserMediaRequest` 对象，并将 `WebFeature::kMediaStreamConstraintsWidth` 和 `WebFeature::kMediaStreamConstraintsHeight` 计入使用统计。`Audio()` 和 `Video()` 方法会返回 `true`。`AudioMediaStreamType()` 返回 `DEVICE_AUDIO_CAPTURE`，`VideoMediaStreamType()` 返回 `DEVICE_VIDEO_CAPTURE`。
* **场景 2:**
    * **输入:** `options->video()` 为真，`options->hasSystemAudio()` 为真，`options->systemAudio().AsEnum()` 为 `V8DisplayMediaIncludeOrExclude::Enum::kExclude`。
    * **C++ 处理:** `UserMediaRequest::Create` 会成功解析约束，创建 `UserMediaRequest` 对象，并将 `exclude_system_audio_` 设置为 `true`。`RecordGetDisplayMediaIncludeExcludeConstraintUma` 函数会被调用，记录 `Media.GetDisplayMedia.Constraints.SystemAudio` 的值为 `kExclude`。

**用户或编程常见的使用错误：**

1. **未请求任何媒体类型:**
   * **JavaScript:** `navigator.mediaDevices.getUserMedia({});` 或 `navigator.mediaDevices.getUserMedia({ audio: false, video: false });`
   * **C++ 处理:** `UserMediaRequest::Create` 中会抛出 `TypeError: At least one of audio and video must be requested`。

2. **在 `getDisplayMedia` 中使用 `advanced` 约束:**
   * **JavaScript:**
     ```javascript
     navigator.mediaDevices.getDisplayMedia({ video: { advanced: [{ frameRate: { min: 30 } }] } });
     ```
   * **C++ 处理:** `UserMediaRequest::Create` 中会抛出 `TypeError: Advanced constraints are not supported`。

3. **在 `getDisplayMedia` 中使用 `min` 或 `exact` 约束:**
   * **JavaScript:** `navigator.mediaDevices.getDisplayMedia({ video: { width: { min: 100 } } });`
   * **C++ 处理:** `UserMediaRequest::Create` 中会抛出相应的 `TypeError` (例如 "min constraints are not supported")。

4. **在非安全上下文中使用 `getUserMedia`:**
   * **用户操作:** 在非 HTTPS 页面上调用 `getUserMedia`。
   * **C++ 处理:** `IsSecureContextUse` 方法会返回 `false`，并且在控制台记录弃用警告。

5. **`preferCurrentTab` 和 `selfBrowserSurface=exclude` 同时使用 (自相矛盾):**
   * **JavaScript:** `navigator.mediaDevices.getDisplayMedia({ preferCurrentTab: true, selfBrowserSurface: "exclude" });`
   * **C++ 处理:** `UserMediaRequest::Create` 中会抛出 `TypeError: Self-contradictory configuration (preferCurrentTab and selfBrowserSurface=exclude).`

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个网页:** 用户在 Chrome 浏览器中访问一个包含 WebRTC 功能的网页。
2. **网页 JavaScript 执行:** 网页的 JavaScript 代码被执行。
3. **调用 `getUserMedia` 或 `getDisplayMedia`:** JavaScript 代码调用了 `navigator.mediaDevices.getUserMedia(constraints)` 或 `navigator.mediaDevices.getDisplayMedia(options)`，并传入了包含媒体约束的对象。
4. **Blink 引擎接收请求:** 浏览器内核（Blink 引擎）接收到这个 JavaScript 请求。
5. **创建 `UserMediaRequest` 对象:** Blink 引擎会调用 `user_media_request.cc` 中的 `UserMediaRequest::Create` 方法，根据 JavaScript 传递的约束参数创建一个 `UserMediaRequest` 对象。
6. **参数解析和校验:** `UserMediaRequest::Create` 方法会对传入的约束进行解析、校验，并记录使用统计。
7. **权限请求:**  `UserMediaRequest` 对象会被传递给 `UserMediaClient`，最终触发浏览器向用户请求摄像头、麦克风或屏幕共享的权限。
8. **设备选择和媒体流创建:** 如果用户授予权限，Blink 引擎会选择合适的媒体设备并创建媒体流。
9. **`Succeed` 回调:**  媒体流创建成功后，`UserMediaRequest::Succeed` 方法会被调用，通知 JavaScript 代码媒体流已就绪。

**调试线索:**  如果在调试 WebRTC 应用时遇到问题，例如权限请求失败、媒体流获取失败或约束不生效，可以关注以下几点：

* **检查 JavaScript 代码中的约束对象:**  确认传递给 `getUserMedia` 或 `getDisplayMedia` 的约束对象是否符合预期。
* **查看浏览器控制台的错误信息:**  如果约束有误，`UserMediaRequest::Create` 可能会抛出 `TypeError`，这些错误信息会显示在浏览器的开发者工具控制台中。
* **使用 `chrome://webrtc-internals`:**  Chrome 浏览器提供的 `chrome://webrtc-internals` 页面可以查看详细的 WebRTC 事件日志，包括 `getUserMedia` 和 `getDisplayMedia` 请求的详细信息，有助于追踪问题的根源。
* **断点调试 C++ 代码:**  对于更深入的调试，可以在 `user_media_request.cc` 中设置断点，逐步跟踪代码的执行流程，查看约束是如何被解析和处理的。

总结来说，`user_media_request.cc` 是 Blink 引擎中处理 WebRTC 媒体请求的关键组件，它连接了 JavaScript API 和底层的媒体管理功能，负责约束的解析、校验和初步处理。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/user_media_request.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Ericsson AB. All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of Ericsson nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/mediastream/user_media_request.h"

#include <type_traits>

#include "base/metrics/histogram_functions.h"
#include "base/strings/stringprintf.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_track_constraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_boolean_mediatrackconstraints.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_domexception_overconstrainederror.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/space_split_string.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/mediastream/capture_controller.h"
#include "third_party/blink/renderer/modules/mediastream/identifiability_metrics.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_set.h"
#include "third_party/blink/renderer/modules/mediastream/overconstrained_error.h"
#include "third_party/blink/renderer/modules/mediastream/transferred_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_tracker.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

using mojom::blink::MediaStreamType;
using Result = mojom::blink::MediaStreamRequestResult;

namespace {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class GetDisplayMediaIncludeExcludeConstraint {
  kNotSpecified = 0,
  kInclude = 1,
  kExclude = 2,
  kMaxValue = kExclude
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class GetDisplayMediaConstraintsDisplaySurface {
  kNotSpecified = 0,
  kTab = 1,
  kWindow = 2,
  kMonitor = 3,
  kMaxValue = kMonitor
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class GetDisplayMediaBooleanConstraint {
  kNotSpecified = 0,
  kTrue = 1,
  kFalse = 2,
  kMaxValue = kFalse
};

void RecordUma(GetDisplayMediaConstraintsDisplaySurface value) {
  base::UmaHistogramEnumeration(
      "Media.GetDisplayMedia.Constraints.DisplaySurface", value);
}

template <typename NumericConstraint>
bool SetUsesNumericConstraint(
    const MediaTrackConstraintSetPlatform& set,
    NumericConstraint MediaTrackConstraintSetPlatform::*field) {
  return (set.*field).HasExact() || (set.*field).HasIdeal() ||
         (set.*field).HasMin() || (set.*field).HasMax();
}

template <typename DiscreteConstraint>
bool SetUsesDiscreteConstraint(
    const MediaTrackConstraintSetPlatform& set,
    DiscreteConstraint MediaTrackConstraintSetPlatform::*field) {
  return (set.*field).HasExact() || (set.*field).HasIdeal();
}

template <typename NumericConstraint>
bool RequestUsesNumericConstraint(
    const MediaConstraints& constraints,
    NumericConstraint MediaTrackConstraintSetPlatform::*field) {
  if (SetUsesNumericConstraint(constraints.Basic(), field))
    return true;
  for (const auto& advanced_set : constraints.Advanced()) {
    if (SetUsesNumericConstraint(advanced_set, field))
      return true;
  }
  return false;
}

template <typename DiscreteConstraint>
bool RequestUsesDiscreteConstraint(
    const MediaConstraints& constraints,
    DiscreteConstraint MediaTrackConstraintSetPlatform::*field) {
  static_assert(
      std::is_same<
          decltype(field),
          StringConstraint MediaTrackConstraintSetPlatform::*>::value ||
          std::is_same<
              decltype(field),
              BooleanConstraint MediaTrackConstraintSetPlatform::*>::value,
      "Must use StringConstraint or BooleanConstraint");
  if (SetUsesDiscreteConstraint(constraints.Basic(), field))
    return true;
  for (const auto& advanced_set : constraints.Advanced()) {
    if (SetUsesDiscreteConstraint(advanced_set, field))
      return true;
  }
  return false;
}

class FeatureCounter {
 public:
  explicit FeatureCounter(ExecutionContext* context)
      : context_(context), is_unconstrained_(true) {}

  FeatureCounter(const FeatureCounter&) = delete;
  FeatureCounter& operator=(const FeatureCounter&) = delete;

  void Count(WebFeature feature) {
    UseCounter::Count(context_, feature);
    is_unconstrained_ = false;
  }

  void CountDeprecation(WebFeature feature) {
    UseCounter::CountDeprecation(context_, feature);
    is_unconstrained_ = false;
  }

  bool IsUnconstrained() { return is_unconstrained_; }

 private:
  Persistent<ExecutionContext> context_;
  bool is_unconstrained_;
};

void CountAudioConstraintUses(ExecutionContext* context,
                              const MediaConstraints& constraints) {
  FeatureCounter counter(context);
  if (RequestUsesNumericConstraint(
          constraints, &MediaTrackConstraintSetPlatform::sample_rate)) {
    counter.Count(WebFeature::kMediaStreamConstraintsSampleRate);
  }
  if (RequestUsesNumericConstraint(
          constraints, &MediaTrackConstraintSetPlatform::sample_size)) {
    counter.Count(WebFeature::kMediaStreamConstraintsSampleSize);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::echo_cancellation)) {
    counter.Count(WebFeature::kMediaStreamConstraintsEchoCancellation);
  }
  if (RequestUsesNumericConstraint(constraints,
                                   &MediaTrackConstraintSetPlatform::latency)) {
    counter.Count(WebFeature::kMediaStreamConstraintsLatency);
  }
  if (RequestUsesNumericConstraint(
          constraints, &MediaTrackConstraintSetPlatform::channel_count)) {
    counter.Count(WebFeature::kMediaStreamConstraintsChannelCount);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::device_id)) {
    counter.Count(WebFeature::kMediaStreamConstraintsDeviceIdAudio);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::disable_local_echo)) {
    counter.Count(WebFeature::kMediaStreamConstraintsDisableLocalEcho);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::group_id)) {
    counter.Count(WebFeature::kMediaStreamConstraintsGroupIdAudio);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::media_stream_source)) {
    counter.Count(WebFeature::kMediaStreamConstraintsMediaStreamSourceAudio);
  }
  if (RequestUsesDiscreteConstraint(
          constraints,
          &MediaTrackConstraintSetPlatform::render_to_associated_sink)) {
    counter.Count(WebFeature::kMediaStreamConstraintsRenderToAssociatedSink);
  }
  if (RequestUsesDiscreteConstraint(
          constraints,
          &MediaTrackConstraintSetPlatform::goog_echo_cancellation)) {
    counter.CountDeprecation(
        WebFeature::kMediaStreamConstraintsGoogEchoCancellation);
  }
  if (RequestUsesDiscreteConstraint(constraints,
                                    &MediaTrackConstraintSetPlatform::
                                        goog_experimental_echo_cancellation)) {
    counter.CountDeprecation(
        WebFeature::kMediaStreamConstraintsGoogExperimentalEchoCancellation);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::auto_gain_control)) {
    counter.Count(WebFeature::kMediaStreamConstraintsGoogAutoGainControl);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::noise_suppression)) {
    counter.Count(WebFeature::kMediaStreamConstraintsGoogNoiseSuppression);
  }
  if (RequestUsesDiscreteConstraint(
          constraints,
          &MediaTrackConstraintSetPlatform::goog_highpass_filter)) {
    counter.CountDeprecation(
        WebFeature::kMediaStreamConstraintsGoogHighpassFilter);
  }
  if (RequestUsesDiscreteConstraint(constraints,
                                    &MediaTrackConstraintSetPlatform::
                                        goog_experimental_noise_suppression)) {
    counter.CountDeprecation(
        WebFeature::kMediaStreamConstraintsGoogExperimentalNoiseSuppression);
  }
  if (RequestUsesDiscreteConstraint(
          constraints,
          &MediaTrackConstraintSetPlatform::goog_audio_mirroring)) {
    counter.CountDeprecation(
        WebFeature::kMediaStreamConstraintsGoogAudioMirroring);
  }
  if (RequestUsesDiscreteConstraint(
          constraints,
          &MediaTrackConstraintSetPlatform::goog_da_echo_cancellation)) {
    counter.CountDeprecation(
        WebFeature::kMediaStreamConstraintsGoogDAEchoCancellation);
  }

  UseCounter::Count(context, WebFeature::kMediaStreamConstraintsAudio);
  if (counter.IsUnconstrained()) {
    UseCounter::Count(context,
                      WebFeature::kMediaStreamConstraintsAudioUnconstrained);
  }
}

void CountVideoConstraintUses(ExecutionContext* context,
                              const MediaConstraints& constraints) {
  FeatureCounter counter(context);
  if (RequestUsesNumericConstraint(constraints,
                                   &MediaTrackConstraintSetPlatform::width)) {
    counter.Count(WebFeature::kMediaStreamConstraintsWidth);
  }
  if (RequestUsesNumericConstraint(constraints,
                                   &MediaTrackConstraintSetPlatform::height)) {
    counter.Count(WebFeature::kMediaStreamConstraintsHeight);
  }
  if (RequestUsesNumericConstraint(
          constraints, &MediaTrackConstraintSetPlatform::aspect_ratio)) {
    counter.Count(WebFeature::kMediaStreamConstraintsAspectRatio);
  }
  if (RequestUsesNumericConstraint(
          constraints, &MediaTrackConstraintSetPlatform::frame_rate)) {
    counter.Count(WebFeature::kMediaStreamConstraintsFrameRate);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::facing_mode)) {
    counter.Count(WebFeature::kMediaStreamConstraintsFacingMode);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::device_id)) {
    counter.Count(WebFeature::kMediaStreamConstraintsDeviceIdVideo);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::group_id)) {
    counter.Count(WebFeature::kMediaStreamConstraintsGroupIdVideo);
  }
  if (RequestUsesDiscreteConstraint(
          constraints, &MediaTrackConstraintSetPlatform::media_stream_source)) {
    counter.Count(WebFeature::kMediaStreamConstraintsMediaStreamSourceVideo);
  }
  if (RequestUsesDiscreteConstraint(
          constraints,
          &MediaTrackConstraintSetPlatform::goog_noise_reduction)) {
    counter.Count(WebFeature::kMediaStreamConstraintsGoogNoiseReduction);
  }

  UseCounter::Count(context, WebFeature::kMediaStreamConstraintsVideo);
  if (counter.IsUnconstrained()) {
    UseCounter::Count(context,
                      WebFeature::kMediaStreamConstraintsVideoUnconstrained);
  }
}

void RecordGetDisplayMediaIncludeExcludeConstraintUma(
    std::optional<V8DisplayMediaIncludeOrExclude::Enum> include_or_exclude,
    const std::string& histogram_name) {
  const GetDisplayMediaIncludeExcludeConstraint value =
      (!include_or_exclude.has_value()
           ? GetDisplayMediaIncludeExcludeConstraint::kNotSpecified
       : include_or_exclude == V8DisplayMediaIncludeOrExclude::Enum::kInclude
           ? GetDisplayMediaIncludeExcludeConstraint::kInclude
           : GetDisplayMediaIncludeExcludeConstraint::kExclude);
  base::UmaHistogramEnumeration(histogram_name, value);
}

void RecordPreferredDisplaySurfaceConstraintUma(
    const mojom::blink::PreferredDisplaySurface preferred_display_surface) {
  switch (preferred_display_surface) {
    case mojom::blink::PreferredDisplaySurface::NO_PREFERENCE:
      RecordUma(GetDisplayMediaConstraintsDisplaySurface::kNotSpecified);
      return;
    case mojom::blink::PreferredDisplaySurface::MONITOR:
      RecordUma(GetDisplayMediaConstraintsDisplaySurface::kMonitor);
      return;
    case mojom::blink::PreferredDisplaySurface::WINDOW:
      RecordUma(GetDisplayMediaConstraintsDisplaySurface::kWindow);
      return;
    case mojom::blink::PreferredDisplaySurface::BROWSER:
      RecordUma(GetDisplayMediaConstraintsDisplaySurface::kTab);
      return;
  }
  NOTREACHED();
}

void RecordSuppressLocalAudioPlaybackConstraintUma(
    std::optional<bool> suppress_local_audio_playback) {
  const GetDisplayMediaBooleanConstraint value =
      (!suppress_local_audio_playback.has_value()
           ? GetDisplayMediaBooleanConstraint::kNotSpecified
       : suppress_local_audio_playback.value()
           ? GetDisplayMediaBooleanConstraint::kTrue
           : GetDisplayMediaBooleanConstraint::kFalse);
  base::UmaHistogramEnumeration(
      "Media.GetDisplayMedia.Constraints.SuppressLocalAudioPlayback", value);
}

MediaConstraints ParseOptions(
    ExecutionContext* execution_context,
    const V8UnionBooleanOrMediaTrackConstraints* options,
    ExceptionState& exception_state) {
  if (!options)
    return MediaConstraints();
  switch (options->GetContentType()) {
    case V8UnionBooleanOrMediaTrackConstraints::ContentType::kBoolean:
      if (options->GetAsBoolean())
        return media_constraints_impl::Create();
      else
        return MediaConstraints();
    case V8UnionBooleanOrMediaTrackConstraints::ContentType::
        kMediaTrackConstraints:
      String error_message;
      auto constraints = media_constraints_impl::Create(
          execution_context, options->GetAsMediaTrackConstraints(),
          error_message);
      if (constraints.IsNull()) {
        exception_state.ThrowTypeError(error_message);
      }
      return constraints;
  }
  NOTREACHED();
}

}  // namespace

UserMediaRequest* UserMediaRequest::Create(
    ExecutionContext* context,
    UserMediaClient* client,
    UserMediaRequestType media_type,
    const MediaStreamConstraints* options,
    Callbacks* callbacks,
    ExceptionState& exception_state,
    IdentifiableSurface surface) {
  MediaConstraints audio =
      ParseOptions(context, options->audio(), exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  MediaConstraints video =
      ParseOptions(context, options->video(), exception_state);
  if (exception_state.HadException()) {
    return nullptr;
  }

  std::string display_surface_constraint;
  std::optional<bool> suppress_local_audio_playback;

  if (media_type == UserMediaRequestType::kUserMedia) {
    if (audio.IsNull() && video.IsNull()) {
      exception_state.ThrowTypeError(
          "At least one of audio and video must be requested");
      return nullptr;
    } else if (!video.IsNull()) {
      auto& video_basic = video.MutableBasic();
      const BaseConstraint* constraints[] = {
          &video_basic.pan,
          &video_basic.tilt,
          &video_basic.zoom,
          &video_basic.background_blur,
          &video_basic.background_segmentation_mask,
          &video_basic.eye_gaze_correction,
          &video_basic.face_framing,
      };
      for (const BaseConstraint* constraint : constraints) {
        if (constraint->HasMandatory()) {
          exception_state.ThrowTypeError(
              String::Format("Mandatory %s constraints are not supported",
                             constraint->GetName()));
          return nullptr;
        }
      }
      BaseConstraint* compatibility_constraints[] = {
          &video_basic.exposure_compensation,
          &video_basic.exposure_time,
          &video_basic.color_temperature,
          &video_basic.iso,
          &video_basic.brightness,
          &video_basic.contrast,
          &video_basic.saturation,
          &video_basic.sharpness,
          &video_basic.focus_distance,
          &video_basic.torch,
      };
      for (BaseConstraint* constraint : compatibility_constraints) {
        if (constraint->HasMandatory()) {
          // This should throw a TypeError, but that cannot be done due
          // to backward compatibility.
          // Thus instead of that, let's ignore the constraint.
          constraint->ResetToUnconstrained();
        }
      }
    }
  } else if (media_type == UserMediaRequestType::kDisplayMedia ||
             media_type == UserMediaRequestType::kAllScreensMedia) {
    // https://w3c.github.io/mediacapture-screen-share/#mediadevices-additions
    // MediaDevices Additions
    // The user agent MUST reject audio-only requests.
    // 1. Let constraints be the method's first argument.
    // 2. For each member present in constraints whose value, value, is a
    // dictionary, run the following steps:
    //   1. If value contains a member named advanced, return a promise rejected
    //   with a newly created TypeError.
    //   2. If value contains a member which in turn is a dictionary containing
    //   a member named either min or exact, return a promise rejected with a
    //   newly created TypeError.
    // 3. Let requestedMediaTypes be the set of media types in constraints with
    // either a dictionary value or a value of true.
    if (media_type == UserMediaRequestType::kAllScreensMedia) {
      if (!audio.IsNull()) {
        exception_state.ThrowTypeError("Audio requests are not supported");
        return nullptr;
      } else if (options->preferCurrentTab()) {
        exception_state.ThrowTypeError("preferCurrentTab is not supported");
        return nullptr;
      }
    }

    if (audio.IsNull() && video.IsNull()) {
      exception_state.ThrowTypeError("either audio or video must be requested");
      return nullptr;
    }

    if ((!audio.IsNull() && !audio.Advanced().empty()) ||
        (!video.IsNull() && !video.Advanced().empty())) {
      exception_state.ThrowTypeError("Advanced constraints are not supported");
      return nullptr;
    }

    if ((!audio.IsNull() && audio.Basic().HasMin()) ||
        (!video.IsNull() && video.Basic().HasMin())) {
      exception_state.ThrowTypeError("min constraints are not supported");
      return nullptr;
    }

    if ((!audio.IsNull() && audio.Basic().HasExact()) ||
        (!video.IsNull() && video.Basic().HasExact())) {
      exception_state.ThrowTypeError("exact constraints are not supported");
      return nullptr;
    }

    if (!video.IsNull() && video.Basic().display_surface.HasIdeal() &&
        video.Basic().display_surface.Ideal().size() > 0) {
      display_surface_constraint =
          video.Basic().display_surface.Ideal()[0].Utf8();
    }

    if (!audio.IsNull() &&
        audio.Basic().suppress_local_audio_playback.HasIdeal()) {
      suppress_local_audio_playback =
          audio.Basic().suppress_local_audio_playback.Ideal();
    }
  }

  if (!audio.IsNull())
    CountAudioConstraintUses(context, audio);
  if (!video.IsNull())
    CountVideoConstraintUses(context, video);

  UserMediaRequest* const result = MakeGarbageCollected<UserMediaRequest>(
      context, client, media_type, audio, video, options->preferCurrentTab(),
      options->getControllerOr(nullptr), callbacks, surface);

  // The default is to include.
  // Note that this option is no-op if audio is not requested.
  result->set_exclude_system_audio(
      options->hasSystemAudio() &&
      options->systemAudio().AsEnum() ==
          V8DisplayMediaIncludeOrExclude::Enum::kExclude);
  if (media_type == UserMediaRequestType::kDisplayMedia) {
    std::optional<V8DisplayMediaIncludeOrExclude::Enum> include_or_exclude;
    if (options->hasSystemAudio()) {
      include_or_exclude = options->systemAudio().AsEnum();
    }
    RecordGetDisplayMediaIncludeExcludeConstraintUma(
        include_or_exclude, "Media.GetDisplayMedia.Constraints.SystemAudio");
  }

  // The default is to include.
  const bool exclude_self_browser_surface =
      options->hasSelfBrowserSurface() &&
      options->selfBrowserSurface().AsEnum() ==
          V8DisplayMediaIncludeOrExclude::Enum::kExclude;
  if (exclude_self_browser_surface && options->preferCurrentTab()) {
    exception_state.ThrowTypeError(
        "Self-contradictory configuration (preferCurrentTab and "
        "selfBrowserSurface=exclude).");
    return nullptr;
  }
  result->set_exclude_self_browser_surface(exclude_self_browser_surface);
  if (media_type == UserMediaRequestType::kDisplayMedia) {
    std::optional<V8DisplayMediaIncludeOrExclude::Enum> include_or_exclude;
    if (options->hasSelfBrowserSurface()) {
      include_or_exclude = options->selfBrowserSurface().AsEnum();
    }
    RecordGetDisplayMediaIncludeExcludeConstraintUma(
        include_or_exclude,
        "Media.GetDisplayMedia.Constraints.SelfBrowserSurface");
  }

  mojom::blink::PreferredDisplaySurface preferred_display_surface =
      mojom::blink::PreferredDisplaySurface::NO_PREFERENCE;
  if (display_surface_constraint == "monitor") {
    preferred_display_surface = mojom::blink::PreferredDisplaySurface::MONITOR;
  } else if (display_surface_constraint == "window") {
    preferred_display_surface = mojom::blink::PreferredDisplaySurface::WINDOW;
  } else if (display_surface_constraint == "browser") {
    preferred_display_surface = mojom::blink::PreferredDisplaySurface::BROWSER;
  }
  result->set_preferred_display_surface(preferred_display_surface);
  if (media_type == UserMediaRequestType::kDisplayMedia)
    RecordPreferredDisplaySurfaceConstraintUma(preferred_display_surface);

  // The default is to request dynamic surface switching.
  result->set_dynamic_surface_switching_requested(
      !options->hasSurfaceSwitching() ||
      options->surfaceSwitching().AsEnum() ==
          V8DisplayMediaIncludeOrExclude::Enum::kInclude);
  if (media_type == UserMediaRequestType::kDisplayMedia) {
    std::optional<V8DisplayMediaIncludeOrExclude::Enum> include_or_exclude;
    if (options->hasSurfaceSwitching()) {
      include_or_exclude = options->surfaceSwitching().AsEnum();
    }
    RecordGetDisplayMediaIncludeExcludeConstraintUma(
        include_or_exclude,
        "Media.GetDisplayMedia.Constraints.SurfaceSwitching");
  }

  // The default is to include.
  const bool exclude_monitor_type_surfaces =
      options->hasMonitorTypeSurfaces() &&
      options->monitorTypeSurfaces().AsEnum() ==
          V8DisplayMediaIncludeOrExclude::Enum::kExclude;
  if (exclude_monitor_type_surfaces &&
      display_surface_constraint == "monitor") {
    exception_state.ThrowTypeError(
        "Self-contradictory configuration (displaySurface=monitor and "
        "monitorTypeSurfaces=exclude).");
    return nullptr;
  }
  result->set_exclude_monitor_type_surfaces(exclude_monitor_type_surfaces);
  if (media_type == UserMediaRequestType::kDisplayMedia) {
    std::optional<V8DisplayMediaIncludeOrExclude::Enum> include_or_exclude;
    if (options->hasMonitorTypeSurfaces()) {
      include_or_exclude = options->monitorTypeSurfaces().AsEnum();
    }
    RecordGetDisplayMediaIncludeExcludeConstraintUma(
        include_or_exclude,
        "Media.GetDisplayMedia.Constraints.MonitorTypeSurfaces");
  }

  result->set_suppress_local_audio_playback(
      suppress_local_audio_playback.value_or(false));
  if (media_type == UserMediaRequestType::kDisplayMedia) {
    RecordSuppressLocalAudioPlaybackConstraintUma(
        suppress_local_audio_playback);
  }

  return result;
}

UserMediaRequest* UserMediaRequest::CreateForTesting(
    const MediaConstraints& audio,
    const MediaConstraints& video) {
  return MakeGarbageCollected<UserMediaRequest>(
      nullptr, nullptr, UserMediaRequestType::kUserMedia, audio, video,
      /*should_prefer_current_tab=*/false,
      /*capture_controller=*/nullptr, /*callbacks=*/nullptr,
      IdentifiableSurface());
}

UserMediaRequest::UserMediaRequest(ExecutionContext* context,
                                   UserMediaClient* client,
                                   UserMediaRequestType media_type,
                                   MediaConstraints audio,
                                   MediaConstraints video,
                                   bool should_prefer_current_tab,
                                   CaptureController* capture_controller,
                                   Callbacks* callbacks,
                                   IdentifiableSurface surface)
    : ExecutionContextLifecycleObserver(context),
      media_type_(media_type),
      audio_(audio),
      video_(video),
      capture_controller_(capture_controller),
      should_prefer_current_tab_(should_prefer_current_tab),
      should_disable_hardware_noise_suppression_(
          RuntimeEnabledFeatures::DisableHardwareNoiseSuppressionEnabled(
              context)),
      client_(client),
      callbacks_(callbacks),
      surface_(surface) {
  if (should_disable_hardware_noise_suppression_) {
    UseCounter::Count(context,
                      WebFeature::kUserMediaDisableHardwareNoiseSuppression);
  }
}

UserMediaRequest::~UserMediaRequest() = default;

UserMediaRequestType UserMediaRequest::MediaRequestType() const {
  return media_type_;
}

bool UserMediaRequest::Audio() const {
  return !audio_.IsNull();
}

bool UserMediaRequest::Video() const {
  return !video_.IsNull();
}

MediaConstraints UserMediaRequest::AudioConstraints() const {
  return audio_;
}

MediaConstraints UserMediaRequest::VideoConstraints() const {
  return video_;
}

MediaStreamType UserMediaRequest::AudioMediaStreamType() const {
  if (!Audio()) {
    return MediaStreamType::NO_SERVICE;
  }
  if (MediaRequestType() == UserMediaRequestType::kDisplayMedia) {
    return MediaStreamType::DISPLAY_AUDIO_CAPTURE;
  }
  if (MediaRequestType() == UserMediaRequestType::kAllScreensMedia) {
    return MediaStreamType::NO_SERVICE;
  }
  DCHECK_EQ(UserMediaRequestType::kUserMedia, MediaRequestType());

  // Check if this is a getUserMedia display capture.
  const MediaConstraints& constraints = AudioConstraints();
  String source_constraint =
      constraints.Basic().media_stream_source.Exact().empty()
          ? String()
          : String(constraints.Basic().media_stream_source.Exact()[0]);
  if (!source_constraint.empty()) {
    // This is a getUserMedia display capture call.
    if (source_constraint == blink::kMediaStreamSourceTab) {
      return MediaStreamType::GUM_TAB_AUDIO_CAPTURE;
    } else if (source_constraint == blink::kMediaStreamSourceDesktop ||
               source_constraint == blink::kMediaStreamSourceSystem) {
      return MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE;
    }
    return MediaStreamType::NO_SERVICE;
  }

  return MediaStreamType::DEVICE_AUDIO_CAPTURE;
}

MediaStreamType UserMediaRequest::VideoMediaStreamType() const {
  if (!Video()) {
    return MediaStreamType::NO_SERVICE;
  }
  if (MediaRequestType() == UserMediaRequestType::kDisplayMedia) {
    return should_prefer_current_tab()
               ? MediaStreamType::DISPLAY_VIDEO_CAPTURE_THIS_TAB
               : MediaStreamType::DISPLAY_VIDEO_CAPTURE;
  }
  if (MediaRequestType() == UserMediaRequestType::kAllScreensMedia) {
    DCHECK(!should_prefer_current_tab());
    return MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET;
  }
  DCHECK_EQ(UserMediaRequestType::kUserMedia, MediaRequestType());

  // Check if this is a getUserMedia display capture.
  const MediaConstraints& constraints = VideoConstraints();
  String source_constraint =
      constraints.Basic().media_stream_source.Exact().empty()
          ? String()
          : String(constraints.Basic().media_stream_source.Exact()[0]);
  if (!source_constraint.empty()) {
    // This is a getUserMedia display capture call.
    if (source_constraint == blink::kMediaStreamSourceTab) {
      return MediaStreamType::GUM_TAB_VIDEO_CAPTURE;
    } else if (source_constraint == blink::kMediaStreamSourceDesktop ||
               source_constraint == blink::kMediaStreamSourceScreen) {
      return MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE;
    }
    return MediaStreamType::NO_SERVICE;
  }

  return MediaStreamType::DEVICE_VIDEO_CAPTURE;
}

bool UserMediaRequest::ShouldDisableHardwareNoiseSuppression() const {
  return should_disable_hardware_noise_suppression_;
}

bool UserMediaRequest::IsSecureContextUse(String& error_message) {
  LocalDOMWindow* window = GetWindow();

  if (window->IsSecureContext(error_message)) {
    UseCounter::Count(window, WebFeature::kGetUserMediaSecureOrigin);
    window->CountUseOnlyInCrossOriginIframe(
        WebFeature::kGetUserMediaSecureOriginIframe);

    // Permissions policy deprecation messages.
    if (Audio()) {
      if (!window->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kMicrophone,
              ReportOptions::kReportOnFailure)) {
        UseCounter::Count(
            window, WebFeature::kMicrophoneDisabledByFeaturePolicyEstimate);
      }
    }
    if (Video() &&
        VideoMediaStreamType() != MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET) {
      if (!window->IsFeatureEnabled(
              mojom::blink::PermissionsPolicyFeature::kCamera,
              ReportOptions::kReportOnFailure)) {
        UseCounter::Count(window,
                          WebFeature::kCameraDisabledByFeaturePolicyEstimate);
      }
    }

    return true;
  }

  // While getUserMedia is blocked on insecure origins, we still want to
  // count attempts to use it.
  Deprecation::CountDeprecation(window,
                                WebFeature::kGetUserMediaInsecureOrigin);
  Deprecation::CountDeprecationCrossOriginIframe(
      window, WebFeature::kGetUserMediaInsecureOriginIframe);
  return false;
}

LocalDOMWindow* UserMediaRequest::GetWindow() {
  return To<LocalDOMWindow>(GetExecutionContext());
}

void UserMediaRequest::Start() {
  if (client_)
    client_->RequestUserMedia(this);
}

void UserMediaRequest::Succeed(
    const MediaStreamDescriptorVector& streams_descriptors) {
  DCHECK(!is_resolved_);
  DCHECK(transferred_track_ == nullptr);
  if (!GetExecutionContext())
    return;

  MediaStreamSet::Create(
      GetExecutionContext(), streams_descriptors, media_type_,
      WTF::BindOnce(&UserMediaRequest::OnMediaStreamsInitialized,
                    WrapPersistent(this)));
}

void UserMediaRequest::OnMediaStreamInitialized(MediaStream* stream) {
```