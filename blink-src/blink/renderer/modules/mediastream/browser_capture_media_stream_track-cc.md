Response:
Let's break down the thought process for analyzing this Chromium source code.

1. **Understand the Goal:** The request asks for the functionality of the `browser_capture_media_stream_track.cc` file, its relation to web technologies, examples of its usage, potential errors, and debugging information.

2. **Identify the Core Class:** The filename and the initial lines of the code immediately point to the `BrowserCaptureMediaStreamTrack` class. This is the central entity to understand.

3. **Examine Includes:** The `#include` directives provide clues about the class's dependencies and responsibilities:
    * `third_party/blink/...`: Indicates this is part of Blink, the rendering engine.
    * `modules/mediastream/...`:  Confirms it's related to media streams, a Web API.
    * `media/capture/...`:  Shows interaction with the browser's capture mechanisms.
    * `core/dom/...`:  Suggests it's a DOM object or interacts with DOM elements.
    * `platform/heap/...`: Hints at memory management within Blink.
    * `wtf/...`: Implies usage of Web Template Framework utilities.

4. **Analyze the Class Structure and Methods:** Read through the class definition and its methods. Focus on public methods as they represent the primary interface:
    * **Constructors:**  How is this class created? Notice the `MediaStreamComponent` argument, suggesting a connection to the underlying media stream implementation.
    * **`cropTo()` and `restrictTo()`:** These are the most prominent user-facing methods. They clearly relate to modifying the captured content.
    * **`clone()`:**  Standard for `MediaStreamTrack` objects.
    * **`ApplySubCaptureTarget()`:** A central, internal method called by `cropTo` and `restrictTo`. This is where the core logic resides.
    * **`OnResultFromBrowserProcess()` and `OnSubCaptureTargetVersionObserved()`:** These appear to be callbacks, likely from the browser process after an operation is initiated.
    * **`MaybeFinalizeCropPromise()`:** Suggests promise management and asynchronous operations.

5. **Focus on Key Functionality (The "What"):**
    * The class is responsible for managing a media stream track that originates from a browser capture (screen sharing, tab capture, etc.).
    * The key functionalities are `cropTo()` and `restrictTo()`, which allow JavaScript to programmatically define the visible portion of the captured stream. This is the core user-facing feature.

6. **Connect to Web Technologies (The "How" and "Where"):**
    * **JavaScript:** The methods are exposed to JavaScript, allowing web developers to control the capture. Think of the `MediaStreamTrack` API.
    * **HTML:**  The target of `cropTo` and `restrictTo` can be HTML elements. The `CropTarget` and `RestrictionTarget` classes likely wrap these elements.
    * **CSS (Indirectly):** While CSS doesn't directly interact with this C++ code, the positioning and sizing of HTML elements (influenced by CSS) determine the initial capture area and how cropping/restriction will affect the visible portion.

7. **Develop Examples (Concrete Usage):**
    *  Think about the scenarios where these methods would be used.
        * Cropping a specific window or element during screen sharing.
        * Restricting the captured area to a specific element to avoid showing sensitive information.
    * Craft basic JavaScript snippets demonstrating the usage of `cropTo()` and `restrictTo()`, emphasizing the asynchronous nature (Promises).

8. **Consider Logic and Data Flow (The "Why"):**
    * **Asynchronous Operations:** Recognize that `cropTo()` and `restrictTo()` are asynchronous. They involve communication with the browser process. Promises are used to handle the results.
    * **Inter-Process Communication:** The callbacks (`OnResultFromBrowserProcess`, `OnSubCaptureTargetVersionObserved`) indicate communication between the renderer process (where Blink runs) and the browser process.
    * **Unique Identifiers (Tokens):** The use of `base::Token` suggests a mechanism for uniquely identifying the target elements.

9. **Identify Potential Issues and Errors (The "What Could Go Wrong"):**
    * **Invalid Targets:**  Providing an invalid HTML element or an invalid ID to `cropTo()` or `restrictTo()`.
    * **Permissions:**  Though not explicitly in this code, consider potential permission issues related to screen capture.
    * **Unsupported Browsers/Platforms:** The `#if !BUILDFLAG(IS_ANDROID)` sections highlight platform-specific limitations.
    * **Race Conditions/Timing Issues:** Asynchronous operations can lead to unexpected behavior if not handled correctly.

10. **Think about Debugging (The "How to Find Problems"):**
    * **Console Logging:** Standard debugging technique for JavaScript.
    * **Browser Developer Tools (Network, Console, Sources):** Essential for inspecting API calls and errors.
    * **Chromium's Internal Debugging Tools:** For deeper issues within Blink, developers might use tools to inspect logs, break points, and trace execution flow within the C++ code itself (though this is less common for web developers). Mentioning potential breakpoints in this file is relevant for Chromium developers.
    * **User Actions:** Trace back the user's interaction that leads to the execution of this code (e.g., clicking a "Share Screen" button).

11. **Structure the Answer:** Organize the information logically, starting with the core functionality, then expanding to related web technologies, examples, errors, and debugging. Use clear headings and bullet points for readability.

12. **Review and Refine:**  Read through the generated explanation. Ensure it's accurate, comprehensive, and addresses all aspects of the original request. Correct any inaccuracies or ambiguities. For instance, initially, I might focus too much on the C++ implementation details. The refinement step involves ensuring the explanation is also helpful for someone who understands web development concepts. Emphasize the JavaScript API interaction.
这个文件 `blink/renderer/modules/mediastream/browser_capture_media_stream_track.cc` 是 Chromium Blink 引擎中负责处理**由浏览器捕获的媒体流轨道 (MediaStreamTrack)** 的 C++ 源代码文件。 它的主要功能是：

**核心功能:**

1. **表示和管理浏览器捕获的媒体流轨道:**  它实现了 `BrowserCaptureMediaStreamTrack` 类，该类是 `MediaStreamTrackImpl` 的子类，专门用于表示从浏览器捕获的音视频轨道，例如屏幕共享、标签页共享或窗口共享。
2. **实现区域捕获 (Region Capture) 和元素捕获 (Element Capture) 功能:**  该文件实现了 `cropTo()` 和 `restrictTo()` 方法，允许 JavaScript 代码动态地裁剪或限制浏览器捕获的视频轨道显示的区域。这是实现例如“选择你要共享的窗口/标签页的特定部分”功能的核心。
3. **与浏览器进程通信:**  该文件与浏览器进程（Browser Process）进行通信，以请求应用裁剪或限制操作，并接收操作结果。
4. **处理异步操作:**  `cropTo()` 和 `restrictTo()` 操作是异步的，该文件使用 Promises 来处理这些操作的结果。
5. **管理 SubCaptureTarget:**  它涉及到 `SubCaptureTarget` 的概念，包括 `CropTarget` 和 `RestrictionTarget`，用于指定裁剪或限制的目标。
6. **统计指标收集:**  文件中包含用于收集 `cropTo()` 和 `restrictTo()` 操作相关性能指标的代码。

**与 JavaScript, HTML, CSS 的关系:**

这个文件是 Blink 渲染引擎的一部分，直接支持 Web API `MediaStreamTrack` 的功能，特别是涉及到浏览器捕获的轨道。

* **JavaScript:**
    * `cropTo(CropTarget)`: 这个方法可以直接在 JavaScript 的 `MediaStreamTrack` 对象上调用，用于裁剪浏览器捕获的视频轨道。`CropTarget` 对象可以通过 JavaScript 创建，它通常关联到一个 HTML 元素。
        ```javascript
        navigator.mediaDevices.getDisplayMedia()
          .then(stream => {
            const videoTrack = stream.getVideoTracks()[0];
            const cropTargetElement = document.getElementById('my-element');
            videoTrack.cropTo(cropTargetElement)
              .then(() => {
                console.log('裁剪成功');
              })
              .catch(error => {
                console.error('裁剪失败', error);
              });
          });
        ```
    * `restrictTo(RestrictionTarget)`: 类似于 `cropTo()`，用于限制浏览器捕获的视频轨道显示的区域。`RestrictionTarget` 对象也通常关联到一个 HTML 元素。
        ```javascript
        navigator.mediaDevices.getDisplayMedia()
          .then(stream => {
            const videoTrack = stream.getVideoTracks()[0];
            const restrictionTargetElement = document.getElementById('another-element');
            videoTrack.restrictTo(restrictionTargetElement)
              .then(() => {
                console.log('限制成功');
              })
              .catch(error => {
                console.error('限制失败', error);
              });
          });
        ```
* **HTML:**
    * `CropTarget` 和 `RestrictionTarget` 通常指向 HTML 元素。这意味着 JavaScript 可以选择页面上的特定元素作为裁剪或限制的目标。例如，用户可能只想共享一个特定的 `<div>` 元素的内容。
        ```html
        <div>
          <h1>主内容</h1>
          <div id="my-element">
            <p>这是要共享的区域</p>
          </div>
        </div>
        ```
* **CSS:**
    * CSS 影响 HTML 元素的布局和大小，这间接地影响了 `cropTo()` 和 `restrictTo()` 的效果。当指定一个 HTML 元素作为目标时，该元素当前的尺寸和位置（由 CSS 决定）将被用于定义裁剪或限制的区域。

**逻辑推理与假设输入输出:**

**假设输入:**

1. **JavaScript 调用 `videoTrack.cropTo(cropTargetElement)`:** 其中 `videoTrack` 是一个浏览器捕获的视频轨道的 `MediaStreamTrack` 对象，`cropTargetElement` 是页面上一个具有特定 ID 的 `<div>` 元素。
2. **`cropTargetElement` 的 ID 为 "target-area"，其在页面上的位置和尺寸由 CSS 定义。**

**逻辑推理:**

1. 当 `cropTo()` 在 JavaScript 中被调用时，Blink 引擎会将这个调用传递到 `BrowserCaptureMediaStreamTrack::cropTo()` 方法。
2. `cropTo()` 内部会调用 `ApplySubCaptureTarget()`，并将目标类型设置为 `kCropTarget`。
3. `ApplySubCaptureTarget()` 会从 `cropTargetElement` 中提取唯一标识符 (token)。
4. 它会向浏览器进程发送一个请求，指示需要将该视频轨道裁剪到与该标识符关联的区域。
5. 浏览器进程会处理这个请求，并调整底层的媒体捕获管道。
6. 当裁剪操作成功后，浏览器进程会通知 Blink 进程。
7. `OnResultFromBrowserProcess()` 回调函数会被调用，解析结果并 resolve 相应的 JavaScript Promise。
8. 如果裁剪成功，后续的视频帧将只包含 `cropTargetElement` 区域的内容。

**假设输出:**

* **成功情况:** JavaScript 的 `cropTo()` Promise 会 resolve，控制台会输出 "裁剪成功"。后续通过该 `videoTrack` 传输的视频流将只包含 "target-area" `<div>` 元素的内容。
* **失败情况 (例如，无效的 `cropTargetElement`):** JavaScript 的 `cropTo()` Promise 会 reject，控制台会输出 "裁剪失败" 以及相应的错误信息。

**用户或编程常见的使用错误:**

1. **尝试在非浏览器捕获的轨道上调用 `cropTo()` 或 `restrictTo()`:** 这些方法只适用于通过 `getDisplayMedia()` 等 API 获取的浏览器捕获的媒体流轨道。如果在例如摄像头捕获的轨道上调用，会导致错误。
    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(stream => {
        const videoTrack = stream.getVideoTracks()[0];
        const element = document.getElementById('some-element');
        // 错误：不能在摄像头捕获的轨道上调用 cropTo
        videoTrack.cropTo(element).catch(e => console.error(e));
      });
    ```
2. **传递无效的 `CropTarget` 或 `RestrictionTarget`:** 例如，传递 `null` 或者指向一个不存在的 DOM 元素的引用。这会导致 `ApplySubCaptureTarget()` 中校验失败。
    ```javascript
    navigator.mediaDevices.getDisplayMedia()
      .then(stream => {
        const videoTrack = stream.getVideoTracks()[0];
        // 错误：传递 null
        videoTrack.cropTo(null).catch(e => console.error(e));

        const nonExistentElement = document.getElementById('does-not-exist');
        // 错误：传递指向不存在元素的引用
        videoTrack.cropTo(nonExistentElement).catch(e => console.error(e));
      });
    ```
3. **在 `cropTo()` 或 `restrictTo()` 操作进行中再次调用:**  虽然代码中可能做了处理，但过快地连续调用这些方法可能会导致不可预测的结果或性能问题。最好等待前一个 Promise 完成后再进行下一次调用。
4. **假设裁剪会立即生效:**  `cropTo()` 和 `restrictTo()` 是异步操作，需要等待浏览器进程处理。开发者不应该假设在调用后立即就能看到裁剪效果。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户发起屏幕共享或标签页/窗口共享:** 用户在浏览器中点击了屏幕共享按钮或通过 JavaScript 调用了 `navigator.mediaDevices.getDisplayMedia()` API。
2. **浏览器显示共享选择界面:** 浏览器会弹出窗口让用户选择要共享的内容（整个屏幕、特定窗口、特定标签页）。
3. **用户选择并确认共享:** 用户选择了共享的内容并点击了“共享”按钮。
4. **Blink 引擎创建 `BrowserCaptureMediaStreamTrack` 对象:**  一旦用户确认共享，Blink 引擎会创建一个 `BrowserCaptureMediaStreamTrack` 对象来表示这个捕获到的视频轨道。
5. **JavaScript 代码调用 `videoTrack.cropTo()` 或 `videoTrack.restrictTo()`:**  网页上的 JavaScript 代码获取到这个 `MediaStreamTrack` 对象后，可能会调用 `cropTo()` 或 `restrictTo()` 方法，以实现更精细的共享控制。
6. **`BrowserCaptureMediaStreamTrack::cropTo()` 或 `BrowserCaptureMediaStreamTrack::restrictTo()` 被调用:**  JavaScript 的调用最终会触发这个 C++ 文件中的相应方法。
7. **与浏览器进程通信:**  `ApplySubCaptureTarget()` 方法会与浏览器进程进行通信，请求应用裁剪或限制。
8. **浏览器进程处理请求并通知 Blink:** 浏览器进程会处理请求，并可能涉及操作系统级别的窗口管理和捕获 API 的调用。处理完成后，会通知 Blink 进程结果。
9. **`OnResultFromBrowserProcess()` 处理结果:**  Blink 进程接收到通知后，`OnResultFromBrowserProcess()` 方法会被调用，用于处理操作结果并更新 JavaScript Promise 的状态。

**作为调试线索:**

* 如果用户报告屏幕共享区域不正确，可以检查 JavaScript 代码中是否正确调用了 `cropTo()` 或 `restrictTo()`，以及传递的目标元素是否正确。
* 可以通过 Chromium 的内部日志 (chrome://webrtc-internals) 查看与媒体流和屏幕捕获相关的事件和错误信息，来定位问题是否发生在 Blink 侧或浏览器进程侧。
* 可以设置断点在 `BrowserCaptureMediaStreamTrack::cropTo()`, `ApplySubCaptureTarget()`, 和 `OnResultFromBrowserProcess()` 等关键方法中，来跟踪代码执行流程和变量状态。
* 检查 `pending_promises_` 成员，可以了解当前是否有正在进行的裁剪或限制操作，以及对应的 Promise 状态。
* 如果涉及到特定的 HTML 元素，需要检查该元素是否存在，其 ID 是否正确，以及其布局和尺寸是否符合预期。

总而言之，`browser_capture_media_stream_track.cc` 文件是实现浏览器捕获媒体流轨道裁剪和限制功能的核心，它连接了 JavaScript API 和底层的浏览器捕获机制。 理解其功能有助于调试与屏幕共享和标签页/窗口共享相关的 WebRTC 应用问题。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/browser_capture_media_stream_track.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/browser_capture_media_stream_track.h"

#include <optional>

#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/token.h"
#include "base/types/expected.h"
#include "base/uuid.h"
#include "build/build_config.h"
#include "media/capture/mojom/video_capture_types.mojom-blink.h"
#include "media/capture/video_capture_types.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/mediastream/crop_target.h"
#include "third_party/blink/renderer/modules/mediastream/restriction_target.h"
#include "third_party/blink/renderer/modules/mediastream/sub_capture_target.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/region_capture_crop_id.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

#if !BUILDFLAG(IS_ANDROID)

using ApplySubCaptureTargetResult =
    BrowserCaptureMediaStreamTrack::ApplySubCaptureTargetResult;

// If crop_id is the empty string, returns an empty base::Token.
// If crop_id is a valid UUID, returns a base::Token representing the ID.
// Otherwise, returns nullopt.
std::optional<base::Token> IdStringToToken(const String& crop_id) {
  if (crop_id.empty()) {
    return base::Token();
  }
  if (!crop_id.ContainsOnlyASCIIOrEmpty()) {
    return std::nullopt;
  }
  const base::Uuid guid = base::Uuid::ParseCaseInsensitive(crop_id.Ascii());
  return guid.is_valid() ? std::make_optional<base::Token>(GUIDToToken(guid))
                         : std::nullopt;
}

void RaiseApplySubCaptureTargetException(
    ScriptPromiseResolverWithTracker<ApplySubCaptureTargetResult, IDLUndefined>*
        resolver,
    DOMExceptionCode exception_code,
    const WTF::String& exception_text,
    ApplySubCaptureTargetResult result) {
  resolver->Reject<DOMException>(
      MakeGarbageCollected<DOMException>(exception_code, exception_text),
      result);
}

void ResolveApplySubCaptureTargetPromiseHelper(
    ScriptPromiseResolverWithTracker<ApplySubCaptureTargetResult, IDLUndefined>*
        resolver,
    media::mojom::ApplySubCaptureTargetResult result) {
  DCHECK(IsMainThread());

  if (!resolver) {
    return;
  }

  switch (result) {
    case media::mojom::ApplySubCaptureTargetResult::kSuccess:
      resolver->Resolve();
      return;
    case media::mojom::ApplySubCaptureTargetResult::kErrorGeneric:
      RaiseApplySubCaptureTargetException(
          resolver, DOMExceptionCode::kAbortError, "Unknown error.",
          ApplySubCaptureTargetResult::kRejectedWithErrorGeneric);
      return;
    case media::mojom::ApplySubCaptureTargetResult::kUnsupportedCaptureDevice:
      // Note that this is an unsupported device; not an unsupported Element.
      // This should essentially not happen. If it happens, it indicates
      // something in the capture pipeline has been changed.
      RaiseApplySubCaptureTargetException(
          resolver, DOMExceptionCode::kAbortError, "Unsupported device.",
          ApplySubCaptureTargetResult::kRejectedWithUnsupportedCaptureDevice);
      return;
    case media::mojom::ApplySubCaptureTargetResult::kNotImplemented:
      // Unimplemented codepath reached, OTHER than lacking support for
      // a specific Element subtype.
      RaiseApplySubCaptureTargetException(
          resolver, DOMExceptionCode::kOperationError, "Not implemented.",
          ApplySubCaptureTargetResult::kRejectedWithNotImplemented);
      return;
    case media::mojom::ApplySubCaptureTargetResult::kNonIncreasingVersion:
      // This should rarely happen, as the browser process would issue
      // a BadMessage in this case. But if that message has to hop from
      // the IO thread to the UI thread, it could theoretically happen
      // that Blink receives this callback before being killed, so we
      // can't quite DCHECK this.
      RaiseApplySubCaptureTargetException(
          resolver, DOMExceptionCode::kAbortError, "Non-increasing version.",
          ApplySubCaptureTargetResult::kNonIncreasingVersion);
      return;
    case media::mojom::ApplySubCaptureTargetResult::kInvalidTarget:
      RaiseApplySubCaptureTargetException(
          resolver, DOMExceptionCode::kNotAllowedError, "Invalid target.",
          ApplySubCaptureTargetResult::kInvalidTarget);
      return;
  }

  NOTREACHED();
}

#endif  // !BUILDFLAG(IS_ANDROID)

}  // namespace

BrowserCaptureMediaStreamTrack::BrowserCaptureMediaStreamTrack(
    ExecutionContext* execution_context,
    MediaStreamComponent* component,
    base::OnceClosure callback)
    : BrowserCaptureMediaStreamTrack(execution_context,
                                     component,
                                     component->GetReadyState(),
                                     std::move(callback)) {}

BrowserCaptureMediaStreamTrack::BrowserCaptureMediaStreamTrack(
    ExecutionContext* execution_context,
    MediaStreamComponent* component,
    MediaStreamSource::ReadyState ready_state,
    base::OnceClosure callback)
    : MediaStreamTrackImpl(execution_context,
                           component,
                           ready_state,
                           std::move(callback)) {}

#if !BUILDFLAG(IS_ANDROID)
void BrowserCaptureMediaStreamTrack::Trace(Visitor* visitor) const {
  visitor->Trace(pending_promises_);
  MediaStreamTrackImpl::Trace(visitor);
}
#endif  // !BUILDFLAG(IS_ANDROID)

ScriptPromise<IDLUndefined> BrowserCaptureMediaStreamTrack::cropTo(
    ScriptState* script_state,
    CropTarget* target,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());
  return ApplySubCaptureTarget(script_state,
                               SubCaptureTarget::Type::kCropTarget, target,
                               exception_state);
}

ScriptPromise<IDLUndefined> BrowserCaptureMediaStreamTrack::restrictTo(
    ScriptState* script_state,
    RestrictionTarget* target,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());
  return ApplySubCaptureTarget(script_state,
                               SubCaptureTarget::Type::kRestrictionTarget,
                               target, exception_state);
}

BrowserCaptureMediaStreamTrack* BrowserCaptureMediaStreamTrack::clone(
    ExecutionContext* execution_context) {
  // Instantiate the clone.
  BrowserCaptureMediaStreamTrack* cloned_track =
      MakeGarbageCollected<BrowserCaptureMediaStreamTrack>(
          execution_context, Component()->Clone(), GetReadyState(),
          base::DoNothing());

  // Copy state.
  MediaStreamTrackImpl::CloneInternal(cloned_track);

  return cloned_track;
}

ScriptPromise<IDLUndefined>
BrowserCaptureMediaStreamTrack::ApplySubCaptureTarget(
    ScriptState* script_state,
    SubCaptureTarget::Type type,
    SubCaptureTarget* target,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());
  CHECK(type == SubCaptureTarget::Type::kCropTarget ||
        type == SubCaptureTarget::Type::kRestrictionTarget);

  const std::string metric_name_prefix =
      (type == SubCaptureTarget::Type::kCropTarget)
          ? "Media.RegionCapture.CropTo"
          : "Media.ElementCapture.RestrictTo";

  // If the promise is not resolved within the |timeout_interval|, an
  // ApplySubCaptureTargetResult::kTimedOut response will be recorded in the
  // UMA.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolverWithTracker<
      ApplySubCaptureTargetResult, IDLUndefined>>(
      script_state, metric_name_prefix,
      /*timeout_interval=*/base::Seconds(10));
  if (type == SubCaptureTarget::Type::kCropTarget) {
    resolver->SetResultSuffix("Result2");
  }
  auto promise = resolver->Promise();

#if BUILDFLAG(IS_ANDROID)
  resolver->Reject<DOMException>(
      MakeGarbageCollected<DOMException>(DOMExceptionCode::kUnknownError,
                                         "Not supported on Android."),
      ApplySubCaptureTargetResult::kUnsupportedPlatform);
  return promise;
#else

  const std::optional<base::Token> token =
      IdStringToToken(target ? target->GetId() : String());
  if (!token.has_value()) {
    resolver->Reject<DOMException>(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kUnknownError,
                                           "Invalid token."),
        ApplySubCaptureTargetResult::kInvalidTarget);
    return promise;
  }

  MediaStreamComponent* const component = Component();
  DCHECK(component);

  MediaStreamSource* const source = component->Source();
  DCHECK(component->Source());
  // We don't currently instantiate BrowserCaptureMediaStreamTrack for audio
  // tracks. If we do in the future, we'll have to raise an exception if
  // cropTo() or restrictTo() are called on a non-video track.
  DCHECK_EQ(source->GetType(), MediaStreamSource::kTypeVideo);

  MediaStreamVideoSource* const native_source =
      MediaStreamVideoSource::GetVideoSource(source);
  MediaStreamTrackPlatform* const native_track =
      MediaStreamTrackPlatform::GetTrack(WebMediaStreamTrack(component));
  if (!native_source || !native_track) {
    resolver->Reject<DOMException>(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kUnknownError,
                                           "Native/platform track missing."),
        ApplySubCaptureTargetResult::kRejectedWithErrorGeneric);
    return promise;
  }

  // TODO(crbug.com/1332628): Instead of using GetNextSubCaptureTargetVersion(),
  // move the ownership of the Promises from this->pending_promises_ into
  // native_source.
  const std::optional<uint32_t> optional_sub_capture_target_version =
      native_source->GetNextSubCaptureTargetVersion();
  if (!optional_sub_capture_target_version.has_value()) {
    resolver->Reject<DOMException>(
        MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kOperationError,
            "Can't change target while clones exist."),
        ApplySubCaptureTargetResult::kInvalidTarget);
    return promise;
  }
  const uint32_t sub_capture_target_version =
      optional_sub_capture_target_version.value();

  pending_promises_.Set(sub_capture_target_version,
                        MakeGarbageCollected<PromiseInfo>(resolver));

  // Register for a one-off notification when the first frame cropped
  // to the new crop-target is observed.
  native_track->AddSubCaptureTargetVersionCallback(
      sub_capture_target_version,
      WTF::BindOnce(
          &BrowserCaptureMediaStreamTrack::OnSubCaptureTargetVersionObserved,
          WrapWeakPersistent(this), sub_capture_target_version));

  native_source->ApplySubCaptureTarget(
      type, token.value(), sub_capture_target_version,
      WTF::BindOnce(&BrowserCaptureMediaStreamTrack::OnResultFromBrowserProcess,
                    WrapWeakPersistent(this), sub_capture_target_version));

  return promise;
#endif
}

#if !BUILDFLAG(IS_ANDROID)
void BrowserCaptureMediaStreamTrack::OnResultFromBrowserProcess(
    uint32_t sub_capture_target_version,
    media::mojom::ApplySubCaptureTargetResult result) {
  DCHECK(IsMainThread());
  DCHECK_GT(sub_capture_target_version, 0u);

  const auto iter = pending_promises_.find(sub_capture_target_version);
  if (iter == pending_promises_.end()) {
    return;
  }
  PromiseInfo* const info = iter->value;

  DCHECK(!info->result.has_value()) << "Invoked twice.";
  info->result = result;

  MaybeFinalizeCropPromise(iter);
}

void BrowserCaptureMediaStreamTrack::OnSubCaptureTargetVersionObserved(
    uint32_t sub_capture_target_version) {
  DCHECK(IsMainThread());
  DCHECK_GT(sub_capture_target_version, 0u);

  const auto iter = pending_promises_.find(sub_capture_target_version);
  if (iter == pending_promises_.end()) {
    return;
  }
  PromiseInfo* const info = iter->value;

  DCHECK(!info->sub_capture_target_version_observed) << "Invoked twice.";
  info->sub_capture_target_version_observed = true;

  MaybeFinalizeCropPromise(iter);
}

void BrowserCaptureMediaStreamTrack::MaybeFinalizeCropPromise(
    BrowserCaptureMediaStreamTrack::PromiseMapIterator iter) {
  DCHECK(IsMainThread());
  CHECK_NE(iter, pending_promises_.end(), base::NotFatalUntil::M130);

  PromiseInfo* const info = iter->value;

  if (!info->result.has_value()) {
    return;
  }

  const media::mojom::ApplySubCaptureTargetResult result = info->result.value();

  // Failure can be reported immediately, but success is only reported once
  // the new sub-capture-target-version is observed.
  if (result == media::mojom::ApplySubCaptureTargetResult::kSuccess &&
      !info->sub_capture_target_version_observed) {
    return;
  }

  // When `result == kSuccess`, the callback will be removed by the track
  // itself as it invokes it. For failure, we remove the callback immediately,
  // since there's no need to wait.
  if (result != media::mojom::ApplySubCaptureTargetResult::kSuccess) {
    MediaStreamTrackPlatform* const native_track =
        MediaStreamTrackPlatform::GetTrack(WebMediaStreamTrack(Component()));
    if (native_track) {
      native_track->RemoveSubCaptureTargetVersionCallback(iter->key);
    }
  }

  ScriptPromiseResolverWithTracker<ApplySubCaptureTargetResult,
                                   IDLUndefined>* const resolver =
      info->promise_resolver;
  pending_promises_.erase(iter);
  ResolveApplySubCaptureTargetPromiseHelper(resolver, result);
}
#endif  // !BUILDFLAG(IS_ANDROID)

}  // namespace blink

"""

```