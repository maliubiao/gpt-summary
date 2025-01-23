Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The primary goal is to analyze the `PictureInPictureControllerImpl.cc` file and explain its functionality, its relation to web technologies, its logic, potential errors, and how a user might trigger its execution.

2. **Initial Code Scan (Keywords and Structure):**  Quickly skim the code for important keywords and structural elements. This helps to get a high-level understanding:
    * `#include`:  Indicates dependencies on other parts of the Chromium project. Pay attention to things like `media/mojo/mojom`, `blink/public/`, `renderer/bindings/`, `renderer/core/`, `renderer/modules/`. This gives clues about the module's purpose.
    * `namespace blink`:  Confirms it's part of the Blink rendering engine.
    * Class definition: `class PictureInPictureControllerImpl`. The "Impl" suffix often suggests this is a concrete implementation of an interface.
    * Member variables: Look for key member variables like `picture_in_picture_element_`, `picture_in_picture_window_`, `picture_in_picture_service_`, etc. These suggest what the class manages.
    * Methods: Scan for public methods like `EnterPictureInPicture`, `ExitPictureInPicture`, `PictureInPictureEnabled`, etc. These are the entry points for external interaction. Also look for private methods (like `OnEnteredPictureInPicture`, `OnExitedPictureInPicture`) which handle internal events.
    * `// Copyright`, `// static`: Standard code conventions in Chromium.
    * `#if !BUILDFLAG(TARGET_OS_IS_ANDROID)`: Conditional compilation, indicating platform-specific behavior.

3. **Focus on Key Functionality (Core Logic):**  Identify the main tasks the class is responsible for. The name itself, "PictureInPictureControllerImpl," is a huge hint. The methods confirm this:
    * Entering Picture-in-Picture (`EnterPictureInPicture`).
    * Exiting Picture-in-Picture (`ExitPictureInPicture`).
    * Checking if Picture-in-Picture is enabled (`PictureInPictureEnabled`, `IsDocumentAllowed`, `IsElementAllowed`).
    * Managing the Picture-in-Picture window and element.

4. **Trace the User Flow (Debugging Clues):** Imagine a user interacting with a website that uses Picture-in-Picture. How would they trigger this code?
    * A user clicks a "Picture-in-Picture" button on a video.
    * JavaScript code calls a method to enter Picture-in-Picture. This likely maps to the `EnterPictureInPicture` method in the C++ code.
    * The browser needs to check if Picture-in-Picture is allowed (permissions, browser settings). This involves the `IsDocumentAllowed` and `IsElementAllowed` methods.
    * The browser creates a separate window for the video.
    * When the user exits Picture-in-Picture, the `ExitPictureInPicture` method is called.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how this C++ code interacts with the front-end.
    * **JavaScript:**  The JavaScript `requestPictureInPicture()` method on a video element is the most obvious entry point. Look for mentions of `ScriptPromiseResolver` which are used for asynchronous JavaScript calls. Also, events like `enterpictureinpicture` and `leavepictureinpicture` are dispatched to JavaScript.
    * **HTML:** The `<video>` element is central to video Picture-in-Picture. The `disablepictureinpicture` attribute directly influences the behavior.
    * **CSS:** While this specific file doesn't directly manipulate CSS,  the size and positioning of the video element on the page (before entering PiP) are relevant, as are the potential styling of the PiP window itself (though this code focuses on the core logic).

6. **Identify Logic and Assumptions:** Examine the code for conditional statements and data flow.
    * **Permissions and Restrictions:** The code checks for various conditions that prevent Picture-in-Picture (browser settings, permissions policy, element attributes, video state).
    * **Mojo Communication:**  The code uses Mojo for inter-process communication (IPC) with the browser process (e.g., `picture_in_picture_service_`).
    * **Asynchronous Operations:** The use of `ScriptPromiseResolver` and callbacks (`WTF::BindOnce`) indicates asynchronous operations.
    * **Platform Differences:** The `#if !BUILDFLAG(TARGET_OS_IS_ANDROID)` block indicates different logic for Android.

7. **Look for Potential Errors:**  Consider common mistakes a developer might make when using the Picture-in-Picture API, and how this code handles them.
    * Calling `requestPictureInPicture()` on a non-video element or a video that isn't loaded.
    * Attempting to enter Picture-in-Picture when it's disabled by browser settings or permissions.
    * Errors during the Mojo communication.

8. **Address Specific Requirements:** Review the prompt and ensure all questions are addressed:
    * **Functionality:** Clearly list the main purposes of the class.
    * **Relationship to Web Technologies:** Provide concrete examples of how JavaScript, HTML, and (to a lesser extent) CSS interact with the code.
    * **Logic and Assumptions:** Describe the decision-making within the code, providing hypothetical inputs and outputs.
    * **User/Programming Errors:** Give practical examples of common mistakes.
    * **User Steps to Reach the Code:** Outline the sequence of user actions that would lead to the execution of this code.

9. **Structure the Output:** Organize the information logically with clear headings and bullet points. Start with a high-level overview and then delve into specifics. Use examples where possible. Ensure the language is clear and concise.

10. **Review and Refine:** After drafting the analysis, reread it to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that need further explanation. For instance, the Document Picture-in-Picture part is a distinct feature and should be treated separately within the analysis.

By following these steps, you can systematically analyze complex C++ code like this and extract meaningful information about its purpose and behavior within the larger context of a web browser.
这个文件 `blink/renderer/modules/document_picture_in_picture/picture_in_picture_controller_impl.cc` 是 Chromium Blink 渲染引擎中，负责实现 **画中画 (Picture-in-Picture, PiP)** 功能的核心控制器。它主要处理与视频元素相关的画中画操作，并且在非 Android 平台上，也负责管理文档画中画 (Document Picture-in-Picture) 的功能。

以下是它的主要功能：

**核心功能：视频画中画 (Video Picture-in-Picture)**

1. **控制画中画的进入和退出:**
   - `EnterPictureInPicture(HTMLVideoElement* video_element, ScriptPromiseResolver<PictureInPictureWindow>* resolver)`:  处理将指定的 HTMLVideoElement 进入画中画模式的请求。
   - `ExitPictureInPicture(HTMLVideoElement* element, ScriptPromiseResolver<IDLUndefined>* resolver)`: 处理退出指定 HTMLVideoElement 的画中画模式的请求。
   - `OnEnteredPictureInPicture(...)`: 当画中画成功进入后被调用，创建 `PictureInPictureWindow` 对象，并通知视频元素。
   - `OnExitedPictureInPicture(...)`: 当画中画成功退出后被调用，清理 `PictureInPictureWindow` 对象，并通知视频元素。

2. **检查画中画是否允许:**
   - `PictureInPictureEnabled() const`: 返回当前文档是否允许使用画中画功能。
   - `IsDocumentAllowed(bool report_failure) const`: 检查当前文档是否满足使用画中画的条件（例如，权限策略，浏览器设置）。
   - `IsElementAllowed(const HTMLVideoElement& video_element, bool report_failure) const`: 检查特定的视频元素是否可以进入画中画模式（例如，视频是否加载，是否设置了禁用属性）。

3. **管理画中画窗口:**
   - 维护 `picture_in_picture_window_` 成员变量，指向当前正在显示的画中画窗口对象。
   - `OnWindowSizeChanged(const gfx::Size& size)`: 当画中画窗口大小改变时被调用，并通知 `PictureInPictureWindow` 对象。

4. **与浏览器进程通信:**
   - 使用 Mojo 接口 `mojom::blink::PictureInPictureService` 与浏览器进程通信，请求创建和管理画中画窗口。
   - 使用 `mojom::blink::PictureInPictureSessionObserver` 接收来自浏览器进程的关于画中画会话的通知。
   - 使用 `media::mojom::blink::MediaPlayer` 接口与媒体播放器进行交互。

5. **处理画中画状态变化:**
   - `OnPictureInPictureStateChange()`: 当视频元素的某些状态发生变化（例如，视频源改变）时被调用，并通知浏览器进程。

**非 Android 平台特有功能：文档画中画 (Document Picture-in-Picture)**

6. **控制文档画中画窗口的创建和管理:**
   - `CreateDocumentPictureInPictureWindow(...)`: 处理创建文档画中画窗口的请求。
   - 维护 `document_picture_in_picture_window_` 成员变量，指向当前正在显示的文档画中画窗口对象。
   - 维护 `document_picture_in_picture_owner_` 成员变量，指向拥有该文档画中画窗口的原始窗口。
   - `SetDocumentPictureInPictureOwner(...)`: 设置文档画中画窗口的拥有者。
   - `OnDocumentPictureInPictureContextDestroyed()`: 当文档画中画窗口或其拥有者的上下文被销毁时被调用。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Blink 渲染引擎的内部实现，它与前端技术通过以下方式关联：

* **JavaScript API:**  这个文件实现了浏览器提供的 JavaScript 画中画 API 的底层逻辑，例如：
    * `videoElement.requestPictureInPicture()`: 当 JavaScript 调用这个方法时，最终会触发 `PictureInPictureControllerImpl::EnterPictureInPicture` 方法。
    * `document.exitPictureInPicture()`: 当 JavaScript 调用这个方法时，会触发 `PictureInPictureControllerImpl::ExitPictureInPicture` 方法。
    * `navigator.pictureInPicture.requestWindow()` (Document PiP): 当 JavaScript 调用这个方法时，会触发 `PictureInPictureControllerImpl::CreateDocumentPictureInPictureWindow` 方法。
* **HTML `<video>` 元素:** 这个文件大量涉及到 `HTMLVideoElement` 对象，例如：
    * 检查视频元素是否可以进入画中画模式。
    * 获取视频元素的尺寸和状态。
    * 在进入和退出画中画模式时，向视频元素派发 `enterpictureinpicture` 和 `leavepictureinpicture` 事件。
    * 检查视频元素是否设置了 `disablepictureinpicture` 属性。
* **CSS (间接关系):**  CSS 影响视频元素在页面上的布局和尺寸，而这些信息会被传递给画中画窗口。虽然这个 C++ 文件不直接操作 CSS，但 CSS 的渲染结果会影响画中画功能的行为。例如，视频的初始尺寸会作为画中画窗口的初始尺寸的参考。

**逻辑推理 (假设输入与输出):**

**场景 1: 用户点击视频上的 "进入画中画" 按钮**

* **假设输入:**
    * 用户在包含一个 `<video id="myVideo">` 元素的网页上点击了 "进入画中画" 按钮。
    * 相应的 JavaScript 代码调用了 `document.getElementById('myVideo').requestPictureInPicture()`.
* **逻辑推理:**
    1. JavaScript 调用会触发 Blink 内部的事件处理机制。
    2. Blink 会找到与该视频元素关联的 `PictureInPictureControllerImpl` 实例。
    3. 调用 `EnterPictureInPicture(video_element, resolver)`，其中 `video_element` 指向 `<video id="myVideo">` 元素，`resolver` 是一个用于返回 Promise 结果的对象。
    4. `EnterPictureInPicture` 会检查文档和元素是否允许进入画中画模式 (`IsDocumentAllowed`, `IsElementAllowed`)。
    5. 如果允许，则通过 Mojo 向浏览器进程发送请求创建画中画窗口。
    6. 浏览器进程创建窗口后，会通过回调通知 Blink 进程 (`OnEnteredPictureInPicture`)。
    7. `OnEnteredPictureInPicture` 会创建 `PictureInPictureWindow` 对象，并 resolve JavaScript 的 Promise。
* **预期输出:**
    * 一个独立的画中画窗口显示该视频的内容。
    * JavaScript 的 Promise 被 resolve，返回 `PictureInPictureWindow` 对象。

**场景 2: 用户在画中画窗口上点击 "关闭" 按钮**

* **假设输入:**
    * 用户正在观看一个画中画窗口。
    * 用户点击了窗口上的 "关闭" 按钮。
* **逻辑推理:**
    1. 浏览器进程检测到用户操作，并通知 Blink 进程。
    2. Blink 进程的 `PictureInPictureControllerImpl` 接收到通知。
    3. 调用 `OnExitedPictureInPicture(nullptr)`.
    4. `OnExitedPictureInPicture` 会清理 `picture_in_picture_window_`，并通知相关的 `HTMLVideoElement`。
    5. `HTMLVideoElement` 会派发 `leavepictureinpicture` 事件。
* **预期输出:**
    * 画中画窗口被关闭。
    * 原始网页上的 `<video>` 元素恢复正常播放。
    * JavaScript 监听到的 `leavepictureinpicture` 事件被触发。

**用户或编程常见的使用错误举例说明:**

1. **在不允许使用画中画的上下文中调用 `requestPictureInPicture()`:**
   - **错误场景:** 网页的权限策略 (Permissions Policy) 禁止使用画中画功能。
   - **代码示例 (JavaScript):**  尝试在一个被 `allow="picture-in-picture 'none'"` 的 `<iframe>` 中的视频元素上调用 `requestPictureInPicture()`。
   - **结果:** `requestPictureInPicture()` 方法会返回一个被 reject 的 Promise，并抛出一个 `NotAllowedError` 类型的 `DOMException`。

2. **在未加载或无法播放的视频元素上调用 `requestPictureInPicture()`:**
   - **错误场景:**  在一个 `readyState` 为 `HAVE_NOTHING` 的视频元素上调用 `requestPictureInPicture()`。
   - **代码示例 (JavaScript):**
     ```javascript
     const video = document.createElement('video');
     video.requestPictureInPicture(); // 在设置 src 之前调用
     ```
   - **结果:** `EnterPictureInPicture` 方法会检查 `video_element->getReadyState()`，发现其为 `kHaveNothing`，会返回相应的状态，最终导致 Promise 被 reject，并可能抛出一个 `InvalidStateError` 类型的 `DOMException`。

3. **忘记处理 `enterpictureinpicture` 和 `leavepictureinpicture` 事件:**
   - **错误场景:**  开发者没有监听视频元素的 `enterpictureinpicture` 和 `leavepictureinpicture` 事件，导致在进入或退出画中画模式时，页面上的其他元素或状态没有相应更新。
   - **结果:**  虽然画中画功能本身可以正常工作，但用户体验可能不佳，例如，进入画中画后，页面上的播放控制按钮仍然显示 "播放" 状态。

4. **在文档画中画中尝试操作属于原始窗口的对象 (非 Android 平台):**
   - **错误场景:** 在文档画中画窗口的 JavaScript 中，尝试直接访问属于创建该窗口的原始窗口的 DOM 元素或变量，而没有正确地传递或引用。
   - **代码示例 (文档画中画窗口的 JavaScript):**
     ```javascript
     // 假设 openerWindow 是对原始窗口的引用
     openerWindow.document.getElementById('someElement').textContent = 'Hello';
     ```
   - **结果:**  可能会因为跨域或其他安全限制而导致访问失败或报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户加载包含 `<video>` 元素的网页:**  浏览器开始解析 HTML，创建 DOM 树，其中包括 `HTMLVideoElement` 对象。
2. **JavaScript 代码执行:** 网页上的 JavaScript 代码可能注册了事件监听器，或者在特定条件下调用了画中画相关的 API。
3. **用户触发画中画请求:**
   - **点击视频元素上的浏览器默认画中画按钮:**  浏览器会捕获这个事件，并调用 Blink 内部相应的处理函数。
   - **点击网页自定义的 "进入画中画" 按钮，并执行 JavaScript 代码 `videoElement.requestPictureInPicture()`:** JavaScript 调用会通过 Blink 的绑定机制，最终调用到 C++ 代码的 `PictureInPictureControllerImpl::EnterPictureInPicture` 方法。
4. **Blink 内部处理:**
   - `PictureInPictureControllerImpl::From(document)` 用于获取与当前文档关联的 `PictureInPictureControllerImpl` 实例。
   - `EnterPictureInPicture` 方法会进行各种检查，并与浏览器进程通信。
5. **浏览器进程创建画中画窗口 (如果允许):** 浏览器进程会创建一个新的窗口，并将视频内容渲染到该窗口中。
6. **Blink 接收到画中画窗口创建成功的通知:** `OnEnteredPictureInPicture` 被调用。
7. **用户操作画中画窗口 (例如，关闭):** 浏览器进程会将这些操作通知给 Blink 进程。
8. **Blink 处理画中画窗口事件:** 例如，`OnExitedPictureInPicture` 被调用。

**作为调试线索:**

* **断点:** 在 `EnterPictureInPicture`、`ExitPictureInPicture`、`IsDocumentAllowed`、`IsElementAllowed` 等关键方法设置断点，可以追踪画中画请求的流程和状态。
* **日志输出:**  在关键路径上添加日志输出，可以记录变量的值和执行路径，帮助理解代码的行为。
* **Mojo Inspector:**  可以使用 Mojo Inspector 工具查看 Blink 进程和浏览器进程之间的 Mojo 消息传递，了解画中画请求的发送和响应。
* **Chrome DevTools:**  可以使用 Chrome DevTools 的 "Media" 面板查看媒体相关的状态信息，例如视频元素的 readyState。
* **Permissions Policy Inspector:**  可以使用 Chrome DevTools 的 "Application" 面板查看页面的权限策略，确认画中画功能是否被允许。

总而言之，`picture_in_picture_controller_impl.cc` 文件是 Blink 渲染引擎中实现画中画功能的核心组件，它连接了 JavaScript API 和底层的浏览器实现，负责管理画中画的生命周期，并处理各种相关的状态和事件。理解这个文件的功能对于调试和理解 Chromium 的画中画实现至关重要。

### 提示词
```
这是目录为blink/renderer/modules/document_picture_in_picture/picture_in_picture_controller_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/document_picture_in_picture/picture_in_picture_controller_impl.h"

#include <limits>
#include <utility>

#include "base/functional/callback_helpers.h"
#include "base/task/single_thread_task_runner.h"
#include "media/mojo/mojom/media_player.mojom-blink.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/common/media/display_type.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/layout/layout_video.h"
#include "third_party/blink/renderer/modules/picture_in_picture/picture_in_picture_event.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
#include "third_party/blink/public/web/web_picture_in_picture_window_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_document_picture_in_picture_options.h"
#include "third_party/blink/renderer/modules/document_picture_in_picture/document_picture_in_picture.h"
#include "third_party/blink/renderer/modules/document_picture_in_picture/document_picture_in_picture_event.h"
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

namespace blink {

namespace {

bool ShouldShowPlayPauseButton(const HTMLVideoElement& element) {
  return element.GetLoadType() != WebMediaPlayer::kLoadTypeMediaStream &&
         element.duration() != std::numeric_limits<double>::infinity();
}

}  // namespace

// static
PictureInPictureControllerImpl& PictureInPictureControllerImpl::From(
    Document& document) {
  return static_cast<PictureInPictureControllerImpl&>(
      PictureInPictureController::From(document));
}

bool PictureInPictureControllerImpl::PictureInPictureEnabled() const {
  return IsDocumentAllowed(/*report_failure=*/true) == Status::kEnabled;
}

PictureInPictureController::Status
PictureInPictureControllerImpl::IsDocumentAllowed(bool report_failure) const {
  DCHECK(GetSupplementable());

  // If document has been detached from a frame, return kFrameDetached status.
  LocalFrame* frame = GetSupplementable()->GetFrame();
  if (!frame)
    return Status::kFrameDetached;

  // Picture-in-Picture is not allowed if the window is a document
  // Picture-in-Picture window.
  if (RuntimeEnabledFeatures::DocumentPictureInPictureAPIEnabled(
          GetSupplementable()->GetExecutionContext()) &&
      DomWindow() && DomWindow()->IsPictureInPictureWindow()) {
    return Status::kDocumentPip;
  }

  // `GetPictureInPictureEnabled()` returns false when the embedder or the
  // system forbids the page from using Picture-in-Picture.
  DCHECK(GetSupplementable()->GetSettings());
  if (!GetSupplementable()->GetSettings()->GetPictureInPictureEnabled())
    return Status::kDisabledBySystem;

  // If document is not allowed to use the policy-controlled feature named
  // "picture-in-picture", return kDisabledByPermissionsPolicy status.
  if (!GetSupplementable()->GetExecutionContext()->IsFeatureEnabled(
          blink::mojom::blink::PermissionsPolicyFeature::kPictureInPicture,
          report_failure ? ReportOptions::kReportOnFailure
                         : ReportOptions::kDoNotReport)) {
    return Status::kDisabledByPermissionsPolicy;
  }

  return Status::kEnabled;
}

PictureInPictureController::Status
PictureInPictureControllerImpl::IsElementAllowed(
    const HTMLVideoElement& video_element,
    bool report_failure) const {
  PictureInPictureController::Status status = IsDocumentAllowed(report_failure);
  if (status != Status::kEnabled)
    return status;

  if (video_element.getReadyState() == HTMLMediaElement::kHaveNothing)
    return Status::kMetadataNotLoaded;

  if (!video_element.HasVideo())
    return Status::kVideoTrackNotAvailable;

  if (video_element.FastHasAttribute(html_names::kDisablepictureinpictureAttr))
    return Status::kDisabledByAttribute;

  if (video_element.IsInAutoPIP())
    return Status::kAutoPipAndroid;

  return Status::kEnabled;
}

void PictureInPictureControllerImpl::EnterPictureInPicture(
    HTMLVideoElement* video_element,
    ScriptPromiseResolver<PictureInPictureWindow>* resolver) {
  if (!video_element->GetWebMediaPlayer()) {
    if (resolver) {
      // TODO(crbug.com/1293949): Add an error message.
      resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                       "");
    }

    return;
  }

  if (picture_in_picture_element_ == video_element) {
    if (resolver)
      resolver->Resolve(picture_in_picture_window_);

    return;
  }

  if (!EnsureService())
    return;

  if (video_element->GetDisplayType() == DisplayType::kFullscreen)
    Fullscreen::ExitFullscreen(*GetSupplementable());

  video_element->GetWebMediaPlayer()->OnRequestPictureInPicture();
  DCHECK(video_element->GetWebMediaPlayer()->GetSurfaceId().has_value());

  session_observer_receiver_.reset();

  mojo::PendingRemote<mojom::blink::PictureInPictureSessionObserver>
      session_observer;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      video_element->GetDocument().GetTaskRunner(TaskType::kMediaElementEvent);
  session_observer_receiver_.Bind(
      session_observer.InitWithNewPipeAndPassReceiver(), task_runner);

  mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>
      media_player_remote;
  video_element->BindMediaPlayerReceiver(
      media_player_remote.InitWithNewEndpointAndPassReceiver());

  gfx::Rect video_bounds;
  if (auto* layout_video =
          DynamicTo<LayoutVideo>(video_element->GetLayoutObject())) {
    PhysicalRect content_rect = layout_video->ReplacedContentRect();
    video_bounds = video_element->GetDocument().View()->FrameToViewport(
        ToEnclosingRect(layout_video->LocalToAbsoluteRect(content_rect)));
  } else {
    video_bounds = video_element->BoundsInWidget();
  }

  picture_in_picture_service_->StartSession(
      video_element->GetWebMediaPlayer()->GetDelegateId(),
      std::move(media_player_remote),
      video_element->GetWebMediaPlayer()->GetSurfaceId().value(),
      video_element->GetWebMediaPlayer()->NaturalSize(),
      ShouldShowPlayPauseButton(*video_element), std::move(session_observer),
      video_bounds,
      WTF::BindOnce(&PictureInPictureControllerImpl::OnEnteredPictureInPicture,
                    WrapPersistent(this), WrapPersistent(video_element),
                    WrapPersistent(resolver)));
}

void PictureInPictureControllerImpl::OnEnteredPictureInPicture(
    HTMLVideoElement* element,
    ScriptPromiseResolver<PictureInPictureWindow>* resolver,
    mojo::PendingRemote<mojom::blink::PictureInPictureSession> session_remote,
    const gfx::Size& picture_in_picture_window_size) {
  // If |session_ptr| is null then Picture-in-Picture is not supported by the
  // browser. We should rarely see this because we should have already rejected
  // with |kDisabledBySystem|.
  if (!session_remote) {
    if (resolver &&
        IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                      resolver->GetScriptState())) {
      ScriptState::Scope script_state_scope(resolver->GetScriptState());
      resolver->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                       "Picture-in-Picture is not available.");
    }

    return;
  }

  picture_in_picture_session_.reset();
  picture_in_picture_session_.Bind(
      std::move(session_remote),
      element->GetDocument().GetTaskRunner(TaskType::kMediaElementEvent));
  if (IsElementAllowed(*element, /*report_failure=*/true) != Status::kEnabled) {
    if (resolver &&
        IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                      resolver->GetScriptState())) {
      ScriptState::Scope script_state_scope(resolver->GetScriptState());
      // TODO(crbug.com/1293949): Add an error message.
      resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                       "");
    }

    ExitPictureInPicture(element, nullptr);
    return;
  }

  if (picture_in_picture_element_)
    OnExitedPictureInPicture(nullptr);

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
  if (document_picture_in_picture_window_) {
    // TODO(crbug.com/1360452): close the window too.
    document_picture_in_picture_window_ = nullptr;
  }
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

  picture_in_picture_element_ = element;
  picture_in_picture_element_->OnEnteredPictureInPicture();

  // Request that viz does not throttle our LayerTree's BeginFrame messages, in
  // case this page generates them as a side-effect of driving picture-in-
  // picture content.  See the header file for more details, or
  // https://crbug.com/1232173
  SetMayThrottleIfUndrawnFrames(false);

  picture_in_picture_window_ = MakeGarbageCollected<PictureInPictureWindow>(
      GetExecutionContext(), picture_in_picture_window_size);

  picture_in_picture_element_->DispatchEvent(*PictureInPictureEvent::Create(
      event_type_names::kEnterpictureinpicture,
      WrapPersistent(picture_in_picture_window_.Get())));

  if (resolver)
    resolver->Resolve(picture_in_picture_window_);

  // Unregister the video frame sink from the element since it will be moved
  // to be the child of the PiP window frame sink.
  if (picture_in_picture_element_->GetWebMediaPlayer()) {
    picture_in_picture_element_->GetWebMediaPlayer()
        ->UnregisterFrameSinkHierarchy();
  }
}

void PictureInPictureControllerImpl::ExitPictureInPicture(
    HTMLVideoElement* element,
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  if (!EnsureService())
    return;

  if (!picture_in_picture_session_.is_bound())
    return;

  picture_in_picture_session_->Stop(
      WTF::BindOnce(&PictureInPictureControllerImpl::OnExitedPictureInPicture,
                    WrapPersistent(this), WrapPersistent(resolver)));
  session_observer_receiver_.reset();
}

void PictureInPictureControllerImpl::OnExitedPictureInPicture(
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  DCHECK(GetSupplementable());

  // Bail out if document is not active.
  if (!GetSupplementable()->IsActive())
    return;

  // Now that this widget is not responsible for providing the content for a
  // Picture in Picture window, we should not be producing CompositorFrames
  // while the widget is hidden.  Let viz know that throttling us is okay if we
  // do that.
  SetMayThrottleIfUndrawnFrames(true);

  // The Picture-in-Picture window and the Picture-in-Picture element
  // should be either both set or both null.
  DCHECK(!picture_in_picture_element_ == !picture_in_picture_window_);
  if (picture_in_picture_element_) {
    picture_in_picture_window_->OnClose();

    HTMLVideoElement* element = picture_in_picture_element_;
    picture_in_picture_element_ = nullptr;

    element->OnExitedPictureInPicture();
    element->DispatchEvent(*PictureInPictureEvent::Create(
        event_type_names::kLeavepictureinpicture,
        WrapPersistent(picture_in_picture_window_.Get())));

    picture_in_picture_window_ = nullptr;

    // Register the video frame sink back to the element when the PiP window
    // is closed and if the video is not unset.
    if (element->GetWebMediaPlayer()) {
      element->GetWebMediaPlayer()->RegisterFrameSinkHierarchy();
    }
  }

  if (resolver)
    resolver->Resolve();
}

PictureInPictureWindow* PictureInPictureControllerImpl::pictureInPictureWindow()
    const {
  return picture_in_picture_window_.Get();
}

Element* PictureInPictureControllerImpl::PictureInPictureElement() const {
  return picture_in_picture_element_.Get();
}

Element* PictureInPictureControllerImpl::PictureInPictureElement(
    TreeScope& scope) const {
  if (!picture_in_picture_element_)
    return nullptr;

  return scope.AdjustedElement(*picture_in_picture_element_);
}

bool PictureInPictureControllerImpl::IsPictureInPictureElement(
    const Element* element) const {
  DCHECK(element);
  return element == picture_in_picture_element_;
}

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
LocalDOMWindow* PictureInPictureControllerImpl::documentPictureInPictureWindow()
    const {
  return document_picture_in_picture_window_.Get();
}

LocalDOMWindow*
PictureInPictureControllerImpl::GetDocumentPictureInPictureWindow() const {
  return document_picture_in_picture_window_;
}

LocalDOMWindow*
PictureInPictureControllerImpl::GetDocumentPictureInPictureOwner() const {
  return document_picture_in_picture_owner_;
}

void PictureInPictureControllerImpl::SetDocumentPictureInPictureOwner(
    LocalDOMWindow* owner) {
  CHECK(owner);

  document_picture_in_picture_owner_ = owner;
  document_pip_context_observer_ =
      MakeGarbageCollected<DocumentPictureInPictureObserver>(this);
  document_pip_context_observer_->SetContextLifecycleNotifier(owner);
}

void PictureInPictureControllerImpl::CreateDocumentPictureInPictureWindow(
    ScriptState* script_state,
    LocalDOMWindow& opener,
    DocumentPictureInPictureOptions* options,
    ScriptPromiseResolver<DOMWindow>* resolver) {
  if (!LocalFrame::ConsumeTransientUserActivation(opener.GetFrame())) {
    resolver->RejectWithDOMException(DOMExceptionCode::kNotAllowedError,
                                     "Document PiP requires user activation");
    return;
  }

  WebPictureInPictureWindowOptions web_options;
  web_options.width = options->width();
  web_options.height = options->height();
  web_options.disallow_return_to_opener = options->disallowReturnToOpener();
  web_options.prefer_initial_window_placement =
      options->preferInitialWindowPlacement();

  // If either width or height is specified, then both must be specified.
  if (web_options.width > 0 && web_options.height == 0) {
    resolver->RejectWithRangeError(
        "Height must be specified if width is specified");
    return;
  } else if (web_options.width == 0 && web_options.height > 0) {
    resolver->RejectWithRangeError(
        "Width must be specified if height is specified");
    return;
  }

  auto* dom_window = opener.openPictureInPictureWindow(
      script_state->GetIsolate(), web_options);

  if (!dom_window) {
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     "Internal error: no window");
    return;
  }

  auto* local_dom_window = dom_window->ToLocalDOMWindow();
  DCHECK(local_dom_window);

  // Instantiate WindowProxy, so that a script state can be created for it
  // successfully later.
  // TODO(https://crbug.com/1336142): This should not be necessary.
  local_dom_window->GetScriptController().WindowProxy(script_state->World());

  // Set the Picture-in-Picture window's base URL to be the same as the opener
  // window's so that relative URLs will be resolved in the same way.
  Document* pip_document = local_dom_window->document();
  DCHECK(pip_document);
  pip_document->SetBaseURLOverride(opener.document()->BaseURL());

  SetMayThrottleIfUndrawnFrames(false);

  if (!document_pip_context_observer_) {
    document_pip_context_observer_ =
        MakeGarbageCollected<DocumentPictureInPictureObserver>(this);
  }
  document_pip_context_observer_->SetContextLifecycleNotifier(
      pip_document->GetExecutionContext());

  // While this API could be synchronous since we're using the |window.open()|
  // API to open the PiP window, we still use a Promise and post a task to make
  // it asynchronous because:
  // 1) We may eventually make this an asynchronous call to the browsser
  // 2) Other UAs may want to implement the API in an asynchronous way

  // If we have a task waiting already, just cancel the task and immediately
  // resolve.
  if (open_document_pip_task_.IsActive()) {
    open_document_pip_task_.Cancel();
    ResolveOpenDocumentPictureInPicture();
  }

  document_picture_in_picture_window_ = local_dom_window;

  // Give the pip document's PictureInPictureControllerImpl a pointer to our
  // window as its owner/opener.
  From(*pip_document)
      .SetDocumentPictureInPictureOwner(GetSupplementable()->domWindow());

  // There should not be an unresolved ScriptPromiseResolverBase at this point.
  // Leaving one unresolved and letting it get garbage collected will crash the
  // renderer.
  DCHECK(!open_document_pip_resolver_);
  open_document_pip_resolver_ = resolver;

  open_document_pip_task_ = PostCancellableTask(
      *opener.GetTaskRunner(TaskType::kInternalDefault), FROM_HERE,
      WTF::BindOnce(
          &PictureInPictureControllerImpl::ResolveOpenDocumentPictureInPicture,
          WrapPersistent(this)));
}

void PictureInPictureControllerImpl::ResolveOpenDocumentPictureInPicture() {
  CHECK(document_picture_in_picture_window_);
  CHECK(open_document_pip_resolver_);

  if (DomWindow()) {
    DocumentPictureInPicture::From(*DomWindow())
        ->DispatchEvent(*DocumentPictureInPictureEvent::Create(
            event_type_names::kEnter,
            WrapPersistent(document_picture_in_picture_window_.Get())));
  }

  open_document_pip_resolver_->Resolve(document_picture_in_picture_window_);
  open_document_pip_resolver_ = nullptr;
}

PictureInPictureControllerImpl::DocumentPictureInPictureObserver::
    DocumentPictureInPictureObserver(PictureInPictureControllerImpl* controller)
    : controller_(controller) {}
PictureInPictureControllerImpl::DocumentPictureInPictureObserver::
    ~DocumentPictureInPictureObserver() = default;

void PictureInPictureControllerImpl::DocumentPictureInPictureObserver::
    ContextDestroyed() {
  controller_->OnDocumentPictureInPictureContextDestroyed();
}

void PictureInPictureControllerImpl::DocumentPictureInPictureObserver::Trace(
    Visitor* visitor) const {
  visitor->Trace(controller_);
  ContextLifecycleObserver::Trace(visitor);
}

void PictureInPictureControllerImpl::
    OnDocumentPictureInPictureContextDestroyed() {
  // If we have an owner, then we are contained in a picture-in-picture window
  // and our owner's context has been destroyed.
  if (document_picture_in_picture_owner_) {
    CHECK(!document_picture_in_picture_window_);
    OnDocumentPictureInPictureOwnerWindowContextDestroyed();
    return;
  }

  // Otherwise, our owned picture-in-picture window's context has been
  // destroyed.
  OnOwnedDocumentPictureInPictureWindowContextDestroyed();
}

void PictureInPictureControllerImpl::
    OnOwnedDocumentPictureInPictureWindowContextDestroyed() {
  // The document PIP window has been destroyed, so the opener is no longer
  // associated with it.  Allow throttling again.
  SetMayThrottleIfUndrawnFrames(true);
  document_picture_in_picture_window_ = nullptr;

  // If there is an unresolved promise for a document PiP window, reject it now.
  // Note that we know that it goes with the current session, since we replace
  // the context observer's context at the same time we replace the session.
  if (open_document_pip_task_.IsActive()) {
    open_document_pip_task_.Cancel();
    open_document_pip_resolver_->Reject();
    open_document_pip_resolver_ = nullptr;
  }
}

void PictureInPictureControllerImpl::
    OnDocumentPictureInPictureOwnerWindowContextDestroyed() {
  document_picture_in_picture_owner_ = nullptr;
}
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

void PictureInPictureControllerImpl::OnPictureInPictureStateChange() {
  DCHECK(picture_in_picture_element_);
  DCHECK(picture_in_picture_element_->GetWebMediaPlayer());
  DCHECK(picture_in_picture_element_->GetWebMediaPlayer()
             ->GetSurfaceId()
             .has_value());

  // The lifetime of the MediaPlayer mojo endpoint in the renderer is tied to
  // WebMediaPlayer, which is recreated by |picture_in_picture_element_| on
  // src= change. Since src= change is one of the reasons we get here, we need
  // to give the browser a newly bound remote.
  mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>
      media_player_remote;
  picture_in_picture_element_->BindMediaPlayerReceiver(
      media_player_remote.InitWithNewEndpointAndPassReceiver());

  picture_in_picture_session_->Update(
      picture_in_picture_element_->GetWebMediaPlayer()->GetDelegateId(),
      std::move(media_player_remote),
      picture_in_picture_element_->GetWebMediaPlayer()->GetSurfaceId().value(),
      picture_in_picture_element_->GetWebMediaPlayer()->NaturalSize(),
      ShouldShowPlayPauseButton(*picture_in_picture_element_));
}

void PictureInPictureControllerImpl::OnWindowSizeChanged(
    const gfx::Size& size) {
  if (picture_in_picture_window_)
    picture_in_picture_window_->OnResize(size);
}

void PictureInPictureControllerImpl::OnStopped() {
  OnExitedPictureInPicture(nullptr);
}

void PictureInPictureControllerImpl::SetMayThrottleIfUndrawnFrames(
    bool may_throttle) {
  if (!GetSupplementable()->GetFrame() ||
      !GetSupplementable()->GetFrame()->GetWidgetForLocalRoot()) {
    // Tests do not always have a frame or widget.
    return;
  }
  GetSupplementable()
      ->GetFrame()
      ->GetWidgetForLocalRoot()
      ->SetMayThrottleIfUndrawnFrames(may_throttle);
}

void PictureInPictureControllerImpl::Trace(Visitor* visitor) const {
#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
  visitor->Trace(document_picture_in_picture_window_);
  visitor->Trace(document_picture_in_picture_owner_);
  visitor->Trace(document_pip_context_observer_);
  visitor->Trace(open_document_pip_resolver_);
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)
  visitor->Trace(picture_in_picture_element_);
  visitor->Trace(picture_in_picture_window_);
  visitor->Trace(session_observer_receiver_);
  visitor->Trace(picture_in_picture_service_);
  visitor->Trace(picture_in_picture_session_);
  PictureInPictureController::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

PictureInPictureControllerImpl::PictureInPictureControllerImpl(
    Document& document)
    : PictureInPictureController(document),
      ExecutionContextClient(document.GetExecutionContext()),
      session_observer_receiver_(this, document.GetExecutionContext()),
      picture_in_picture_service_(document.GetExecutionContext()),
      picture_in_picture_session_(document.GetExecutionContext()) {}

bool PictureInPictureControllerImpl::EnsureService() {
  if (picture_in_picture_service_.is_bound())
    return true;

  if (!GetSupplementable()->GetFrame())
    return false;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetSupplementable()->GetFrame()->GetTaskRunner(
          TaskType::kMediaElementEvent);
  GetSupplementable()->GetFrame()->GetBrowserInterfaceBroker().GetInterface(
      picture_in_picture_service_.BindNewPipeAndPassReceiver(task_runner));
  return true;
}

}  // namespace blink
```