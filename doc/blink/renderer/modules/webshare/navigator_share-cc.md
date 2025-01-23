Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The request asks for an analysis of the `navigator_share.cc` file in the Chromium Blink engine. The focus is on its functionality, relationships with web technologies (JS, HTML, CSS), logical reasoning, potential errors, and how user actions lead to its execution.

2. **Initial Code Scan and Keyword Identification:**
   - Immediately recognize `#include` statements. These point to dependencies and give clues about the file's purpose. Key includes like `webshare/navigator_share.h`, `mojom/webshare_service.mojom-blink.h`,  `ScriptPromiseResolver`, `ShareData`, `File`, `Navigator`, etc., are strong indicators of the file's role in the Web Share API implementation.
   - Look for class names. `NavigatorShare` is the central class. The nested `ShareClientImpl` is also important.
   - Identify key function names: `canShare`, `share`, `Callback`, `OnConnectionError`. These are the primary actions the class performs.
   - Note the namespaces: `blink` and the anonymous namespace.

3. **High-Level Functionality Deduction:** Based on the includes and class/function names, conclude that this file implements the core logic for the Web Share API within the Blink rendering engine. It handles requests from JavaScript to share data (text, URLs, files) using the underlying platform's sharing capabilities.

4. **Detailed Function Analysis (Iterate through the code):**
   - **Constants:** Pay attention to constants like `kMaxSharedFileCount`, `kMaxSharedFileBytes`, `kMaxTitleLength`, etc. These define limitations and constraints on the sharing process.
   - **Error Handling:**  Examine the `ErrorToString` function and how `mojom::blink::ShareError` is used. This indicates how sharing failures are reported.
   - **`CanShareInternal`:**  This function is crucial for determining if a share operation *can* be performed. Note its checks for empty data, URL validity, and how it uses `ExceptionState` for reporting errors.
   - **`ShareClientImpl`:**  This inner class manages the asynchronous nature of the sharing process using Promises. Focus on how it interacts with the `NavigatorShare` and handles callbacks.
   - **`NavigatorShare::canShare` (overloads):**  These methods expose the ability to check if sharing is possible. Notice the permission policy check.
   - **`NavigatorShare::share` (overloads):** This is the core function for initiating the share. Analyze the steps:
     - Context and feature enablement checks.
     - Transient user activation requirement.
     - Check for existing ongoing shares.
     - Data validation (length limits, file safety, file counts, total size).
     - Interaction with the `service_remote_` (the browser process interface).
     - Promise creation and handling using `ShareClientImpl`.
   - **`OnConnectionError`:**  Handles the case where the connection to the browser process is lost.

5. **Relating to Web Technologies:**
   - **JavaScript:**  The `canShare` and `share` methods are directly called from JavaScript using the `navigator.share()` and `navigator.canShare()` APIs. The `ShareData` object in C++ corresponds to the JavaScript object passed to these functions. The `ScriptPromise` in C++ represents the Promise returned to JavaScript.
   - **HTML:**  HTML triggers the JavaScript that eventually calls these C++ functions (e.g., through a button click or other user interaction).
   - **CSS:** CSS is not directly involved in the *core logic* of the sharing process itself, but it influences the user interface elements (buttons, links) that trigger the sharing action.

6. **Logical Reasoning and Examples:**
   - **Assumption:** A user clicks a "Share" button on a webpage.
   - **Input (JavaScript):**  `navigator.share({ title: 'My Page', text: 'Check this out!', url: 'https://example.com' })`
   - **Output (C++):** The `NavigatorShare::share` function receives this data in the `ShareData` object and initiates the platform's sharing mechanism. The Promise resolves or rejects based on the outcome.
   - **Assumption (File Sharing):** A user tries to share files exceeding the limits.
   - **Input (JavaScript):** `navigator.share({ files: [file1, file2, ...] })` where the number or total size of files exceeds the limits.
   - **Output (C++):** The C++ code will detect this in the `share` method and throw a `NotAllowedError` DOMException, which is then propagated back to JavaScript, rejecting the Promise.

7. **Common User/Programming Errors:** Think about what mistakes developers or users might make when using the Web Share API.
   - Not handling the Promise rejection.
   - Trying to share without a user gesture.
   - Providing invalid URLs.
   - Exceeding data limits (file count, file size, text length).
   - Incorrectly assuming the API is always available.

8. **Debugging Steps:** Trace the user interaction from the initial action to the C++ code.
   - User clicks a button/link.
   - JavaScript event handler is triggered.
   - JavaScript calls `navigator.share()`.
   - The browser internally routes this call to the Blink rendering engine.
   - The `NavigatorShare::share` method in `navigator_share.cc` is invoked.

9. **Structure and Refine:** Organize the information logically, using headings and bullet points for clarity. Ensure the language is clear and concise. Double-check for accuracy and completeness. Provide concrete examples to illustrate the concepts. Initially, my thoughts might be a bit scattered, but structuring them into categories like "Functionality," "Relationships," "Logic," "Errors," and "Debugging" brings order. Review and refine the language to make it more precise. For instance, instead of just saying "it handles sharing," be more specific about *what* data is shared and *how* it's handled (through a browser service).

By following these steps, systematically examining the code, and considering the context of web development, a comprehensive and accurate analysis can be generated.
这个文件 `blink/renderer/modules/webshare/navigator_share.cc` 是 Chromium Blink 引擎中实现 **Web Share API** 的核心部分。它负责处理网页发起的共享请求，并与底层操作系统进行交互，最终将数据分享到其他应用程序。

**主要功能：**

1. **接收和验证共享数据:**
   - 从 JavaScript 接收 `navigator.share()` 方法传递的共享数据，这些数据可能包含 `title` (标题), `text` (文本), `url` (链接) 和 `files` (文件)。
   - 对接收到的数据进行各种验证，例如：
     - 检查是否提供了任何可共享的数据 (title, text, url, files)。
     - 验证 URL 的有效性。
     - 检查标题、文本和 URL 的长度是否超过预设的最大值 (`kMaxTitleLength`, `kMaxTextLength`, `kMaxUrlLength`)。
     - 检查共享文件的数量和总大小是否超过预设的最大值 (`kMaxSharedFileCount`, `kMaxSharedFileBytes`)。
     - 检查文件名是否安全。
2. **处理权限和用户手势:**
   - 检查 Permissions Policy 是否允许使用 Web Share API。
   - 强制要求共享操作必须在处理用户手势（例如，点击事件）时触发，以防止恶意网站滥用共享功能。
   - 检查当前页面是否在 Fenced Frame 中，如果是则不允许共享。
3. **与浏览器进程通信:**
   - 通过 `BrowserInterfaceBroker` 与浏览器进程建立连接 (使用 `mojom::blink::WebShareService` 接口)。
   - 将验证后的共享数据（包括标题、文本、URL 和文件）发送到浏览器进程。
4. **处理共享结果:**
   - 从浏览器进程接收共享操作的结果（成功或失败）。
   - 如果共享成功，则 `share()` 方法返回的 Promise 会 resolve。
   - 如果共享失败，则 Promise 会 reject，并根据错误类型抛出相应的 `DOMException` (例如，`NotAllowedError` 表示权限被拒绝，`AbortError` 表示操作被取消或发生内部错误)。
5. **管理并发共享请求:**
   - 在非 Android 平台上，为了避免潜在的问题，同一时刻只允许进行一个共享操作。如果前一个共享操作尚未完成，则会抛出 `InvalidStateError`。
6. **记录使用情况:**
   - 使用 `UseCounter` 记录 Web Share API 的使用情况，例如是否成功、是否包含文件等，用于统计和分析。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `navigator_share.cc` 是 Web Share API 的底层实现，JavaScript 通过 `navigator.share()` 和 `navigator.canShare()` 方法来调用它的功能。
   ```javascript
   // JavaScript 调用 Web Share API
   document.getElementById('shareButton').addEventListener('click', async () => {
     try {
       await navigator.share({
         title: '精彩内容',
         text: '快来看看这个！',
         url: 'https://example.com',
       });
       console.log('共享成功！');
     } catch (error) {
       console.error('共享失败:', error);
     }
   });
   ```
   在这个例子中，当用户点击 ID 为 `shareButton` 的元素时，JavaScript 代码调用 `navigator.share()` 方法，并将共享数据传递给浏览器。Blink 引擎的 `navigator_share.cc` 文件会接收这些数据并处理共享逻辑。

* **HTML:** HTML 提供了触发 JavaScript 代码的元素（例如按钮、链接）。在上面的例子中，`<button id="shareButton">分享</button>` 就是一个触发共享操作的 HTML 元素。

* **CSS:** CSS 负责网页的样式和布局，与 `navigator_share.cc` 的核心功能没有直接关系。但是，CSS 可以用来美化触发共享操作的 UI 元素。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

* **用户操作:** 用户点击了一个 "分享到 Twitter" 的按钮。
* **JavaScript 代码:**
  ```javascript
  navigator.share({
    text: '刚刚在 [网站名称] 上看到了一个很棒的文章：[文章标题] [文章链接]',
    url: '[文章链接]'
  });
  ```

* **C++ 处理:**
    * `NavigatorShare::share` 方法被调用。
    * 检查用户手势存在。
    * 检查 Permissions Policy 允许 `web-share`。
    * 文本和 URL 的长度都在限制范围内。
    * 与浏览器进程的 WebShareService 通信，将文本和 URL 发送给操作系统。
    * 操作系统弹出分享对话框，列出可用的分享目标（例如 Twitter）。
* **假设输出:** 操作系统显示分享对话框，用户可以选择 Twitter 应用进行分享。如果用户选择并成功分享，Promise 会 resolve。如果用户取消分享或发生错误，Promise 会 reject。

**假设输入 2:**

* **用户操作:** 用户尝试分享 15 个文件。
* **JavaScript 代码:**
  ```javascript
  navigator.share({ files: [file1, file2, ..., file15] });
  ```

* **C++ 处理:**
    * `NavigatorShare::share` 方法被调用。
    * 检查用户手势存在。
    * 检查 Permissions Policy 允许 `web-share`。
    * 在处理文件时，发现文件数量 (15) 大于 `kMaxSharedFileCount` (10)。
    * `execution_context->AddConsoleMessage` 发出警告 "Share too large"。
    * `exception_state.ThrowDOMException` 抛出 `NotAllowedError` 异常。
* **假设输出:** JavaScript 的 `navigator.share()` 返回的 Promise 会被 reject，并抛出一个 `NotAllowedError` 类型的 DOMException。控制台会输出 "Share too large" 的警告信息。

**用户或编程常见的使用错误：**

1. **在非用户手势处理程序中调用 `navigator.share()`:**
   ```javascript
   // 错误示例：在页面加载完成后立即尝试分享
   window.onload = async () => {
     try {
       await navigator.share({ title: '尝试分享' });
     } catch (error) {
       console.error('分享失败:', error); // 可能抛出 NotAllowedError
     }
   };
   ```
   **错误说明:**  Web Share API 需要用户的主动操作来触发，直接在页面加载完成时调用会被浏览器阻止，并抛出 `NotAllowedError` 异常。

2. **未处理 `navigator.share()` 返回的 Promise 的 rejection:**
   ```javascript
   // 不推荐：未处理错误情况
   navigator.share({ title: '可能失败的分享' });
   ```
   **错误说明:**  共享操作可能因为各种原因失败（用户取消、权限拒绝、内部错误等）。如果不处理 Promise 的 rejection，开发者无法得知共享是否成功，用户体验会很差。应该使用 `try...catch` 或 `.catch()` 来处理错误。

3. **尝试分享超出限制的数据:**
   ```javascript
   // 尝试分享过长的文本
   navigator.share({ text: 'A'.repeat(200 * 1024) }); // 假设超过 kMaxTextLength
   ```
   **错误说明:**  如果共享的数据（文本、URL）或文件数量/大小超过了浏览器的限制，`navigator.share()` 会抛出 `NotAllowedError` 异常。

4. **分享不安全的文件名:**
   ```javascript
   const file = new File(['内容'], '../evil.sh', { type: 'text/plain' });
   navigator.share({ files: [file] });
   ```
   **错误说明:**  Blink 会检查文件名是否安全，包含 `..` 等路径操作符的文件名会被认为是unsafe，导致分享失败并抛出 `NotAllowedError`。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在网页上执行了某个操作，触发了一个 JavaScript 事件处理程序。** 例如，点击了一个 "分享" 按钮，或者点击了网页上的某个链接。

2. **JavaScript 事件处理程序调用了 `navigator.share(data)` 方法。**  `data` 对象包含了要分享的标题、文本、URL 和/或文件。

3. **浏览器接收到 JavaScript 的 `navigator.share()` 调用。**  浏览器会将这个调用路由到 Blink 渲染引擎中的相应模块。

4. **Blink 引擎的 `Navigator::share()` 方法被调用 (在 `blink/renderer/core/frame/navigator.cc` 中)。** 这个方法会获取到 `NavigatorShare` 辅助对象。

5. **`NavigatorShare::share(ScriptState* script_state, const ShareData* data, ExceptionState& exception_state)` 方法被调用 (在 `navigator_share.cc` 中)。**

6. **在 `NavigatorShare::share` 方法中，会进行一系列的检查和处理：**
   - 检查 Permissions Policy。
   - 检查用户手势。
   - 验证共享数据的有效性和大小限制。
   - 如果需要，与浏览器进程建立连接 (`service_remote_`)。
   - 将共享请求发送到浏览器进程。

7. **浏览器进程接收到共享请求，并调用操作系统的原生分享功能。**  操作系统会显示分享对话框，用户可以选择要分享到的应用程序。

8. **用户在操作系统分享对话框中选择目标应用并完成分享，或者取消分享。**

9. **操作系统将分享结果返回给浏览器进程。**

10. **浏览器进程将分享结果通过 `mojom::blink::WebShareService::ShareCallback` 传递回 Blink 渲染引擎。**

11. **`NavigatorShare::ShareClientImpl::Callback` 方法被调用，处理分享结果。**

12. **`NavigatorShare::share()` 方法返回的 Promise 根据分享结果 resolve 或 reject。**  JavaScript 代码中的 `then()` 或 `catch()` 回调函数会被执行。

**调试线索:**

* **检查 JavaScript 代码中 `navigator.share()` 的调用是否在用户手势处理程序中。**
* **使用浏览器的开发者工具查看控制台，是否有关于 Web Share API 的错误或警告信息。**
* **在 Blink 源代码中设置断点，例如在 `NavigatorShare::share` 方法的入口处，以及在数据验证和与浏览器进程通信的关键步骤。**
* **查看 `chrome://webrtc-internals` 页面，有时可以提供一些关于媒体相关操作的信息，虽然 Web Share 主要用于数据，但如果涉及到文件，可能会有一些关联。**
* **检查 Permissions Policy 是否阻止了 Web Share API 的使用。**
* **如果涉及到文件分享，检查文件的状态和访问权限。**

### 提示词
```
这是目录为blink/renderer/modules/webshare/navigator_share.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webshare/navigator_share.h"

#include <stdint.h>

#include <utility>

#include "base/files/safe_base_name.h"
#include "build/build_config.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/file_path_conversion.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_share_data.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_or_worker_scheduler.h"

namespace blink {

namespace {

constexpr size_t kMaxSharedFileCount = 10;
constexpr uint32_t kMaxSharedFileBytes = 50U * 1024 * 1024;

constexpr uint32_t kMaxTitleLength = 16U * 1024;
#if BUILDFLAG(IS_ANDROID)
constexpr uint32_t kMaxTextLength = 120U * 1024;
#else
constexpr uint32_t kMaxTextLength = 1U * 1024 * 1024;
#endif
constexpr uint32_t kMaxUrlLength = 16U * 1024;

// Gets the human-friendly error message for a ShareError. |error| must not be
// ShareError::OK.
String ErrorToString(mojom::blink::ShareError error) {
  switch (error) {
    case mojom::blink::ShareError::OK:
      NOTREACHED();
    case mojom::blink::ShareError::INTERNAL_ERROR:
      return "Share failed";
    case mojom::blink::ShareError::PERMISSION_DENIED:
      return "Permission denied";
    case mojom::blink::ShareError::CANCELED:
      return "Share canceled";
  }
  NOTREACHED();
}

bool HasFiles(const ShareData& data) {
  if (!data.hasFiles())
    return false;

  return !data.files().empty();
}

// Returns true unless |share(data)| would reject with TypeError.
// Populates |url| with the result of running the URL parser on |data.url|.
// If the return value is false and |exception_state| is non null, throws
// TypeError.
//
// https://w3c.github.io/web-share/level-2/#canshare-method
// https://w3c.github.io/web-share/level-2/#share-method
bool CanShareInternal(const LocalDOMWindow& window,
                      const ShareData& data,
                      KURL& url,
                      ExceptionState* exception_state) {
  if (!data.hasTitle() && !data.hasText() && !data.hasUrl() &&
      !HasFiles(data)) {
    if (exception_state) {
      exception_state->ThrowTypeError(
          "No known share data fields supplied. If using only new fields "
          "(other than title, text and url), you must feature-detect "
          "them first.");
    }
    return false;
  }

  if (data.hasUrl()) {
    url = window.CompleteURL(data.url());
    if (!url.IsValid() ||
        (!url.ProtocolIsInHTTPFamily() &&
         url.Protocol() != window.document()->BaseURL().Protocol())) {
      if (exception_state) {
        exception_state->ThrowTypeError("Invalid URL");
      }
      return false;
    }
  }

  return true;
}

}  // namespace

class NavigatorShare::ShareClientImpl final
    : public GarbageCollected<ShareClientImpl> {
 public:
  ShareClientImpl(NavigatorShare*,
                  bool has_files,
                  ScriptPromiseResolver<IDLUndefined>*);

  void Callback(mojom::blink::ShareError);

  void OnConnectionError();

  void Trace(Visitor* visitor) const {
    visitor->Trace(navigator_);
    visitor->Trace(resolver_);
  }

 private:
  WeakMember<NavigatorShare> navigator_;
  bool has_files_;
  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  FrameOrWorkerScheduler::SchedulingAffectingFeatureHandle
      feature_handle_for_scheduler_;
};

NavigatorShare::ShareClientImpl::ShareClientImpl(
    NavigatorShare* navigator_share,
    bool has_files,
    ScriptPromiseResolver<IDLUndefined>* resolver)
    : navigator_(navigator_share),
      has_files_(has_files),
      resolver_(resolver),
      feature_handle_for_scheduler_(
          ExecutionContext::From(resolver_->GetScriptState())
              ->GetScheduler()
              ->RegisterFeature(
                  SchedulingPolicy::Feature::kWebShare,
                  {SchedulingPolicy::DisableBackForwardCache()})) {}

void NavigatorShare::ShareClientImpl::Callback(mojom::blink::ShareError error) {
  if (navigator_) {
    DCHECK(navigator_->clients_.Contains(this));
    navigator_->clients_.erase(this);
  }

  if (error == mojom::blink::ShareError::OK) {
    UseCounter::Count(ExecutionContext::From(resolver_->GetScriptState()),
                      has_files_
                          ? WebFeature::kWebShareSuccessfulContainingFiles
                          : WebFeature::kWebShareSuccessfulWithoutFiles);
    resolver_->Resolve();
  } else {
    UseCounter::Count(ExecutionContext::From(resolver_->GetScriptState()),
                      has_files_
                          ? WebFeature::kWebShareUnsuccessfulContainingFiles
                          : WebFeature::kWebShareUnsuccessfulWithoutFiles);
    resolver_->Reject(MakeGarbageCollected<DOMException>(
        (error == mojom::blink::ShareError::PERMISSION_DENIED)
            ? DOMExceptionCode::kNotAllowedError
            : DOMExceptionCode::kAbortError,
        ErrorToString(error)));
  }
}

void NavigatorShare::ShareClientImpl::OnConnectionError() {
  resolver_->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError,
      "Internal error: could not connect to Web Share interface."));
}

NavigatorShare& NavigatorShare::From(Navigator& navigator) {
  NavigatorShare* supplement =
      Supplement<Navigator>::From<NavigatorShare>(navigator);
  if (!supplement) {
    supplement = MakeGarbageCollected<NavigatorShare>(navigator);
    ProvideTo(navigator, supplement);
  }
  return *supplement;
}

void NavigatorShare::Trace(Visitor* visitor) const {
  visitor->Trace(service_remote_);
  visitor->Trace(clients_);
  Supplement<Navigator>::Trace(visitor);
}

const char NavigatorShare::kSupplementName[] = "NavigatorShare";

bool NavigatorShare::canShare(ScriptState* script_state,
                              const ShareData* data) {
  if (!script_state->ContextIsValid())
    return false;

  if (!ExecutionContext::From(script_state)
           ->IsFeatureEnabled(
               mojom::blink::PermissionsPolicyFeature::kWebShare)) {
    return false;
  }

  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  KURL unused_url;
  return CanShareInternal(*window, *data, unused_url, nullptr);
}

bool NavigatorShare::canShare(ScriptState* script_state,
                              Navigator& navigator,
                              const ShareData* data) {
  return From(navigator).canShare(script_state, data);
}

ScriptPromise<IDLUndefined> NavigatorShare::share(
    ScriptState* script_state,
    const ShareData* data,
    ExceptionState& exception_state) {
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Internal error: window frame is missing (the navigator may be "
        "detached).");
    return EmptyPromise();
  }

  LocalDOMWindow* const window = LocalDOMWindow::From(script_state);
  ExecutionContext* const execution_context =
      ExecutionContext::From(script_state);

  if (!execution_context->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kWebShare)) {
    window->CountUse(WebFeature::kWebSharePolicyDisallow);
    exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                      "Permission denied");
    return EmptyPromise();
  }
  window->CountUse(WebFeature::kWebSharePolicyAllow);

// This is due to a limitation on Android, where we sometimes are not advised
// when the share completes. This goes against the web share spec to work around
// the platform-specific bug, it is explicitly skipping section §2.1.2 step 2 of
// the Web Share spec. https://www.w3.org/TR/web-share/#share-method
#if !BUILDFLAG(IS_ANDROID)
  if (!clients_.empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "An earlier share has not yet completed.");
    return EmptyPromise();
  }
#endif

  if (!LocalFrame::ConsumeTransientUserActivation(window->GetFrame())) {
    VLOG(1) << "Share without transient activation (user gesture)";
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Must be handling a user gesture to perform a share request.");
    return EmptyPromise();
  }

  if (window->GetFrame()->IsInFencedFrameTree()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Web Share is not allowed in a fenced frame tree.");
    return EmptyPromise();
  }

  KURL url;
  if (!CanShareInternal(*window, *data, url, &exception_state)) {
    DCHECK(exception_state.HadException());
    return EmptyPromise();
  }

  if (!service_remote_.is_bound()) {
    // See https://bit.ly/2S0zRAS for task types.
    window->GetFrame()->GetBrowserInterfaceBroker().GetInterface(
        service_remote_.BindNewPipeAndPassReceiver(
            window->GetTaskRunner(TaskType::kMiscPlatformAPI)));
    service_remote_.set_disconnect_handler(WTF::BindOnce(
        &NavigatorShare::OnConnectionError, WrapWeakPersistent(this)));
    DCHECK(service_remote_.is_bound());
  }

  if ((data->hasTitle() && data->title().length() > kMaxTitleLength) ||
      (data->hasText() && data->text().length() > kMaxTextLength) ||
      (data->hasUrl() && data->url().length() > kMaxUrlLength)) {
    execution_context->AddConsoleMessage(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kWarning, "Share too large");
    exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                      "Permission denied");
    return EmptyPromise();
  }

  bool has_files = HasFiles(*data);
  WTF::Vector<mojom::blink::SharedFilePtr> files;
  uint64_t total_bytes = 0;
  if (has_files) {
    files.ReserveInitialCapacity(data->files().size());
    for (const blink::Member<blink::File>& file : data->files()) {
      std::optional<base::SafeBaseName> name =
          base::SafeBaseName::Create(StringToFilePath(file->name()));
      if (!name) {
        execution_context->AddConsoleMessage(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kWarning, "Unsafe file name");
        exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                          "Permission denied");
        return EmptyPromise();
      }

      total_bytes += file->size();
      files.push_back(mojom::blink::SharedFile::New(
          *name, file->GetBlobDataHandleWithKnownSize()));
    }

    if (files.size() > kMaxSharedFileCount ||
        total_bytes > kMaxSharedFileBytes) {
      execution_context->AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning, "Share too large");
      exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                        "Permission denied");
      return EmptyPromise();
    }
  }

  if (has_files)
    UseCounter::Count(execution_context, WebFeature::kWebShareContainingFiles);
  if (data->hasTitle())
    UseCounter::Count(execution_context, WebFeature::kWebShareContainingTitle);
  if (data->hasText())
    UseCounter::Count(execution_context, WebFeature::kWebShareContainingText);
  if (data->hasUrl())
    UseCounter::Count(execution_context, WebFeature::kWebShareContainingUrl);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());

  ShareClientImpl* client =
      MakeGarbageCollected<ShareClientImpl>(this, has_files, resolver);
  clients_.insert(client);
  auto promise = resolver->Promise();

  service_remote_->Share(
      data->hasTitle() ? data->title() : g_empty_string,
      data->hasText() ? data->text() : g_empty_string, url, std::move(files),
      WTF::BindOnce(&ShareClientImpl::Callback, WrapPersistent(client)));

  return promise;
}

ScriptPromise<IDLUndefined> NavigatorShare::share(
    ScriptState* script_state,
    Navigator& navigator,
    const ShareData* data,
    ExceptionState& exception_state) {
  return From(navigator).share(script_state, data, exception_state);
}

void NavigatorShare::OnConnectionError() {
  HeapHashSet<Member<ShareClientImpl>> clients;
  clients_.swap(clients);
  for (auto& client : clients) {
    client->OnConnectionError();
  }
  service_remote_.reset();
}

}  // namespace blink
```