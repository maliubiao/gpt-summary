Response:
Let's break down the thought process for analyzing the provided `wake_lock.cc` file.

**1. Initial Skim and Keyword Spotting:**

First, I'd quickly read through the code, looking for familiar keywords and patterns related to web development. Things that jump out include:

* `#include`: Indicates dependencies and functionalities used. I see `javascript`, `html`, `css` related concepts like `ScriptPromise`, `DOMException`, `Document`, `LocalDOMWindow`, `Page`, `PermissionsPolicyFeature`, `NavigatorBase`.
* `WakeLock`: The central concept.
* `request()`: A function that likely handles the user's request to acquire a wake lock.
* `WakeLockSentinel`:  Likely an object representing an active wake lock.
* `V8WakeLockType`: Suggests different types of wake locks (screen, system).
* `PermissionService`:  Indicates that acquiring a wake lock involves checking permissions.
* `UseCounter`:  Implies tracking usage for metrics.
* `ExecutionContext`, `PageVisibilityObserver`: Contextual information that affects wake lock behavior.
* `ContextDestroyed()`, `PageVisibilityChanged()`: Lifecycle methods hinting at how wake locks are managed.

**2. Understanding the Core Functionality (the `request()` method is key):**

The `request()` method is the entry point for acquiring a wake lock, so I'd focus on its steps:

* **Input:** `script_state`, `V8WakeLockType`, `exception_state`. This tells me it's called from JavaScript and takes the wake lock type as an argument.
* **Checks:**  Several `if` conditions suggest validation and security checks:
    * Browsing context existence.
    * Feature enablement (system wake lock).
    * Permissions policy (screen wake lock).
    * Worker context restrictions.
    * Document activity.
    * Page visibility.
    * User activation (sticky activation).
* **Promise:** It returns a `ScriptPromise<WakeLockSentinel>`, indicating an asynchronous operation.
* **`DoRequest()`:** This separates the actual permission request logic.
* **`UseCounter::Count()`:**  Metrics tracking.

**3. Tracing the Flow and Identifying Related Concepts:**

* **Permissions:** The `DoRequest()` method uses `PermissionService` to request permission. This clearly links to the browser's permission model. I'd think about how JavaScript uses `navigator.permissions.request()` and how that relates.
* **Asynchronous Operations:** The use of `ScriptPromise` signifies that acquiring a wake lock is not instantaneous. This is important for JavaScript interaction.
* **Wake Lock Types:** The `V8WakeLockType` enum with `kScreen` and `kSystem` highlights different use cases.
* **Lifecycle Management:** `ContextDestroyed()` and `PageVisibilityChanged()` demonstrate how wake locks are automatically released when the context or page visibility changes. This is crucial for resource management and user experience.

**4. Connecting to JavaScript, HTML, and CSS:**

Based on the understanding of the core functionality, I can now make explicit connections:

* **JavaScript:** The `request()` method is directly called from JavaScript using `navigator.wakeLock.request()`. The promise returned by this function is then handled using `.then()` and `.catch()`.
* **HTML:**  HTML provides the context (the web page) where the JavaScript code runs. The wake lock is associated with the document and its lifecycle.
* **CSS:**  While CSS doesn't directly control wake locks, it can influence user behavior and the need for wake locks. For example, a media-heavy page might encourage users to request a screen wake lock.

**5. Developing Examples (Hypothetical Input/Output and User Errors):**

* **Hypothetical Input/Output:**  Imagine a JavaScript call to `navigator.wakeLock.request('screen')`. The code checks permissions, and if granted, it returns a promise that resolves with a `WakeLockSentinel`. If denied, the promise rejects with a `NotAllowedError`.
* **User Errors:** Consider common mistakes like calling `request()` in a worker for a 'screen' lock, or failing to handle the promise rejection.

**6. Tracing User Operations (Debugging Perspective):**

To understand how a user reaches this code, I'd think about the user actions that trigger a wake lock request:

* User opens a web page.
* JavaScript code on the page calls `navigator.wakeLock.request('screen')` or `navigator.wakeLock.request('system')`.
* The browser's internals then route this request to the Blink engine, and eventually to this `wake_lock.cc` file.

**7. Structuring the Explanation:**

Finally, I'd organize the findings into clear sections:

* **Functionality:** A high-level overview of what the file does.
* **Relationship with Web Technologies:**  Detailed explanations and examples for JavaScript, HTML, and CSS.
* **Logic and Examples:** Hypothetical input/output scenarios.
* **Common Errors:** Examples of incorrect usage.
* **Debugging Clues:** Steps to trace the user's journey to this code.

**Self-Correction/Refinement during the Process:**

* Initially, I might focus too much on the low-level C++ details. I need to constantly remind myself to connect back to the user-facing web technologies.
* I need to ensure the examples are concrete and easy to understand, avoiding overly technical jargon.
*  It's important to distinguish between "screen" and "system" wake locks and their specific restrictions (e.g., screen lock in workers).

By following this thought process, systematically breaking down the code, and connecting it to the broader web development context, I can arrive at a comprehensive and informative explanation like the example provided in the prompt.
这个 `wake_lock.cc` 文件是 Chromium Blink 引擎中负责实现 **Wake Lock API** 的核心代码。Wake Lock API 允许网页请求保持设备的屏幕或系统处于唤醒状态，防止设备进入睡眠模式。

下面详细列举其功能以及与 JavaScript、HTML、CSS 的关系、逻辑推理、用户错误和调试线索：

**功能:**

1. **接收来自 JavaScript 的 Wake Lock 请求:**  通过 `WakeLock::request` 方法接收 JavaScript 代码发起的请求，请求指定 Wake Lock 的类型（"screen" 或 "system"）。
2. **权限管理:**
   - 检查 Permissions Policy，确保当前文档被允许使用 "screen-wake-lock" 或 "system-wake-lock" 功能。
   - 使用 `PermissionService` 请求用户授权，例如弹出权限提示框（如果尚未授权）。
3. **状态校验:**
   - 检查文档的浏览上下文是否有效。
   - 检查对于 "screen" 类型的 Wake Lock，当前页面是否处于激活状态且可见。
   - 对于在 Dedicated Worker 中发起的 "screen" 类型请求，会直接拒绝。
4. **Wake Lock 管理:**
   - 使用 `WakeLockManager` 类来管理不同类型的 Wake Lock（"screen" 和 "system"）。
   - 当权限被授予且校验通过后，调用 `WakeLockManager::AcquireWakeLock` 来实际获取 Wake Lock。
   - 创建并返回一个 `WakeLockSentinel` 对象，这个对象在 JavaScript 中表示一个已激活的 Wake Lock。
5. **生命周期管理:**
   - 监听文档和页面的生命周期事件（例如，文档销毁、页面可见性改变）。
   - 当文档被销毁或页面变为不可见时，自动释放相关的 Wake Lock，防止资源泄露。
6. **性能计数:** 使用 `UseCounter` 记录 Wake Lock API 的使用情况，例如获取 "screen" 或 "system" Wake Lock 的次数，以及在没有 Sticky User Activation 的情况下获取 "screen" Wake Lock 的情况。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** `wake_lock.cc` 文件实现了 Wake Lock API 的底层逻辑，JavaScript 代码通过 `navigator.wakeLock.request('screen')` 或 `navigator.wakeLock.request('system')` 来调用此功能。`WakeLockSentinel` 对象也会返回给 JavaScript，用于控制 Wake Lock 的释放 (`sentinel.release()`)。

   **举例:**

   ```javascript
   async function requestScreenWakeLock() {
     try {
       const wakeLock = await navigator.wakeLock.request('screen');
       console.log('Screen wake lock is active!');

       wakeLock.addEventListener('release', () => {
         console.log('Screen wake lock was released.');
       });

       // 在需要的时候释放 Wake Lock
       // setTimeout(() => {
       //   wakeLock.release();
       // }, 5000);

     } catch (err) {
       console.error(`Failed to acquire screen wake lock: ${err.name}, ${err.message}`);
     }
   }

   requestScreenWakeLock();
   ```

* **HTML:** HTML 结构定义了网页的内容，JavaScript 代码通常嵌入在 HTML 中。用户与 HTML 页面的交互（例如点击按钮）可能会触发 JavaScript 代码来请求 Wake Lock。

   **举例:**

   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <title>Wake Lock Example</title>
   </head>
   <body>
     <button id="requestWakeLock">保持屏幕常亮</button>
     <script>
       const button = document.getElementById('requestWakeLock');
       button.addEventListener('click', async () => {
         try {
           await navigator.wakeLock.request('screen');
           console.log('屏幕唤醒锁已请求');
         } catch (err) {
           console.error('请求屏幕唤醒锁失败:', err);
         }
       });
     </script>
   </body>
   </html>
   ```

* **CSS:** CSS 主要负责网页的样式，它本身不直接与 Wake Lock API 交互。但是，CSS 可能会影响用户行为，从而间接地与 Wake Lock API 产生关联。例如，一个长时间播放视频的网页可能会建议用户开启屏幕唤醒锁。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. JavaScript 代码调用 `navigator.wakeLock.request('screen')`。
2. 页面可见且处于激活状态。
3. Permissions Policy 允许使用 "screen-wake-lock"。
4. 用户已授予屏幕唤醒锁权限。

**输出:**

1. `WakeLock::request` 方法校验通过。
2. `WakeLockManager` 成功获取屏幕唤醒锁。
3. 返回一个 resolved 的 `Promise`，其值为一个 `WakeLockSentinel` 对象。
4. 设备屏幕保持唤醒状态，不会进入睡眠模式。

**假设输入:**

1. JavaScript 代码调用 `navigator.wakeLock.request('system')`。
2. Permissions Policy 允许使用 "system-wake-lock"。
3. 用户尚未授予系统唤醒锁权限。

**输出:**

1. `WakeLock::request` 方法调用 `PermissionService` 请求权限。
2. 如果用户拒绝权限，`Promise` 将被 reject，并抛出 "NotAllowedError" DOMException。

**用户或编程常见的使用错误:**

1. **在不安全的上下文中使用:** Wake Lock API 通常需要在安全上下文 (HTTPS) 中使用。在 HTTP 页面中调用可能会失败。
   ```javascript
   // 在 HTTP 页面中调用可能会失败
   navigator.wakeLock.request('screen');
   ```
2. **在 Worker 中请求 'screen' 类型的 Wake Lock:**  规范禁止在 Dedicated Worker 中请求屏幕唤醒锁。
   ```javascript
   // 在 Worker 中
   navigator.wakeLock.request('screen'); // 会抛出错误
   ```
3. **未处理 Promise 的 rejection:** 如果权限被拒绝或发生其他错误，`navigator.wakeLock.request()` 返回的 Promise 会被 reject。如果 JavaScript 代码没有正确处理 rejection，可能会导致未捕获的错误。
   ```javascript
   navigator.wakeLock.request('screen'); // 没有 .catch() 处理错误
   ```
4. **过早或不必要的请求 Wake Lock:**  持续不必要地持有 Wake Lock 会消耗电池电量，影响用户体验。应该在真正需要时才请求，并在不再需要时及时释放。
5. **假设权限始终被授予:**  用户可以随时撤销权限，因此应用程序应该监听 `WakeLockSentinel` 的 `release` 事件，以便在 Wake Lock 被系统或其他原因释放时做出响应。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开网页:** 用户在浏览器中输入网址或点击链接，加载一个包含使用 Wake Lock API 的 JavaScript 代码的网页。
2. **网页加载和 JavaScript 执行:** 浏览器解析 HTML、CSS，并执行网页中的 JavaScript 代码。
3. **JavaScript 调用 `navigator.wakeLock.request()`:**  当满足特定条件（例如，用户点击按钮，开始播放视频），JavaScript 代码会调用 `navigator.wakeLock.request('screen')` 或 `navigator.wakeLock.request('system')`。
4. **浏览器接收请求:** 浏览器接收到 JavaScript 的请求，并将其传递给 Blink 渲染引擎。
5. **Blink 处理请求:** Blink 引擎中的相关代码（即 `wake_lock.cc` 文件中的 `WakeLock::request` 方法）开始处理该请求。
6. **权限检查:** `WakeLock::request` 方法会进行一系列的权限和状态检查，包括 Permissions Policy 和用户授权。
7. **请求权限 (如果需要):** 如果需要用户授权，Blink 会通过 `PermissionService` 显示权限请求提示框。
8. **Wake Lock 获取:** 如果权限允许且状态校验通过，`WakeLockManager` 会被调用来实际获取 Wake Lock。这会涉及到操作系统层面的调用，以阻止设备进入睡眠状态。
9. **返回 `WakeLockSentinel`:** `WakeLock::request` 方法返回一个 resolved 的 Promise，其值为 `WakeLockSentinel` 对象，JavaScript 代码可以使用该对象来控制 Wake Lock 的释放。

**调试线索:**

* **查看浏览器的开发者工具的 Console 面板:**  可以查看 JavaScript 代码中关于 Wake Lock 的日志输出和错误信息。
* **查看浏览器的开发者工具的 Network 面板:**  检查是否有与权限相关的网络请求。
* **使用 `chrome://permissions` 或 `edge://settings/content/siteDetails?site=<your_site>` 查看站点权限:**  确认 Wake Lock 权限是否被授予。
* **在 `wake_lock.cc` 中添加日志输出:**  为了更深入地了解执行流程，可以在关键路径上添加 `DLOG` 或 `DVLOG` 输出，然后在 Chromium 的调试构建中查看日志。
* **断点调试:** 在 `wake_lock.cc` 中的关键方法上设置断点，例如 `WakeLock::request`、`WakeLock::DoRequest`、`WakeLockManager::AcquireWakeLock` 等，以单步执行代码并查看变量值。
* **检查 Permissions Policy:**  确保页面的 Permissions Policy header 或 iframe 的 `allow` 属性允许使用 "screen-wake-lock" 或 "system-wake-lock"。

通过以上分析，可以深入理解 `wake_lock.cc` 文件在 Chromium Blink 引擎中的作用，以及它如何与 Web 技术栈的各个部分协同工作来实现 Wake Lock API 的功能。

### 提示词
```
这是目录为blink/renderer/modules/wake_lock/wake_lock.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/wake_lock/wake_lock.h"

#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/modules/wake_lock/wake_lock_manager.h"
#include "third_party/blink/renderer/modules/wake_lock/wake_lock_type.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

using mojom::blink::PermissionService;

// static
const char WakeLock::kSupplementName[] = "WakeLock";

// static
WakeLock* WakeLock::wakeLock(NavigatorBase& navigator) {
  WakeLock* supplement = Supplement<NavigatorBase>::From<WakeLock>(navigator);
  if (!supplement && navigator.GetExecutionContext()) {
    supplement = MakeGarbageCollected<WakeLock>(navigator);
    ProvideTo(navigator, supplement);
  }
  return supplement;
}

WakeLock::WakeLock(NavigatorBase& navigator)
    : Supplement<NavigatorBase>(navigator),
      ExecutionContextLifecycleObserver(navigator.GetExecutionContext()),
      PageVisibilityObserver(navigator.DomWindow()
                                 ? navigator.DomWindow()->GetFrame()->GetPage()
                                 : nullptr),
      permission_service_(navigator.GetExecutionContext()),
      managers_{
          MakeGarbageCollected<WakeLockManager>(navigator.GetExecutionContext(),
                                                V8WakeLockType::Enum::kScreen),
          MakeGarbageCollected<WakeLockManager>(
              navigator.GetExecutionContext(),
              V8WakeLockType::Enum::kSystem)} {}

ScriptPromise<WakeLockSentinel> WakeLock::request(
    ScriptState* script_state,
    V8WakeLockType type,
    ExceptionState& exception_state) {
  // https://w3c.github.io/screen-wake-lock/#the-request-method

  // 4. If the document's browsing context is null, reject promise with a
  //    "NotAllowedError" DOMException and return promise.
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "The document has no associated browsing context");
    return EmptyPromise();
  }

  auto* context = ExecutionContext::From(script_state);
  DCHECK(context->IsWindow() || context->IsDedicatedWorkerGlobalScope());

  if (type == V8WakeLockType::Enum::kSystem &&
      !RuntimeEnabledFeatures::SystemWakeLockEnabled()) {
    exception_state.ThrowTypeError(
        "The provided value 'system' is not a valid enum value of type "
        "WakeLockType.");
    return EmptyPromise();
  }

  // 2. If document is not allowed to use the policy-controlled feature named
  //    "screen-wake-lock", return a promise rejected with a "NotAllowedError"
  //     DOMException.
  // TODO: Check permissions policy enabling for System Wake Lock
  // [N.B. Per https://github.com/w3c/webappsec-permissions-policy/issues/207
  // there is no official support for workers in the Permissions Policy spec,
  // but we can perform FP checks in workers in Blink]
  if (type == V8WakeLockType::Enum::kScreen &&
      !context->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kScreenWakeLock,
          ReportOptions::kReportOnFailure)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                      "Access to Screen Wake Lock features is "
                                      "disallowed by permissions policy");
    return EmptyPromise();
  }

  if (context->IsDedicatedWorkerGlobalScope()) {
    // N.B. The following steps were removed from the spec when System Wake Lock
    // was spun off into a separate specification.
    // 3. If the current global object is the DedicatedWorkerGlobalScope object:
    // 3.1. If the current global object's owner set is empty, reject promise
    //      with a "NotAllowedError" DOMException and return promise.
    // 3.2. If type is "screen", reject promise with a "NotAllowedError"
    //      DOMException, and return promise.
    if (type == V8WakeLockType::Enum::kScreen) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotAllowedError,
          "Screen locks cannot be requested from workers");
      return EmptyPromise();
    }
  } else if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    // 1. Let document be this's relevant settings object's associated
    //    Document.
    // 5. If document is not fully active, return a promise rejected with with a
    //    "NotAllowedError" DOMException.
    if (!window->document()->IsActive()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                        "The document is not active");
      return EmptyPromise();
    }
    // 6. If the steps to determine the visibility state return hidden, return a
    //    promise rejected with "NotAllowedError" DOMException.
    if (type == V8WakeLockType::Enum::kScreen &&
        !window->GetFrame()->GetPage()->IsPageVisible()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                        "The requesting page is not visible");
      return EmptyPromise();
    }

    // Measure calls without sticky activation as proposed in
    // https://github.com/w3c/screen-wake-lock/pull/351.
    if (type == V8WakeLockType::Enum::kScreen &&
        !window->GetFrame()->HasStickyUserActivation()) {
      UseCounter::Count(
          context,
          WebFeature::kWakeLockAcquireScreenLockWithoutStickyActivation);
    }
  }

  // 7. Let promise be a new promise.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  switch (type.AsEnum()) {
    case V8WakeLockType::Enum::kScreen:
      UseCounter::Count(context, WebFeature::kWakeLockAcquireScreenLock);
      break;
    case V8WakeLockType::Enum::kSystem:
      UseCounter::Count(context, WebFeature::kWakeLockAcquireSystemLock);
      break;
  }

  // 8. Run the following steps in parallel:
  DoRequest(type.AsEnum(), resolver);

  // 9. Return promise.
  return promise;
}

void WakeLock::DoRequest(V8WakeLockType::Enum type,
                         ScriptPromiseResolver<WakeLockSentinel>* resolver) {
  // https://w3c.github.io/screen-wake-lock/#the-request-method
  // 8.1. Let state be the result of requesting permission to use
  //      "screen-wake-lock".
  mojom::blink::PermissionName permission_name;
  switch (type) {
    case V8WakeLockType::Enum::kScreen:
      permission_name = mojom::blink::PermissionName::SCREEN_WAKE_LOCK;
      break;
    case V8WakeLockType::Enum::kSystem:
      permission_name = mojom::blink::PermissionName::SYSTEM_WAKE_LOCK;
      break;
  }

  auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext());
  auto* local_frame = window ? window->GetFrame() : nullptr;
  GetPermissionService()->RequestPermission(
      CreatePermissionDescriptor(permission_name),
      LocalFrame::HasTransientUserActivation(local_frame),
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&WakeLock::DidReceivePermissionResponse,
                        WrapPersistent(this), type)));
}

void WakeLock::DidReceivePermissionResponse(
    V8WakeLockType::Enum type,
    ScriptPromiseResolver<WakeLockSentinel>* resolver,
    mojom::blink::PermissionStatus status) {
  // https://w3c.github.io/screen-wake-lock/#the-request-method
  // 8.2. If state is "denied", then:
  // 8.2.1. Queue a global task on the screen wake lock task source given
  //        document's relevant global object to reject promise with a
  //        "NotAllowedError" DOMException.
  // 8.2.2. Abort these steps.
  // Note: Treat ASK permission (default in headless_shell) as DENIED.
  if (status != mojom::blink::PermissionStatus::GRANTED) {
    resolver->Reject(V8ThrowDOMException::CreateOrDie(
        resolver->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kNotAllowedError,
        "Wake Lock permission request denied"));
    return;
  }
  // 8.3. Queue a global task on the screen wake lock task source given
  //      document's relevant global object to run these steps:
  if (type == V8WakeLockType::Enum::kScreen &&
      !(GetPage() && GetPage()->IsPageVisible())) {
    // 8.3.1. If the steps to determine the visibility state return hidden,
    //        then:
    // 8.3.1.1. Reject promise with a "NotAllowedError" DOMException.
    // 8.3.1.2. Abort these steps.
    resolver->Reject(V8ThrowDOMException::CreateOrDie(
        resolver->GetScriptState()->GetIsolate(),
        DOMExceptionCode::kNotAllowedError,
        "The requesting page is not visible"));
    return;
  }
  // Steps 8.3.2 to 8.3.5 are described in AcquireWakeLock() and related
  // functions.
  WakeLockManager* manager = managers_[static_cast<size_t>(type)];
  DCHECK(manager);
  manager->AcquireWakeLock(resolver);
}

void WakeLock::ContextDestroyed() {
  // https://w3c.github.io/screen-wake-lock/#handling-document-loss-of-full-activity
  // 1. For each lock in document.[[ActiveLocks]]["screen"]:
  // 1.1. Run release a wake lock with document, lock, and "screen".
  // N.B. The following steps were removed from the spec when System Wake Lock
  // was spun off into a separate specification.
  // 2. For each lock in document.[[ActiveLocks]]["system"]:
  // 2.1. Run release a wake lock with document, lock, and "system".
  for (WakeLockManager* manager : managers_) {
    if (manager)
      manager->ClearWakeLocks();
  }
}

void WakeLock::PageVisibilityChanged() {
  // https://w3c.github.io/screen-wake-lock/#handling-document-loss-of-visibility
  if (GetPage() && GetPage()->IsPageVisible())
    return;
  // 1. For each lock in document.[[ActiveLocks]]["screen"]:
  // 1.1. Run release a wake lock with document, lock, and "screen".
  WakeLockManager* manager =
      managers_[static_cast<size_t>(V8WakeLockType::Enum::kScreen)];
  if (manager)
    manager->ClearWakeLocks();
}

PermissionService* WakeLock::GetPermissionService() {
  if (!permission_service_.is_bound()) {
    ConnectToPermissionService(
        GetExecutionContext(),
        permission_service_.BindNewPipeAndPassReceiver(
            GetExecutionContext()->GetTaskRunner(TaskType::kWakeLock)));
  }
  return permission_service_.get();
}

void WakeLock::Trace(Visitor* visitor) const {
  for (const Member<WakeLockManager>& manager : managers_)
    visitor->Trace(manager);
  visitor->Trace(permission_service_);
  Supplement<NavigatorBase>::Trace(visitor);
  PageVisibilityObserver::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
```