Response:
Let's break down the thought process for analyzing this Chromium source code.

**1. Initial Understanding of the Request:**

The request asks for an explanation of the `NotificationManager.cc` file in the Blink rendering engine. The key requirements are:

* Functionality description.
* Relationship to JavaScript, HTML, and CSS.
* Logical reasoning with input/output examples.
* Common usage errors.
* Steps to reach this code (debugging).

**2. High-Level Overview and Purpose:**

The file name `notification_manager.cc` strongly suggests this class is responsible for managing notifications within the Blink rendering engine. The `#include` statements confirm this, referencing notification-related mojom interfaces (`Notification.mojom-blink.h`) and classes (`Notification.h`). It also interacts with permissions (`Permission.mojom-blink.h`). Therefore, the core responsibility is likely to handle the creation, display, closing, and permission management of web notifications.

**3. Core Functionality Identification (Iterating through the code):**

I'll go through the methods in the class and deduce their purpose:

* **`From(ExecutionContext* context)`:** This is a static factory method, likely used to retrieve the `NotificationManager` instance associated with a given execution context (like a document or worker). The supplement pattern confirms this.
* **`GetPermissionStatus()` and `GetPermissionStatusAsync()`:** These methods clearly deal with retrieving the current permission status for notifications. The asynchronous version suggests non-blocking operations. The prerendering check is interesting – it indicates that permission checks might be delayed or return a default value during prerendering.
* **`RequestPermission(ScriptState* script_state, ...)`:** This function is responsible for requesting notification permissions from the user. The interaction with `permission_service_` and the promise-based return strongly suggest its use in JavaScript's `Notification.requestPermission()` API.
* **`PermissionStatusToEnum()`:**  A helper function to convert the internal `mojom::blink::PermissionStatus` enum to the JavaScript-facing `V8NotificationPermission` enum.
* **`OnPermissionRequestComplete()`:** This is a callback function, likely invoked after the browser process responds to a permission request. It resolves the promise returned by `RequestPermission`.
* **`DisplayNonPersistentNotification()`:**  This handles showing notifications that disappear automatically (like transient notifications). The `NonPersistentNotificationListener` suggests handling events like clicks.
* **`CloseNonPersistentNotification()`:**  Used to programmatically close non-persistent notifications.
* **`DisplayPersistentNotification()`:** Deals with showing notifications that persist until explicitly closed by the user. The size limit check is a noteworthy detail for preventing abuse. The promise resolution/rejection indicates feedback to the initiating script.
* **`DidDisplayPersistentNotification()`:**  Callback for `DisplayPersistentNotification`, handling success or failure.
* **`ClosePersistentNotification()`:**  Closes persistent notifications.
* **`GetNotifications()`:** Retrieves a list of currently active persistent notifications. The `filter_tag` suggests filtering capabilities.
* **`DidGetNotifications()`:**  Callback for `GetNotifications`, constructing `Notification` objects from the returned data.
* **`GetNotificationService()`:**  A lazy initialization method to get the `NotificationService` interface, which communicates with the browser process. The disconnect handler indicates how to handle connection loss.
* **`OnNotificationServiceConnectionError()` and `OnPermissionServiceConnectionError()`:**  Error handling for Mojo connection failures.
* **`Trace()`:** Used for debugging and memory management, allowing the garbage collector to track references.

**4. Connecting to JavaScript, HTML, and CSS:**

This requires understanding how web notifications work at a high level.

* **JavaScript:** The `RequestPermission` function directly maps to the `Notification.requestPermission()` API. The `DisplayPersistentNotification` function relates to the `ServiceWorkerRegistration.showNotification()` method. The `GetNotifications` function maps to the `ServiceWorkerRegistration.getNotifications()` method. The `close()` method on the JavaScript `Notification` object likely triggers calls to `CloseNonPersistentNotification` or `ClosePersistentNotification`. The `Notification` constructor in `DidGetNotifications` clearly links back to the JavaScript `Notification` object.
* **HTML:**  While this file doesn't directly manipulate HTML, the *result* of these operations (the displayed notification) is visually presented on the page. The content of the notification (title, body, icon) is specified in the JavaScript and indirectly affects the HTML structure rendered by the browser.
* **CSS:** Similarly, this code doesn't directly deal with CSS. However, the *styling* of the displayed notification is influenced by the browser's default styles and potentially customized by the operating system or user preferences.

**5. Logical Reasoning (Input/Output Examples):**

For each function, I consider what it takes as input and what it produces as output. For example:

* **`GetPermissionStatus()`:** Input: None (implicitly the current browsing context). Output: A `mojom::blink::PermissionStatus` enum (GRANTED, DENIED, ASK).
* **`RequestPermission()`:** Input: `ScriptState`. Output: A `ScriptPromise` that resolves with a `V8NotificationPermission` enum.
* **`DisplayPersistentNotification()`:** Input: Service worker registration ID, notification data, notification resources, and a promise resolver. Output: (Asynchronous) Resolves or rejects the promise based on success/failure.

**6. Common Usage Errors:**

I think about the common mistakes developers might make when working with notifications:

* **Not requesting permission:**  Trying to show a notification before getting permission will fail.
* **Incorrect permission handling:**  Not checking the permission status and providing appropriate UI.
* **Exceeding data limits:**  Storing too much data in the notification payload.
* **Misunderstanding persistent vs. non-persistent:** Using the wrong API for the desired behavior.
* **Service worker scope issues:**  Persistent notifications require a service worker, and scope mismatches can lead to errors.

**7. User Operations and Debugging:**

I trace the user's actions that would lead to this code being executed:

* Opening a web page that uses notifications.
* The website calling `Notification.requestPermission()`.
* The user granting or denying permission.
* The website calling `ServiceWorkerRegistration.showNotification()` (for persistent notifications).
* The website calling the `Notification` constructor directly (less common, but happens when getting existing notifications).
* The website calling the `close()` method on a `Notification` object.

For debugging, I consider how a developer might investigate issues:

* Setting breakpoints in `NotificationManager.cc`.
* Examining the values of variables like `permission_status`, `notification_data`, etc.
* Observing the flow of execution through the different methods.
* Checking the browser console for errors or warnings related to notifications.

**8. Refinement and Organization:**

Finally, I organize the information logically, using headings and bullet points to make it clear and easy to understand. I ensure that the examples are concrete and illustrative. I also double-check for accuracy and completeness based on my understanding of the code. For instance, initially, I might overlook the details about `Supplement` or the specific Mojo interface names, but upon closer inspection and reviewing the `#include`s, I can refine the explanation. I also make sure to tie specific functions to the corresponding JavaScript APIs.
这个文件 `notification_manager.cc` 是 Chromium Blink 引擎中负责管理 Web Notifications API 的核心组件。它在渲染进程中运行，作为 JavaScript 代码和浏览器底层通知系统之间的桥梁。

以下是该文件的主要功能：

**1. 管理通知权限 (Permission Management):**

* **获取权限状态 (`GetPermissionStatus`, `GetPermissionStatusAsync`):**  查询当前页面的通知权限状态（`granted`, `denied`, `default/prompt`）。
    * **与 JavaScript 的关系:**  对应 JavaScript 中 `Notification.permission` 属性的值。
    * **举例说明:** 当 JavaScript 代码访问 `Notification.permission` 时，最终会调用到这里的 `GetPermissionStatus` 或 `GetPermissionStatusAsync` 方法。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:**  用户尚未对当前网站的通知请求做出任何操作。
        * **输出:** `mojom::blink::PermissionStatus::ASK` (对应 JavaScript 的 'default')
        * **假设输入:** 用户已经允许当前网站发送通知。
        * **输出:** `mojom::blink::PermissionStatus::GRANTED` (对应 JavaScript 的 'granted')
* **请求权限 (`RequestPermission`):**  处理 JavaScript 中 `Notification.requestPermission()` 的调用，向用户请求发送通知的权限。
    * **与 JavaScript 的关系:** 直接响应 `Notification.requestPermission()` 方法。
    * **举例说明:** JavaScript 代码 `Notification.requestPermission().then(function(result) { console.log(result); });` 会触发 `NotificationManager::RequestPermission`。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** JavaScript 调用 `Notification.requestPermission()`，用户点击了 "允许"。
        * **输出:** `RequestPermission` 方法会通过 `permission_service_` 与浏览器进程通信，浏览器进程记录用户的选择，最终 `OnPermissionRequestComplete` 会被调用，并通过 Promise 将 'granted' 传递回 JavaScript。

**2. 显示通知 (Display Notifications):**

* **显示非持久通知 (`DisplayNonPersistentNotification`):** 处理通过 JavaScript 的 `new Notification()` 创建的即时通知（通常在一段时间后自动消失）。
    * **与 JavaScript 的关系:**  当 JavaScript 创建 `new Notification('title', options)` 时，会调用到这里。
    * **举例说明:** `new Notification('提醒', { body: '您有新的消息' });` 会触发此方法。
* **关闭非持久通知 (`CloseNonPersistentNotification`):**  允许程序化关闭非持久通知。
    * **与 JavaScript 的关系:**  可能对应一些浏览器内部的清理操作，JavaScript API 中没有直接对应的方法来关闭所有非持久通知。
* **显示持久通知 (`DisplayPersistentNotification`):** 处理通过 Service Worker 的 `ServiceWorkerRegistration.showNotification()` 创建的持久通知（需要用户手动关闭）。
    * **与 JavaScript 的关系:**  直接响应 `ServiceWorkerRegistration.showNotification()` 方法。
    * **举例说明:**  在 Service Worker 中调用 `registration.showNotification('新邮件', { body: '您收到一封新邮件' });` 会触发此方法。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** Service Worker 调用 `showNotification`，提供标题和内容。
        * **输出:** `DisplayPersistentNotification` 将通知数据发送给浏览器进程进行显示，并通过 Promise 返回操作结果。

**3. 关闭持久通知 (`ClosePersistentNotification`):**

* 允许程序化关闭持久通知。
    * **与 JavaScript 的关系:**  对应 JavaScript 中 `Notification` 对象的 `close()` 方法（通过 Service Worker 获取的 Notification 对象）。
    * **举例说明:**  在 Service Worker 中获取到一个 `Notification` 对象 `notification`，调用 `notification.close()` 会触发此方法。

**4. 获取现有通知 (`GetNotifications`):**

* 允许 Service Worker 查询当前已显示的持久通知。
    * **与 JavaScript 的关系:**  对应 Service Worker 的 `ServiceWorkerRegistration.getNotifications()` 方法。
    * **举例说明:**  `navigator.serviceWorker.ready.then(registration => registration.getNotifications().then(notifications => console.log(notifications)));` 会触发此方法。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** Service Worker 调用 `getNotifications()`。
        * **输出:** `GetNotifications` 会与浏览器进程通信，获取当前显示的持久通知列表，然后通过 `DidGetNotifications` 将 `Notification` 对象数组传递回 JavaScript。

**5. 与浏览器进程通信:**

* `NotificationManager` 通过 `notification_service_` 和 `permission_service_` 这两个 Mojo 接口与浏览器进程中的通知服务和权限服务进行通信。这使得渲染进程可以请求权限、显示通知等操作。

**与 HTML 和 CSS 的关系:**

* **HTML:**  此文件本身不直接操作 HTML。但是，JavaScript 代码调用通知 API 后，浏览器会根据通知的内容（title, body, icon 等）在操作系统层面生成一个通知，这个通知最终会以某种形式展示给用户，可能会覆盖部分 HTML 内容或者在系统通知中心显示。
* **CSS:**  此文件不直接涉及 CSS。通知的样式通常由操作系统或浏览器默认提供，可以通过一些通知选项（例如 `icon`）进行间接影响，但无法通过 CSS 直接控制 `notification_manager.cc` 的行为。

**逻辑推理的假设输入与输出 (更详细的例子):**

* **场景：用户首次访问网站并允许通知**
    * **用户操作:** 访问网站 -> 网站 JavaScript 调用 `Notification.requestPermission()` -> 浏览器弹出权限请求弹窗 -> 用户点击 "允许"。
    * **`NotificationManager` 中的流程:**
        * `RequestPermission` 被调用。
        * `permission_service_->RequestPermission` 发送权限请求到浏览器进程。
        * 浏览器进程记录用户选择。
        * `OnPermissionRequestComplete` 被调用，参数 `status` 为 `mojom::blink::PermissionStatus::GRANTED`。
        * Promise resolve 返回 JavaScript 'granted'。
* **场景：Service Worker 显示一个持久通知**
    * **用户操作:** 网站 Service Worker 运行并调用 `registration.showNotification('新消息', { body: '您有新的更新' });`
    * **`NotificationManager` 中的流程:**
        * `DisplayPersistentNotification` 被调用，接收 Service Worker 的注册 ID、通知数据等。
        * 检查通知数据大小是否超过限制。
        * `GetNotificationService()->DisplayPersistentNotification` 将通知数据发送到浏览器进程。
        * 浏览器进程显示通知。
        * `DidDisplayPersistentNotification` 被调用，如果显示成功，参数 `error` 为 `mojom::blink::PersistentNotificationError::NONE`。
        * Promise resolve 返回 JavaScript `undefined`。

**用户或编程常见的使用错误举例说明:**

1. **未请求权限就尝试显示通知:**
   * **错误代码 (JavaScript):** `new Notification('Hello');` (在用户未授权的情况下)
   * **结果:** 通知可能无法显示，或者浏览器会阻止显示。`Notification.permission` 的值可能是 'default' 或 'denied'。
   * **`notification_manager.cc` 的表现:**  当调用到显示通知的方法时，会检查权限状态，如果权限不足，可能会直接返回或者向浏览器进程发送请求但被拒绝。

2. **在非安全上下文 (non-secure context) 下使用通知 API:**
   * **错误:**  在 HTTP 页面上调用 `Notification.requestPermission()` 或创建 `new Notification()`。
   * **结果:** 现代浏览器通常只允许在 HTTPS 或 localhost 上使用通知 API。
   * **`notification_manager.cc` 的表现:**  可能会在更早的阶段（例如在绑定 JavaScript API 到 Blink 内部实现时）进行检查并阻止调用。

3. **持久通知的数据过大:**
   * **错误代码 (JavaScript - Service Worker):** `registration.showNotification('Title', { data: { veryLongString: '...' } });` (其中 `veryLongString` 很大)
   * **结果:**  `DisplayPersistentNotification` 方法中会检查 `author_data_size` 是否超过 `mojom::blink::NotificationData::kMaximumDeveloperDataSize`，如果超过，Promise 会被 reject。
   * **`notification_manager.cc` 的表现:** `DidDisplayPersistentNotification` 不会被调用，`resolver->Reject()` 会被执行。

**用户操作是如何一步步到达这里的，作为调试线索:**

假设用户在一个网站上看到了一个 "接收通知" 的按钮，点击后弹出了浏览器的通知权限请求。

1. **用户操作:** 用户点击了网站上的 "接收通知" 按钮。
2. **JavaScript 代码执行:** 该按钮的点击事件监听器中，会调用 `Notification.requestPermission()`。
3. **Blink 绑定层:**  JavaScript 的 `Notification.requestPermission()` 调用被转换为对 Blink 内部 C++ 代码的调用。
4. **`NotificationManager::RequestPermission`:**  `notification_manager.cc` 中的 `RequestPermission` 方法被执行。
5. **Mojo 通信:** `RequestPermission` 方法通过 `permission_service_` 发送一个权限请求到浏览器进程。
6. **浏览器进程处理:** 浏览器进程接收到请求，显示权限请求弹窗给用户。
7. **用户操作:** 用户在弹窗中点击 "允许"。
8. **浏览器进程响应:** 浏览器进程将用户的选择通过 Mojo 返回给渲染进程。
9. **`NotificationManager::OnPermissionRequestComplete`:** `notification_manager.cc` 中的 `OnPermissionRequestComplete` 方法被调用，接收到授权结果。
10. **Promise 解析:** `OnPermissionRequestComplete` 解析 `RequestPermission` 返回的 Promise，将结果 ('granted') 传递回 JavaScript。

**调试线索:**

* **在 `NotificationManager::RequestPermission` 方法中设置断点:**  可以观察权限请求的触发。
* **在 `NotificationManager::OnPermissionRequestComplete` 方法中设置断点:**  可以观察权限请求的结果。
* **查看 `permission_service_` 的状态和调用:**  可以了解与浏览器进程的通信情况。
* **检查 JavaScript 控制台的错误信息:**  如果权限被拒绝或发生其他错误，浏览器可能会输出相关信息。
* **使用 Chromium 的 `chrome://webrtc-internals` 或 `chrome://tracing` 工具:** 可以更深入地了解 Mojo 消息的传递和系统调用。

总而言之，`notification_manager.cc` 是 Blink 渲染引擎中管理 Web Notifications 的关键模块，负责处理权限请求、显示和关闭通知，并作为 JavaScript 通知 API 和浏览器底层通知系统之间的桥梁。 理解它的功能和交互方式对于调试和理解 Web Notifications 的工作原理至关重要。

### 提示词
```
这是目录为blink/renderer/modules/notifications/notification_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/notifications/notification_manager.h"

#include <utility>

#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/mojom/notifications/notification.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions/permission.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions/permission_status.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_notification_permission.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/notifications/notification.h"
#include "third_party/blink/renderer/modules/notifications/notification_metrics.h"
#include "third_party/blink/renderer/modules/permissions/permission_utils.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

// static
NotificationManager* NotificationManager::From(ExecutionContext* context) {
  DCHECK(context);
  DCHECK(context->IsContextThread());

  NotificationManager* manager =
      Supplement<ExecutionContext>::From<NotificationManager>(context);
  if (!manager) {
    manager = MakeGarbageCollected<NotificationManager>(*context);
    Supplement<ExecutionContext>::ProvideTo(*context, manager);
  }

  return manager;
}

// static
const char NotificationManager::kSupplementName[] = "NotificationManager";

NotificationManager::NotificationManager(ExecutionContext& context)
    : Supplement<ExecutionContext>(context),
      notification_service_(&context),
      permission_service_(&context) {}

NotificationManager::~NotificationManager() = default;

mojom::blink::PermissionStatus NotificationManager::GetPermissionStatus() {
  if (GetSupplementable()->IsContextDestroyed())
    return mojom::blink::PermissionStatus::DENIED;

  // Tentatively have an early return to avoid calling GetNotificationService()
  // during prerendering. The return value is the same as
  // `Notification::permission`'s.
  // TODO(1280155): defer the construction of notification to ensure this method
  // is not called during prerendering instead.
  if (auto* window = DynamicTo<LocalDOMWindow>(GetSupplementable())) {
    if (Document* document = window->document(); document->IsPrerendering()) {
      return mojom::blink::PermissionStatus::ASK;
    }
  }

  SCOPED_UMA_HISTOGRAM_TIMER(
      "Blink.NotificationManager.GetPermissionStatusTime");
  mojom::blink::PermissionStatus permission_status;
  if (!GetNotificationService()->GetPermissionStatus(&permission_status)) {
    // The browser-side Mojo connection was closed, disabling notifications.
    // Hitting this code path means the mojo call is no longer bound to the
    // browser process.
    return mojom::blink::PermissionStatus::DENIED;
  }

  return permission_status;
}

void NotificationManager::GetPermissionStatusAsync(
    base::OnceCallback<void(mojom::blink::PermissionStatus)> callback) {
  if (GetSupplementable()->IsContextDestroyed()) {
    std::move(callback).Run(mojom::blink::PermissionStatus::DENIED);
    return;
  }

  // Tentatively have an early return to avoid calling GetNotificationService()
  // during prerendering. The return value is the same as
  // `Notification::permission`'s.
  // TODO(1280155): defer the construction of notification to ensure this method
  // is not called during prerendering instead.
  if (auto* window = DynamicTo<LocalDOMWindow>(GetSupplementable())) {
    if (Document* document = window->document(); document->IsPrerendering()) {
      std::move(callback).Run(mojom::blink::PermissionStatus::ASK);
      return;
    }
  }

  GetNotificationService()->GetPermissionStatus(std::move(callback));
}

ScriptPromise<V8NotificationPermission> NotificationManager::RequestPermission(
    ScriptState* script_state,
    V8NotificationPermissionCallback* deprecated_callback) {
  ExecutionContext* context = ExecutionContext::From(script_state);

  if (!permission_service_.is_bound()) {
    // See https://bit.ly/2S0zRAS for task types
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        context->GetTaskRunner(TaskType::kMiscPlatformAPI);
    ConnectToPermissionService(
        context,
        permission_service_.BindNewPipeAndPassReceiver(std::move(task_runner)));
    permission_service_.set_disconnect_handler(
        WTF::BindOnce(&NotificationManager::OnPermissionServiceConnectionError,
                      WrapWeakPersistent(this)));
  }

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8NotificationPermission>>(
          script_state);
  auto promise = resolver->Promise();

  LocalDOMWindow* win = To<LocalDOMWindow>(context);
  permission_service_->RequestPermission(
      CreatePermissionDescriptor(mojom::blink::PermissionName::NOTIFICATIONS),
      LocalFrame::HasTransientUserActivation(win ? win->GetFrame() : nullptr),
      WTF::BindOnce(&NotificationManager::OnPermissionRequestComplete,
                    WrapPersistent(this), WrapPersistent(resolver),
                    WrapPersistent(deprecated_callback)));

  return promise;
}

V8NotificationPermission PermissionStatusToEnum(
    mojom::blink::PermissionStatus permission) {
  switch (permission) {
    case mojom::blink::PermissionStatus::GRANTED:
      return V8NotificationPermission(V8NotificationPermission::Enum::kGranted);
    case mojom::blink::PermissionStatus::DENIED:
      return V8NotificationPermission(V8NotificationPermission::Enum::kDenied);
    case mojom::blink::PermissionStatus::ASK:
      return V8NotificationPermission(V8NotificationPermission::Enum::kDefault);
  }
}

void NotificationManager::OnPermissionRequestComplete(
    ScriptPromiseResolver<V8NotificationPermission>* resolver,
    V8NotificationPermissionCallback* deprecated_callback,
    mojom::blink::PermissionStatus status) {
  V8NotificationPermission permission = PermissionStatusToEnum(status);
  if (deprecated_callback) {
    deprecated_callback->InvokeAndReportException(nullptr, permission);
  }

  resolver->Resolve(permission);
}

void NotificationManager::OnNotificationServiceConnectionError() {
  notification_service_.reset();
}

void NotificationManager::OnPermissionServiceConnectionError() {
  permission_service_.reset();
}

void NotificationManager::DisplayNonPersistentNotification(
    const String& token,
    mojom::blink::NotificationDataPtr notification_data,
    mojom::blink::NotificationResourcesPtr notification_resources,
    mojo::PendingRemote<mojom::blink::NonPersistentNotificationListener>
        event_listener) {
  DCHECK(!token.empty());
  DCHECK(notification_resources);
  GetNotificationService()->DisplayNonPersistentNotification(
      token, std::move(notification_data), std::move(notification_resources),
      std::move(event_listener));
}

void NotificationManager::CloseNonPersistentNotification(const String& token) {
  DCHECK(!token.empty());
  GetNotificationService()->CloseNonPersistentNotification(token);
}

void NotificationManager::DisplayPersistentNotification(
    int64_t service_worker_registration_id,
    mojom::blink::NotificationDataPtr notification_data,
    mojom::blink::NotificationResourcesPtr notification_resources,
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  DCHECK(notification_data);
  DCHECK(notification_resources);
  DCHECK_EQ(notification_data->actions.has_value()
                ? notification_data->actions->size()
                : 0,
            notification_resources->action_icons.has_value()
                ? notification_resources->action_icons->size()
                : 0);

  // Verify that the author-provided payload size does not exceed our limit.
  // This is an implementation-defined limit to prevent abuse of notification
  // data as a storage mechanism. A UMA histogram records the requested sizes,
  // which enables us to track how much data authors are attempting to store.
  //
  // If the size exceeds this limit, reject the showNotification() promise. This
  // is outside of the boundaries set by the specification, but it gives authors
  // an indication that something has gone wrong.
  size_t author_data_size =
      notification_data->data.has_value() ? notification_data->data->size() : 0;

  if (author_data_size >
      mojom::blink::NotificationData::kMaximumDeveloperDataSize) {
    RecordPersistentNotificationDisplayResult(
        PersistentNotificationDisplayResult::kTooMuchData);
    resolver->Reject();
    return;
  }

  GetNotificationService()->DisplayPersistentNotification(
      service_worker_registration_id, std::move(notification_data),
      std::move(notification_resources),
      WTF::BindOnce(&NotificationManager::DidDisplayPersistentNotification,
                    WrapPersistent(this), WrapPersistent(resolver)));
}

void NotificationManager::DidDisplayPersistentNotification(
    ScriptPromiseResolver<IDLUndefined>* resolver,
    mojom::blink::PersistentNotificationError error) {
  switch (error) {
    case mojom::blink::PersistentNotificationError::NONE:
      RecordPersistentNotificationDisplayResult(
          PersistentNotificationDisplayResult::kOk);
      resolver->Resolve();
      return;
    case mojom::blink::PersistentNotificationError::INTERNAL_ERROR:
      RecordPersistentNotificationDisplayResult(
          PersistentNotificationDisplayResult::kInternalError);
      resolver->Reject();
      return;
    case mojom::blink::PersistentNotificationError::PERMISSION_DENIED:
      RecordPersistentNotificationDisplayResult(
          PersistentNotificationDisplayResult::kPermissionDenied);
      // TODO(https://crbug.com/832944): Throw a TypeError if permission denied.
      resolver->Reject();
      return;
  }
  NOTREACHED();
}

void NotificationManager::ClosePersistentNotification(
    const WebString& notification_id) {
  GetNotificationService()->ClosePersistentNotification(notification_id);
}

void NotificationManager::GetNotifications(
    int64_t service_worker_registration_id,
    const WebString& filter_tag,
    bool include_triggered,
    ScriptPromiseResolver<IDLSequence<Notification>>* resolver) {
  GetNotificationService()->GetNotifications(
      service_worker_registration_id, filter_tag, include_triggered,
      WTF::BindOnce(&NotificationManager::DidGetNotifications,
                    WrapPersistent(this), WrapPersistent(resolver)));
}

void NotificationManager::DidGetNotifications(
    ScriptPromiseResolver<IDLSequence<Notification>>* resolver,
    const Vector<String>& notification_ids,
    Vector<mojom::blink::NotificationDataPtr> notification_datas) {
  DCHECK_EQ(notification_ids.size(), notification_datas.size());
  ExecutionContext* context = resolver->GetExecutionContext();
  if (!context)
    return;

  HeapVector<Member<Notification>> notifications;
  notifications.ReserveInitialCapacity(notification_ids.size());

  for (wtf_size_t i = 0; i < notification_ids.size(); ++i) {
    notifications.push_back(Notification::Create(
        context, notification_ids[i], std::move(notification_datas[i]),
        true /* showing */));
  }

  resolver->Resolve(notifications);
}

mojom::blink::NotificationService*
NotificationManager::GetNotificationService() {
  if (!notification_service_.is_bound()) {
    // See https://bit.ly/2S0zRAS for task types
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        GetSupplementable()->GetTaskRunner(TaskType::kMiscPlatformAPI);
    GetSupplementable()->GetBrowserInterfaceBroker().GetInterface(
        notification_service_.BindNewPipeAndPassReceiver(task_runner));

    notification_service_.set_disconnect_handler(WTF::BindOnce(
        &NotificationManager::OnNotificationServiceConnectionError,
        WrapWeakPersistent(this)));
  }

  return notification_service_.get();
}

void NotificationManager::Trace(Visitor* visitor) const {
  visitor->Trace(notification_service_);
  visitor->Trace(permission_service_);
  Supplement<ExecutionContext>::Trace(visitor);
}

}  // namespace blink
```