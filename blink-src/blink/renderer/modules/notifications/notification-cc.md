Response:
My thought process for analyzing the `notification.cc` file went something like this:

1. **Understand the Goal:** The request asks for a breakdown of the file's functionality, its interactions with web technologies (JavaScript, HTML, CSS), logical reasoning examples, common usage errors, and a debugging path to reach this code.

2. **Initial Scan for Keywords and Structure:** I quickly scanned the code for obvious keywords and structural elements. I saw:
    * `Notification`:  This is the central class, so its methods will be key.
    * `Create`: Multiple `Create` methods suggest different ways to instantiate the `Notification` object.
    * Event Handlers (`OnShow`, `OnClick`, `OnClose`, `DispatchErrorEvent`):  This indicates the class deals with user interactions and potential errors.
    * `NotificationOptions`, `NotificationAction`:  These hint at data structures used to configure notifications.
    * `NotificationManager`: This suggests an external component responsible for actually displaying notifications.
    * `ServiceWorkerRegistration`: This links notifications to service workers.
    * `ScriptPromise`, `ScriptValue`:  These are related to JavaScript interaction.
    * `mojom::blink::...`:  This indicates the use of Mojo interfaces for communication with other Blink components or processes.

3. **Identify Core Functionality (Based on Class Methods):** I started going through the main methods of the `Notification` class:

    * **Constructors (`Create` methods):**
        * One for non-persistent notifications created via the `Notification` constructor in a regular web page context. It enforces restrictions like no actions or show triggers.
        * One for persistent notifications created by the system (likely through a service worker).
    * **`SchedulePrepareShow` and `PrepareShow`:** This suggests an asynchronous process to prepare the notification for display, including permission checks and resource loading.
    * **`DidLoadResources`:**  This is called after resources are loaded and likely handles the actual display of the notification using `NotificationManager`.
    * **`close`:**  Handles closing the notification, distinguishing between user-initiated and programmatically initiated closes, and persistent vs. non-persistent notifications.
    * **Event Handlers (`OnShow`, `OnClick`, `OnClose`):** These methods are invoked by the underlying system when corresponding events occur on the displayed notification. They dispatch standard DOM events (`show`, `click`, `close`) that JavaScript can listen for.
    * **`DispatchErrorEvent`:** Handles errors during the notification creation or display process.
    * **Property Getters (`title`, `body`, `icon`, etc.):** These methods expose the notification's data to JavaScript.
    * **`actions`:**  Handles the conversion of internal action data into a JavaScript-accessible array of `NotificationAction` objects.
    * **Static Methods (`permission`, `requestPermission`, `maxActions`):** These provide access to notification permissions and limits.

4. **Map to Web Technologies (JavaScript, HTML, CSS):**  As I identified the core functionality, I thought about how it relates to web technologies:

    * **JavaScript:** The `Notification` class is directly exposed to JavaScript. The `Create` methods correspond to the `new Notification()` constructor and the `showNotification()` method of `ServiceWorkerRegistration`. The event handlers correspond to the `onshow`, `onclick`, and `onclose` event listeners that can be attached to `Notification` objects. The property getters allow JavaScript to access notification data. The `requestPermission` method is a key API for getting user consent.
    * **HTML:**  The notification's content (title, body, icon, etc.) is ultimately rendered visually. While this C++ code doesn't directly manipulate HTML, the data it manages *becomes* the content displayed in the browser's notification UI, which is a form of HTML/CSS rendering.
    * **CSS:**  The appearance of the notification is controlled by the browser's internal styling. While this C++ code doesn't manage CSS directly, the properties of the notification (icon, badge, etc.) influence how the browser styles the notification.

5. **Construct Logical Reasoning Examples (Input/Output):**  I considered scenarios where different inputs to the `Notification::Create` method or different user actions would lead to specific outcomes. This helps illustrate the conditional logic within the code.

6. **Identify Common Usage Errors:**  I looked for error conditions handled by the code (e.g., calling the constructor in a service worker, providing actions for a non-persistent notification, insecure context). These directly translate to common mistakes developers might make.

7. **Trace User Actions to the Code (Debugging Clues):**  I thought about the steps a user or developer would take to trigger the execution of this code. This provides a debugging path. Starting with a webpage loading, a script running, calling `new Notification()`, or a service worker showing a notification seemed like the most common entry points.

8. **Structure the Answer:** Finally, I organized my findings into the requested categories: functionality, relationships to web technologies, logical reasoning, usage errors, and debugging clues. I used clear and concise language, providing specific examples where possible. I also made sure to differentiate between persistent and non-persistent notifications, as this is a key distinction in the code. I paid attention to the keywords and specific error messages present in the code to provide accurate and relevant information.
这个 `notification.cc` 文件是 Chromium Blink 渲染引擎中负责处理 **非持久性通知 (Non-Persistent Notifications)** 的核心逻辑。它实现了 JavaScript `Notification` API 的一部分功能。

以下是该文件的功能分解：

**主要功能:**

1. **创建 `Notification` 对象:**
   - 提供了 `Notification::Create` 静态方法，用于在 JavaScript 中通过 `new Notification()` 构造函数创建 `Notification` 对象。
   - 区分了安全上下文和非安全上下文，以及是否在 Service Worker 上下文中调用。
   - 验证了 `NotificationOptions` 中的属性，例如非持久性通知不支持 actions 和 showTrigger。
   - 创建 `mojom::blink::NotificationDataPtr` 对象，用于存储通知的数据。
   - 启动通知的准备显示流程 (`SchedulePrepareShow`)。

2. **处理通知的生命周期:**
   - **准备显示 (`PrepareShow`)**: 异步检查安全上下文和通知权限，如果允许则开始加载通知所需的资源（例如图片）。
   - **加载资源 (`DidLoadResources`)**: 当资源加载完成后，通过 `NotificationManager` 向浏览器进程发送请求以显示通知。
   - **显示 (`State::kShowing`)**:  当通知成功显示后，状态会更新为 `kShowing`。
   - **关闭 (`close`)**:  处理 JavaScript 中调用 `notification.close()` 方法的情况，并区分用户手动关闭和程序化关闭。对于非持久性通知，会向浏览器进程发送关闭请求。
   - **事件处理 (`OnShow`, `OnClick`, `OnClose`, `DispatchErrorEvent`)**:  接收来自浏览器进程的通知事件，并在 JavaScript 中触发相应的事件 (show, click, close, error)。

3. **管理通知的属性:**
   - 提供了访问 `Notification` 对象各种属性的 getter 方法，例如 `title()`, `body()`, `icon()`, `tag()`, `actions()` 等，这些属性对应着 JavaScript `Notification` 对象的同名属性。

4. **处理通知权限:**
   - 提供了静态方法 `Notification::permission()` 获取当前通知权限状态。
   - 提供了静态方法 `Notification::requestPermission()` 处理 JavaScript 中调用 `Notification.requestPermission()` 请求通知权限。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件实现了 JavaScript `Notification` API 的底层逻辑，使得 JavaScript 代码能够创建和操作通知。

* **JavaScript:**
    - **创建通知:** JavaScript 代码 `const notification = new Notification('Hello', { body: 'World' });` 会最终调用到 `Notification::Create` 方法。
    - **事件监听:** JavaScript 代码 `notification.onshow = () => { console.log('Notification shown'); };` 当通知显示时，会触发 `Notification::OnShow`，并最终调用 JavaScript 中注册的回调函数。
    - **关闭通知:** JavaScript 代码 `notification.close();` 会调用到 `Notification::close` 方法。
    - **访问属性:** JavaScript 代码 `console.log(notification.title);` 会调用到 `Notification::title()` 方法获取通知标题。
    - **请求权限:** JavaScript 代码 `Notification.requestPermission().then(permission => { console.log(permission); });` 会调用到 `Notification::requestPermission` 方法。

* **HTML:**
    - 该文件本身不直接操作 HTML。但是，JavaScript 中创建的通知的内容（例如标题、正文）会最终渲染到浏览器的通知 UI 中，而通知 UI 本身是浏览器使用 HTML 和 CSS 构建的。

* **CSS:**
    - 该文件本身不直接操作 CSS。但是，浏览器会使用内置的 CSS 样式来呈现通知。开发者可以通过 `icon`, `badge` 等属性来影响通知的外观，但不能直接通过 CSS 控制通知样式。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **JavaScript 代码:**
   ```javascript
   const notification = new Notification('Important Update', {
       body: 'A new version is available.',
       icon: '/images/update.png'
   });
   ```
2. **用户操作:** 用户允许显示通知。

**逻辑推理过程:**

1. JavaScript 调用 `new Notification()`，Blink 引擎调用 `Notification::Create`。
2. `Notification::Create` 创建 `Notification` 对象和 `NotificationData` 对象，包含标题 "Important Update"、正文 "A new version is available." 和图标路径 "/images/update.png"。
3. `SchedulePrepareShow` 被调用，启动定时器异步执行 `PrepareShow`。
4. `PrepareShow` 检查安全上下文和通知权限。假设权限已授予。
5. `PrepareShow` 创建 `NotificationResourcesLoader` 开始加载 "/images/update.png"。
6. `DidLoadResources` 在资源加载完成后被调用。
7. `DidLoadResources` 调用 `NotificationManager::DisplayNonPersistentNotification`，将通知数据发送到浏览器进程。
8. 浏览器进程接收到请求，显示通知。
9. 浏览器进程通知 Blink 渲染进程通知已显示，调用 `Notification::OnShow`。
10. `Notification::OnShow` 触发 JavaScript 的 `show` 事件。

**假设输出:**

- 浏览器显示一个带有标题 "Important Update"，正文 "A new version is available."，以及指定图标的非持久性通知。
- JavaScript 的 `notification.onshow` 回调函数被执行。

**用户或编程常见的使用错误及举例说明:**

1. **在 Service Worker 上下文中调用 `new Notification()`:**
   - **错误代码:** 在 Service Worker 的全局作用域中执行 `new Notification('Test');`
   - **结果:**  `Notification::Create` 中会抛出 `TypeError: Illegal constructor.` 异常。
   - **说明:** 非持久性通知应该在页面上下文中创建，持久性通知应该通过 `ServiceWorkerRegistration.showNotification()` 创建。

2. **为非持久性通知设置 `actions` 或 `showTrigger`:**
   - **错误代码:** `new Notification('Test', { actions: [{ action: 'reply', title: 'Reply' }] });`
   - **结果:** `Notification::Create` 中会抛出 `TypeError: Actions are only supported for persistent notifications shown using ServiceWorkerRegistration.showNotification().` 异常。
   - **说明:** `actions` 和 `showTrigger` 仅用于通过 Service Worker 创建的持久性通知。

3. **在非安全上下文 (HTTP) 中尝试创建通知:**
   - **错误代码:** 在 HTTP 页面中执行 `new Notification('Test');`
   - **结果:**  `PrepareShow` 中会因为 `!GetExecutionContext()->IsSecureContext()` 而调用 `DispatchErrorEvent`，触发 JavaScript 的 `error` 事件，并且通知不会显示。
   - **说明:** 出于安全考虑，通知 API 通常只允许在安全上下文（HTTPS）中使用。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者想要调试一个非持久性通知的显示问题。以下是用户操作到达 `notification.cc` 的一个典型路径：

1. **用户访问一个网页:** 用户在浏览器中打开一个使用了 Notification API 的网页。
2. **网页 JavaScript 代码执行:** 网页的 JavaScript 代码被执行。
3. **调用 `new Notification()`:**  JavaScript 代码中调用了 `new Notification('...')` 来创建通知。
4. **Blink 引擎处理 `new Notification()`:**  V8 引擎执行 JavaScript 代码时，会调用 Blink 引擎中对应的 C++ 代码，即 `Notification::Create` 方法。
5. **权限检查:** `Notification::Create` 或其后续调用会检查通知权限。如果权限未授予，可能会触发权限请求流程。
6. **资源加载:** 如果通知包含图标或其他资源，`NotificationResourcesLoader` 会被创建并开始加载这些资源。
7. **发送到浏览器进程:**  `NotificationManager::DisplayNonPersistentNotification` 被调用，通过 Mojo 接口将通知数据发送到浏览器的 UI 进程。
8. **浏览器进程显示通知:** 浏览器的 UI 进程接收到通知数据，并在用户的操作系统中显示通知。
9. **用户与通知交互或关闭通知:** 用户可能会点击通知 (触发 `OnClick`) 或关闭通知 (触发 `OnClose`)。这些用户操作会由操作系统或浏览器进程捕获，并通过 Mojo 接口通知 Blink 渲染进程。
10. **Blink 引擎处理通知事件:** Blink 渲染进程接收到通知事件，并调用 `Notification::OnClick` 或 `Notification::OnClose` 等方法，最终触发 JavaScript 中注册的事件监听器。

**调试线索:**

- **断点:** 在 `Notification::Create`, `PrepareShow`, `DidLoadResources`, `OnShow`, `OnClick`, `OnClose` 等关键方法设置断点，可以观察通知创建和生命周期的各个阶段。
- **日志:** 使用 `DLOG` 或 `DVLOG` 在关键路径上打印日志，可以跟踪代码执行流程和变量值。
- **Mojo 接口监控:** 使用 Chromium 提供的工具 (例如 `chrome://tracing`) 监控 Mojo 消息的传递，可以查看通知数据是如何在渲染进程和浏览器进程之间传递的。
- **浏览器开发者工具:** 使用浏览器的开发者工具 (例如 "审查元素" -> "Application" -> "Notifications") 可以查看已创建的通知状态，以及可能的错误信息。
- **权限设置:** 检查浏览器的通知权限设置，确保网站已被允许发送通知。

通过以上分析，可以理解 `notification.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它连接了 JavaScript API 和浏览器底层的通知机制，负责管理非持久性通知的创建、显示、交互和生命周期。

Prompt: 
```
这是目录为blink/renderer/modules/notifications/notification.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

#include "third_party/blink/renderer/modules/notifications/notification.h"

#include <memory>
#include <utility>

#include "base/task/single_thread_task_runner.h"
#include "base/unguessable_token.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/common/notifications/notification_constants.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value_factory.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_notification_action.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_notification_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/scoped_window_focus_allowed_indicator.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/performance_monitor.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/notifications/notification_data.h"
#include "third_party/blink/renderer/modules/notifications/notification_manager.h"
#include "third_party/blink/renderer/modules/notifications/notification_resources_loader.h"
#include "third_party/blink/renderer/modules/notifications/timestamp_trigger.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

Notification* Notification::Create(ExecutionContext* context,
                                   const String& title,
                                   const NotificationOptions* options,
                                   ExceptionState& exception_state) {
  // The Notification constructor may be disabled through a runtime feature when
  // the platform does not support non-persistent notifications.
  if (!RuntimeEnabledFeatures::NotificationConstructorEnabled()) {
    exception_state.ThrowTypeError(
        "Illegal constructor. Use ServiceWorkerRegistration.showNotification() "
        "instead.");
    return nullptr;
  }

  // The Notification constructor may not be used in Service Worker contexts.
  if (context->IsServiceWorkerGlobalScope()) {
    exception_state.ThrowTypeError("Illegal constructor.");
    return nullptr;
  }

  if (!options->actions().empty()) {
    exception_state.ThrowTypeError(
        "Actions are only supported for persistent notifications shown using "
        "ServiceWorkerRegistration.showNotification().");
    return nullptr;
  }

  if (options->hasShowTrigger()) {
    exception_state.ThrowTypeError(
        "ShowTrigger is only supported for persistent notifications shown "
        "using ServiceWorkerRegistration.showNotification().");
    return nullptr;
  }

  auto* window = DynamicTo<LocalDOMWindow>(context);
  if (context->IsSecureContext()) {
    UseCounter::Count(context, WebFeature::kNotificationSecureOrigin);
    if (window) {
      window->CountUseOnlyInCrossOriginIframe(
          WebFeature::kNotificationAPISecureOriginIframe);
    }
  } else {
    Deprecation::CountDeprecation(context,
                                  WebFeature::kNotificationInsecureOrigin);
    if (window) {
      Deprecation::CountDeprecationCrossOriginIframe(
          window, WebFeature::kNotificationAPIInsecureOriginIframe);
    }
  }

  mojom::blink::NotificationDataPtr data =
      CreateNotificationData(context, title, options, exception_state);
  if (exception_state.HadException())
    return nullptr;

  if (context->IsContextDestroyed()) {
    exception_state.ThrowTypeError("Illegal invocation.");
    return nullptr;
  }

  Notification* notification = MakeGarbageCollected<Notification>(
      context, Type::kNonPersistent, std::move(data));

  // TODO(https://crbug.com/595685): Make |token| a constructor parameter
  // once persistent notifications have been mojofied too.
  if (notification->tag().IsNull() || notification->tag().empty()) {
    auto unguessable_token = base::UnguessableToken::Create();
    notification->SetToken(unguessable_token.ToString().c_str());
  } else {
    notification->SetToken(notification->tag());
  }

  notification->SchedulePrepareShow();

  if (window) {
    if (auto* document_resource_coordinator =
            window->document()->GetResourceCoordinator()) {
      document_resource_coordinator->OnNonPersistentNotificationCreated();
    }
  }

  return notification;
}

Notification* Notification::Create(ExecutionContext* context,
                                   const String& notification_id,
                                   mojom::blink::NotificationDataPtr data,
                                   bool showing) {
  Notification* notification = MakeGarbageCollected<Notification>(
      context, Type::kPersistent, std::move(data));
  notification->SetState(showing ? State::kShowing : State::kClosed);
  notification->SetNotificationId(notification_id);
  return notification;
}

Notification::Notification(ExecutionContext* context,
                           Type type,
                           mojom::blink::NotificationDataPtr data)
    : ActiveScriptWrappable<Notification>({}),
      ExecutionContextLifecycleObserver(context),
      type_(type),
      state_(State::kLoading),
      data_(std::move(data)),
      prepare_show_timer_(context->GetTaskRunner(TaskType::kMiscPlatformAPI),
                          this,
                          &Notification::PrepareShow),
      listener_receiver_(this, context) {
  if (data_->show_trigger_timestamp.has_value()) {
    show_trigger_ = TimestampTrigger::Create(static_cast<DOMTimeStamp>(
        data_->show_trigger_timestamp.value().InMillisecondsFSinceUnixEpoch()));
  }
}

Notification::~Notification() = default;

void Notification::SchedulePrepareShow() {
  DCHECK_EQ(state_, State::kLoading);

  prepare_show_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void Notification::PrepareShow(TimerBase*) {
  DCHECK_EQ(state_, State::kLoading);
  if (!GetExecutionContext()->IsSecureContext()) {
    DispatchErrorEvent();
    return;
  }

  if (NotificationManager::From(GetExecutionContext())->GetPermissionStatus() !=
      mojom::blink::PermissionStatus::GRANTED) {
    DispatchErrorEvent();
    return;
  }

  loader_ = MakeGarbageCollected<NotificationResourcesLoader>(
      WTF::BindOnce(&Notification::DidLoadResources, WrapWeakPersistent(this)));
  loader_->Start(GetExecutionContext(), *data_);
}

void Notification::DidLoadResources(NotificationResourcesLoader* loader) {
  DCHECK_EQ(loader, loader_.Get());

  mojo::PendingRemote<mojom::blink::NonPersistentNotificationListener>
      event_listener;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetExecutionContext()->GetTaskRunner(blink::TaskType::kInternalDefault);
  listener_receiver_.Bind(event_listener.InitWithNewPipeAndPassReceiver(),
                          task_runner);

  NotificationManager::From(GetExecutionContext())
      ->DisplayNonPersistentNotification(token_, data_->Clone(),
                                         loader->GetResources(),
                                         std::move(event_listener));

  loader_.Clear();

  state_ = State::kShowing;
}

void Notification::close() {
  if (state_ != State::kShowing)
    return;

  // Schedule the "close" event to be fired for non-persistent notifications.
  // Persistent notifications won't get such events for programmatic closes.
  if (type_ == Type::kNonPersistent) {
    state_ = State::kClosing;
    NotificationManager::From(GetExecutionContext())
        ->CloseNonPersistentNotification(token_);
    return;
  }

  state_ = State::kClosed;

  NotificationManager::From(GetExecutionContext())
      ->ClosePersistentNotification(notification_id_);
}

void Notification::OnShow() {
  DispatchEvent(*Event::Create(event_type_names::kShow));
}

void Notification::OnClick(OnClickCallback completed_closure) {
  ExecutionContext* context = GetExecutionContext();
  auto* window = DynamicTo<LocalDOMWindow>(context);
  if (window && window->GetFrame()) {
    LocalFrame::NotifyUserActivation(
        window->GetFrame(),
        mojom::blink::UserActivationNotificationType::kInteraction);
  }
  ScopedWindowFocusAllowedIndicator window_focus_allowed(GetExecutionContext());
  DispatchEvent(*Event::Create(event_type_names::kClick));

  std::move(completed_closure).Run();
}

void Notification::OnClose(OnCloseCallback completed_closure) {
  // The notification should be Showing if the user initiated the close, or it
  // should be Closing if the developer initiated the close.
  if (state_ == State::kShowing || state_ == State::kClosing) {
    state_ = State::kClosed;
    DispatchEvent(*Event::Create(event_type_names::kClose));
  }
  std::move(completed_closure).Run();
}

void Notification::DispatchErrorEvent() {
  DispatchEvent(*Event::Create(event_type_names::kError));
}

String Notification::title() const {
  return data_->title;
}

String Notification::dir() const {
  switch (data_->direction) {
    case mojom::blink::NotificationDirection::LEFT_TO_RIGHT:
      return "ltr";
    case mojom::blink::NotificationDirection::RIGHT_TO_LEFT:
      return "rtl";
    case mojom::blink::NotificationDirection::AUTO:
      return "auto";
  }

  NOTREACHED();
}

String Notification::lang() const {
  return data_->lang;
}

String Notification::body() const {
  return data_->body;
}

String Notification::tag() const {
  return data_->tag;
}

String Notification::image() const {
  return data_->image.GetString();
}

String Notification::icon() const {
  return data_->icon.GetString();
}

String Notification::badge() const {
  return data_->badge.GetString();
}

VibrationController::VibrationPattern Notification::vibrate() const {
  VibrationController::VibrationPattern pattern;
  if (data_->vibration_pattern.has_value()) {
    pattern.AppendRange(data_->vibration_pattern->begin(),
                        data_->vibration_pattern->end());
  }

  return pattern;
}

DOMTimeStamp Notification::timestamp() const {
  return data_->timestamp;
}

bool Notification::renotify() const {
  return data_->renotify;
}

bool Notification::silent() const {
  return data_->silent;
}

bool Notification::requireInteraction() const {
  return data_->require_interaction;
}

ScriptValue Notification::data(ScriptState* script_state) {
  base::span<const uint8_t> data;
  if (data_->data.has_value()) {
    data = data_->data.value();
  }
  scoped_refptr<SerializedScriptValue> serialized_value =
      SerializedScriptValue::Create(data);

  return ScriptValue(script_state->GetIsolate(),
                     serialized_value->Deserialize(script_state->GetIsolate()));
}

v8::LocalVector<v8::Value> Notification::actions(
    ScriptState* script_state) const {
  v8::LocalVector<v8::Value> result(script_state->GetIsolate());
  if (!data_->actions.has_value())
    return result;

  const Vector<mojom::blink::NotificationActionPtr>& actions =
      data_->actions.value();
  result.resize(actions.size());
  for (wtf_size_t i = 0; i < actions.size(); ++i) {
    NotificationAction* action = NotificationAction::Create();

    switch (actions[i]->type) {
      case mojom::blink::NotificationActionType::BUTTON:
        action->setType("button");
        break;
      case mojom::blink::NotificationActionType::TEXT:
        action->setType("text");
        break;
      default:
        NOTREACHED() << "Unknown action type: " << actions[i]->type;
    }

    action->setAction(actions[i]->action);
    action->setTitle(actions[i]->title);
    action->setIcon(actions[i]->icon.GetString());
    action->setPlaceholder(actions[i]->placeholder);

    // Both the Action dictionaries themselves and the sequence they'll be
    // returned in are expected to the frozen. This cannot be done with
    // WebIDL.
    result[i] = FreezeV8Object(
        ToV8Traits<NotificationAction>::ToV8(script_state, action),
        script_state->GetIsolate());
  }

  return result;
}

String Notification::scenario() const {
  switch (data_->scenario) {
    case mojom::blink::NotificationScenario::DEFAULT:
      return "default";
    case mojom::blink::NotificationScenario::INCOMING_CALL:
      return "incoming-call";
  }

  NOTREACHED();
}

V8NotificationPermission::Enum Notification::PermissionToV8Enum(
    mojom::blink::PermissionStatus permission) {
  switch (permission) {
    case mojom::blink::PermissionStatus::GRANTED:
      return V8NotificationPermission::Enum::kGranted;
    case mojom::blink::PermissionStatus::DENIED:
      return V8NotificationPermission::Enum::kDenied;
    case mojom::blink::PermissionStatus::ASK:
      return V8NotificationPermission::Enum::kDefault;
  }
  NOTREACHED();
}

V8NotificationPermission Notification::permission(ExecutionContext* context) {
  // Permission is always denied for insecure contexts. Skip the sync IPC call.
  if (!context->IsSecureContext()) {
    return V8NotificationPermission(V8NotificationPermission::Enum::kDenied);
  }

  // If the current global object's browsing context is a prerendering browsing
  // context, then return "default".
  // https://wicg.github.io/nav-speculation/prerendering.html#patch-notifications
  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    if (Document* document = window->document(); document->IsPrerendering()) {
      return V8NotificationPermission(V8NotificationPermission::Enum::kDefault);
    }
  }

  mojom::blink::PermissionStatus status =
      NotificationManager::From(context)->GetPermissionStatus();

  // Permission can only be requested from top-level frames and same-origin
  // iframes. This should be reflected in calls getting permission status.
  //
  // TODO(crbug.com/758603): Move this check to the browser process when the
  // NotificationService connection becomes frame-bound.
  if (status == mojom::blink::PermissionStatus::ASK) {
    auto* window = DynamicTo<LocalDOMWindow>(context);
    LocalFrame* frame = window ? window->GetFrame() : nullptr;
    if (!frame || frame->IsCrossOriginToOutermostMainFrame())
      status = mojom::blink::PermissionStatus::DENIED;
  }

  return V8NotificationPermission(PermissionToV8Enum(status));
}

ScriptPromise<V8NotificationPermission> Notification::requestPermission(
    ScriptState* script_state,
    V8NotificationPermissionCallback* deprecated_callback) {
  if (!script_state->ContextIsValid())
    return EmptyPromise();

  ExecutionContext* context = ExecutionContext::From(script_state);

  probe::BreakableLocation(context, "Notification.requestPermission");
  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    if (!LocalFrame::HasTransientUserActivation(window->GetFrame())) {
      PerformanceMonitor::ReportGenericViolation(
          context, PerformanceMonitor::kDiscouragedAPIUse,
          "Only request notification permission in response to a user gesture.",
          base::TimeDelta(), nullptr);
    }

    // Sites cannot request notification permission from cross-origin iframes,
    // but they can use notifications if permission had already been granted.
    if (window->GetFrame()->IsCrossOriginToOutermostMainFrame()) {
      Deprecation::CountDeprecation(
          context, WebFeature::kNotificationPermissionRequestedIframe);
    }
  }

  // Sites cannot request notification permission from insecure contexts.
  if (!context->IsSecureContext()) {
    Deprecation::CountDeprecation(
        context, WebFeature::kNotificationPermissionRequestedInsecureOrigin);
  }

  return NotificationManager::From(context)->RequestPermission(
      script_state, deprecated_callback);
}

uint32_t Notification::maxActions() {
  return kNotificationMaxActions;
}

DispatchEventResult Notification::DispatchEventInternal(Event& event) {
  DCHECK(GetExecutionContext()->IsContextThread());
  return EventTarget::DispatchEventInternal(event);
}

const AtomicString& Notification::InterfaceName() const {
  return event_target_names::kNotification;
}

void Notification::ContextDestroyed() {
  state_ = State::kClosed;

  if (prepare_show_timer_.IsActive())
    prepare_show_timer_.Stop();

  if (loader_)
    loader_->Stop();
}

bool Notification::HasPendingActivity() const {
  // Non-persistent notification can receive events until they've been closed.
  // Persistent notifications should be subject to regular garbage collection.
  if (type_ == Type::kNonPersistent)
    return state_ != State::kClosed;

  return false;
}

void Notification::Trace(Visitor* visitor) const {
  visitor->Trace(show_trigger_);
  visitor->Trace(prepare_show_timer_);
  visitor->Trace(loader_);
  visitor->Trace(listener_receiver_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink

"""

```