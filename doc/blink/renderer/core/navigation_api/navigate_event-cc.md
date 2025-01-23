Response:
Let's break down the thought process for analyzing this C++ code for `NavigateEvent.cc`.

1. **Identify the Core Purpose:** The file name `navigate_event.cc` immediately suggests this code is about the `NavigateEvent` within the Blink rendering engine. Knowing Blink's role in Chromium, we can infer this is related to how the browser handles navigation within a web page.

2. **Scan the Includes:** The `#include` statements provide valuable clues about the class's dependencies and responsibilities. Key includes that jump out are:
    * `v8/...`:  Indicates interaction with the V8 JavaScript engine.
    * `bindings/core/v8/...`:  Confirms the integration with V8 for exposing this functionality to JavaScript.
    * `core/dom/...`:  Points to interaction with the Document Object Model.
    * `core/frame/...`: Suggests involvement with frame and window management.
    * `core/loader/...`:  Implies interaction with the page loading process.
    * `core/navigation_api/...`: Reinforces the central theme of navigation.
    * `mojom/...`:  Indicates communication with other Chromium components, likely through IPC.

3. **Examine the Class Declaration:** The `class NavigateEvent` declaration confirms the file's focus. Looking at the member variables in the constructor gives a high-level understanding of the event's properties:
    * `navigation_type_`:  The type of navigation (push, replace, etc.).
    * `destination_`:  Information about the target of the navigation.
    * `can_intercept_`:  Whether the navigation can be intercepted.
    * `user_initiated_`: Whether the navigation was initiated by the user.
    * `hash_change_`: Whether it's a hash change navigation.
    * `controller_`, `signal_`:  Related to aborting the navigation.
    * `form_data_`:  Data associated with a form submission.
    * `info_`:  Arbitrary information related to the navigation.
    * `source_element_`: The element that triggered the navigation.

4. **Analyze Key Methods:**  Focus on the public methods as they define the primary interface and functionality:
    * `intercept()`: This is a crucial method, allowing JavaScript to intercept and potentially modify the navigation. Its parameters (`NavigationInterceptOptions`) are important.
    * `commit()`:  Allows forcing the navigation to proceed immediately after interception.
    * `scroll()`:  Allows controlling the scrolling behavior after navigation.
    * `abort()`: Allows JavaScript to cancel the navigation.
    * `PerformSharedChecks()`:  A utility method for common checks (trusted event, default prevented, detached window).
    * `React()` and `ReactDone()`: These seem related to how promises returned by intercept handlers are handled.

5. **Trace the Flow of Control (Conceptual):**  Imagine a scenario where a user clicks a link or JavaScript initiates a navigation. How does `NavigateEvent` fit in?
    * A `NavigateEvent` is created.
    * JavaScript event listeners can be attached to it.
    * If a listener calls `event.intercept()`, it gains control.
    * The listener can perform asynchronous operations.
    * It can then call `event.commit()` to proceed or allow the navigation to proceed naturally after the promise resolves.
    * `event.scroll()` gives control over scrolling.
    * `event.abort()` allows cancellation.

6. **Connect to Web Technologies:** Based on the identified functionality and the names of the methods, establish the relationship with JavaScript, HTML, and CSS:
    * **JavaScript:** The primary interaction point is through the `intercept`, `commit`, `scroll`, and `abort` methods. These are exposed to JavaScript. The use of Promises is a key connection.
    * **HTML:** The navigation is often triggered by HTML elements like `<a>` or form submissions. The `source_element_` member links back to HTML.
    * **CSS:** The scrolling behavior, potentially influenced by CSS's `scroll-behavior` property, is managed by the `scroll()` method.

7. **Infer Logical Reasoning and Scenarios:** Consider how the different methods and states interact. For example:
    * Calling `commit()` without first calling `intercept()`.
    * Calling `intercept()` multiple times.
    * The order of `intercept()`, `commit()`, and `scroll()`.
    * The behavior when promises returned by intercept handlers are rejected.

8. **Identify Potential User/Programming Errors:** Based on the API design and constraints, anticipate common mistakes:
    * Calling methods at the wrong time (e.g., after the event has finished).
    * Security errors when trying to intercept navigations under certain conditions.
    * Incorrectly using the `commit` option.
    * Not handling promise rejections from intercept handlers.

9. **Structure the Output:** Organize the findings into logical categories (functionality, JavaScript/HTML/CSS relations, logical reasoning, common errors) for clarity and readability. Use clear examples to illustrate the concepts.

10. **Refine and Iterate:** Review the analysis for accuracy and completeness. Ensure the explanations are clear and easy to understand for someone familiar with web development concepts but potentially less familiar with Blink internals. For instance, initially, I might just say "handles navigation," but refining it to "intercepting, modifying, and controlling navigation initiated by user actions or JavaScript" is more precise.

This structured approach, moving from the general purpose to specific details and then connecting back to broader web technologies, is effective for understanding and explaining complex code like this.
这个文件 `navigate_event.cc` 是 Chromium Blink 引擎中 `Navigation API` 的核心组件之一，它定义了 `NavigateEvent` 类。`NavigateEvent` 对象会在导航发生时被派发到 `Window` 对象上，它为开发者提供了一种拦截和自定义页面导航行为的机制。

以下是 `navigate_event.cc` 文件的主要功能及其与 JavaScript, HTML, CSS 的关系，以及一些逻辑推理和常见错误示例：

**主要功能:**

1. **表示导航事件:**  `NavigateEvent` 类封装了关于正在发生的导航的信息，例如：
    * 导航的类型 (`navigation_type_`): `pushState`, `replaceState`, `traverse`, `reload` 等。
    * 导航的目标 (`destination_`): 包含目标 URL 和状态信息。
    * 是否可以被拦截 (`can_intercept_`):  决定了这个导航事件是否可以通过 JavaScript 的 `intercept()` 方法进行拦截。
    * 是否由用户发起 (`user_initiated_`): 表明导航是否是用户操作触发的。
    * 是否是哈希值改变 (`hash_change_`):  指示这是一个仅改变 URL 哈希值的导航。
    * 关联的 `AbortController` 和 `AbortSignal`: 用于中止导航。
    * 表单数据 (`form_data_`): 如果导航是由表单提交触发，则包含表单数据。
    * 下载请求 (`download_request_`): 指示这是一个下载请求。
    * 附加信息 (`info_`): 允许传递额外的信息。
    * 用户代理视觉过渡 (`has_ua_visual_transition_`):  指示用户代理是否会应用视觉过渡效果。
    * 触发导航的元素 (`source_element_`):  指向触发导航的 HTML 元素。

2. **提供拦截导航的能力:**  `intercept()` 方法是 `NavigateEvent` 的关键，它允许 JavaScript 代码暂停导航，执行异步操作，并最终决定是否继续导航。开发者可以传入一个 `handler` 函数，该函数返回一个 Promise。只有当 Promise resolve 后，导航才会继续。

3. **支持手动提交导航:**  `commit()` 方法允许在 `intercept()` 被调用后，手动触发导航的提交。这通常用于在 `intercept` 的 handler 中执行一些异步操作后，明确地指示继续导航。

4. **控制滚动行为:** `scroll()` 方法允许在导航完成后控制页面的滚动行为。开发者可以指定是否应该恢复到之前的滚动位置。

5. **支持中止导航:** `abort()` 方法允许 JavaScript 代码中止正在进行的导航。

6. **管理导航状态:**  文件内部维护了一些状态，例如 `intercept_state_`，用于跟踪导航拦截的不同阶段。

7. **处理 Promise 链:**  `React()` 和 `ReactDone()` 方法用于处理 `intercept()` 方法中 `handler` 返回的 Promise 链。只有当所有 `handler` 返回的 Promise 都 resolve 后，导航才会最终完成。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** `NavigateEvent` 是一个 JavaScript 事件，可以通过 `window.addEventListener('navigate', event => { ... })` 监听。
    * **例子:**
        ```javascript
        window.addEventListener('navigate', event => {
          console.log('导航到:', event.destination.url);
          if (event.destination.url.startsWith('/dashboard')) {
            event.intercept({
              handler: () => {
                return fetch('/check-authentication').then(response => {
                  if (!response.ok) {
                    // 用户未认证，阻止导航
                    event.preventDefault();
                  }
                });
              }
            });
          }
        });
        ```
        在这个例子中，JavaScript 代码监听 `navigate` 事件，并对以 `/dashboard` 开头的导航进行拦截，检查用户认证状态。如果未认证，则调用 `event.preventDefault()` 阻止导航。

    * **`intercept()` 方法的选项：**
        * `handler`: 一个返回 Promise 的函数，用于执行异步操作。
        * `focusReset`:  控制导航完成后焦点如何重置 (例如: `after-transition`, `manual`)。
        * `scroll`: 控制导航完成后是否恢复滚动位置 (例如: `auto`, `manual`)。
        * `commit`: 控制导航何时提交 (例如: `immediate`, `after-transition`)。

    * **`scroll()` 方法:**
        ```javascript
        window.addEventListener('navigate', event => {
          if (event.destination.url.startsWith('/products')) {
            event.intercept({
              handler: async () => {
                await loadProducts();
                event.scroll(); // 手动触发滚动行为
              }
            });
          }
        });
        ```

    * **`commit()` 方法:**
        ```javascript
        window.addEventListener('navigate', event => {
          if (event.destination.url.startsWith('/checkout')) {
            event.intercept({
              commit: 'after-transition',
              handler: async () => {
                await validateCart();
                event.commit(); // 显式提交导航
              }
            });
          }
        });
        ```

    * **`abort()` 方法:**
        ```javascript
        const controller = new AbortController();
        window.addEventListener('navigate', event => {
          if (event.destination.url.startsWith('/long-process')) {
            event.intercept({
              signal: controller.signal,
              handler: async () => {
                // ... 启动一个可能很长的任务 ...
              }
            });
          }
        });

        // 在某个时刻决定中止导航
        controller.abort('用户取消');
        ```

* **HTML:**  用户的导航行为通常通过点击 HTML 链接 (`<a>`) 或提交表单 (`<form>`) 触发。`NavigateEvent` 的 `source_element_` 成员可以访问到触发导航的 HTML 元素。
    * **例子:**  用户点击了一个 `<a href="/about">关于我们</a>` 链接会触发一个 `NavigateEvent`。

* **CSS:** CSS 的 `scroll-behavior` 属性可以影响浏览器的默认滚动行为。`NavigateEvent` 的 `scroll()` 方法允许 JavaScript 更精细地控制滚动，可以覆盖默认行为。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 用户点击一个 `<a href="/new-page">New Page</a>` 链接。JavaScript 代码监听了 `navigate` 事件并调用了 `event.intercept()`，其 `handler` 返回一个立即 resolve 的 Promise。
* **输出:**
    1. 创建并派发一个 `NavigateEvent` 对象，其 `destination.url` 为 `/new-page`， `navigation_type_` 为 `pushState` (假设是同源导航)， `user_initiated_` 为 true。
    2. JavaScript 的 `navigate` 事件监听器被触发。
    3. `event.intercept()` 被调用，拦截了导航。
    4. `handler` 函数执行并返回一个立即 resolve 的 Promise。
    5. 由于 Promise 立即 resolve，导航继续进行，页面加载 `/new-page` 的内容。

* **假设输入:** 用户点击一个提交表单的按钮，该表单的 `action` 属性设置为 `/submit-form`。JavaScript 代码监听了 `navigate` 事件，并调用了 `event.intercept()`，其 `handler` 发起了一个网络请求，只有在请求成功后才 resolve Promise。
* **输出:**
    1. 创建一个 `NavigateEvent` 对象，其 `destination.url` 为 `/submit-form`，`navigation_type_` 可能是 `pushState` 或 `replaceState` (取决于表单的 `method` 和是否有其他 JavaScript 操纵)，`user_initiated_` 为 true， `form_data_` 包含表单数据。
    2. JavaScript 的 `navigate` 事件监听器被触发。
    3. `event.intercept()` 被调用，导航被拦截。
    4. `handler` 函数执行，发起网络请求。
    5. 在网络请求完成之前，浏览器可能会显示加载状态，但不会立即导航到 `/submit-form`。
    6. 如果网络请求成功，Promise resolve，导航继续进行。如果请求失败，Promise reject，开发者可以选择调用 `event.preventDefault()` 来阻止导航或采取其他措施。

**涉及用户或者编程常见的使用错误:**

1. **在 `intercept()` 调用之前或之后错误地调用 `commit()` 或 `scroll()`:**  `commit()` 只能在 `intercept()` 被调用之后且在导航完成之前调用。同样，`scroll()` 也需要在 `intercept()` 之后调用。
    * **例子:**
        ```javascript
        window.addEventListener('navigate', event => {
          event.commit(); // 错误：在 intercept 之前调用 commit
          event.intercept({ handler: () => {} });
        });

        window.addEventListener('navigate', event => {
          event.intercept({ handler: () => {} });
          setTimeout(() => {
            event.commit(); // 可能错误：在异步操作后调用，但事件可能已经完成
          }, 1000);
        });
        ```

2. **在非信任事件上调用 `intercept()` 等方法:**  `intercept()`, `commit()`, `scroll()` 等方法只能在 `isTrusted` 属性为 `true` 的 `NavigateEvent` 上调用，这意味着事件必须是由浏览器自身触发的，而不是通过 JavaScript 手动创建并派发的。
    * **例子:**
        ```javascript
        const navigateEvent = new NavigateEvent('navigate', { destination: { url: '/new-page' } });
        navigateEvent.intercept({ handler: () => {} }); // 错误：navigateEvent 不是 trusted event
        ```

3. **在事件已经被取消后调用 `intercept()` 等方法:** 如果 `event.preventDefault()` 已经被调用，再调用 `intercept()`, `commit()`, 或 `scroll()` 会抛出错误。
    * **例子:**
        ```javascript
        window.addEventListener('navigate', event => {
          if (someCondition) {
            event.preventDefault();
          }
          event.intercept({ handler: () => {} }); // 如果 preventDefault 被调用，这里会出错
        });
        ```

4. **在同一个 `NavigateEvent` 上多次调用 `intercept()`:**  只能调用一次 `intercept()`。
    * **例子:**
        ```javascript
        window.addEventListener('navigate', event => {
          event.intercept({ handler: () => {} });
          event.intercept({ handler: () => {} }); // 错误：重复调用 intercept
        });
        ```

5. **忘记处理 `intercept()` handler 返回的 Promise 的 reject 情况:** 如果 `handler` 返回的 Promise reject，导航不会继续，开发者需要根据业务逻辑进行处理，例如显示错误信息。

6. **在 detached 的 window 中调用 `intercept()` 等方法:** 如果 `NavigateEvent` 的目标 `Window` 已经被 detached，调用这些方法会抛出错误。

总而言之，`navigate_event.cc` 文件定义了 Blink 引擎中处理页面导航的核心事件和机制，它与 JavaScript 紧密结合，为开发者提供了强大的自定义导航行为的能力，但也需要开发者理解其生命周期和使用限制，以避免常见的编程错误。

### 提示词
```
这是目录为blink/renderer/core/navigation_api/navigate_event.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/navigation_api/navigate_event.h"

#include "third_party/blink/public/mojom/devtools/console_message.mojom-shared.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/promise_all.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_navigate_event_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_navigation_intercept_handler.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_navigation_intercept_options.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/abort_controller.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/event_interface_names.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/progress_tracker.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_destination.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cancellable_task.h"

namespace blink {

class NavigateEvent::FulfillReaction final
    : public ThenCallable<IDLUndefined, FulfillReaction> {
 public:
  explicit FulfillReaction(NavigateEvent* navigate_event)
      : navigate_event_(navigate_event) {}
  void Trace(Visitor* visitor) const final {
    ThenCallable<IDLUndefined, FulfillReaction>::Trace(visitor);
    visitor->Trace(navigate_event_);
  }
  void React(ScriptState*) {
    navigate_event_->ReactDone(ScriptValue(), /*did_fulfill=*/true);
  }

 private:
  Member<NavigateEvent> navigate_event_;
};

class NavigateEvent::RejectReaction final
    : public ThenCallable<IDLAny, RejectReaction> {
 public:
  explicit RejectReaction(NavigateEvent* navigate_event)
      : navigate_event_(navigate_event) {}
  void Trace(Visitor* visitor) const final {
    ThenCallable<IDLAny, RejectReaction>::Trace(visitor);
    visitor->Trace(navigate_event_);
  }
  void React(ScriptState*, ScriptValue value) {
    navigate_event_->ReactDone(value, /*did_fulfill=*/false);
  }

 private:
  Member<NavigateEvent> navigate_event_;
};

NavigateEvent::NavigateEvent(ExecutionContext* context,
                             const AtomicString& type,
                             NavigateEventInit* init,
                             AbortController* controller)
    : Event(type, init),
      ExecutionContextClient(context),
      navigation_type_(init->navigationType().AsEnum()),
      destination_(init->destination()),
      can_intercept_(init->canIntercept()),
      user_initiated_(init->userInitiated()),
      hash_change_(init->hashChange()),
      controller_(controller),
      signal_(init->signal()),
      form_data_(init->formData()),
      download_request_(init->downloadRequest()),
      info_(init->hasInfo()
                ? init->info()
                : ScriptValue(context->GetIsolate(),
                              v8::Undefined(context->GetIsolate()))),
      has_ua_visual_transition_(init->hasUAVisualTransition()),
      source_element_(init->sourceElement()) {
  CHECK(IsA<LocalDOMWindow>(context));
  CHECK(!controller_ || controller_->signal() == signal_);
}

bool NavigateEvent::PerformSharedChecks(const String& function_name,
                                        ExceptionState& exception_state) {
  if (!DomWindow()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        function_name + "() may not be called in a detached window.");
    return false;
  }
  if (!isTrusted()) {
    exception_state.ThrowSecurityError(
        function_name + "() may only be called on a trusted event.");
    return false;
  }
  if (defaultPrevented()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        function_name + "() may not be called if the event has been canceled.");
    return false;
  }
  return true;
}

void NavigateEvent::intercept(NavigationInterceptOptions* options,
                              ExceptionState& exception_state) {
  if (!PerformSharedChecks("intercept", exception_state)) {
    return;
  }

  if (!can_intercept_) {
    exception_state.ThrowSecurityError(
        "A navigation with URL '" + dispatch_params_->url.ElidedString() +
        "' cannot be intercepted by in a window with origin '" +
        DomWindow()->GetSecurityOrigin()->ToString() + "' and URL '" +
        DomWindow()->Url().ElidedString() + "'.");
    return;
  }

  if (!IsBeingDispatched()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "intercept() may only be called while the navigate event is being "
        "dispatched.");
    return;
  }

  if (RuntimeEnabledFeatures::NavigateEventCommitBehaviorEnabled() &&
      !cancelable() && options->hasCommit() &&
      options->commit().AsEnum() ==
          V8NavigationCommitBehavior::Enum::kAfterTransition) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "intercept() may only be called with a commit option of "
        "\"after-transition\" when the navigate event is cancelable.");
    return;
  }

  if (!HasNavigationActions()) {
    DomWindow()->document()->AddFocusedElementChangeObserver(this);
  }

  if (options->hasFocusReset()) {
    if (focus_reset_behavior_ &&
        focus_reset_behavior_->AsEnum() != options->focusReset().AsEnum()) {
      GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "The \"" + options->focusReset().AsString() + "\" value for " +
                  "intercept()'s focusReset option "
                  "will override the previously-passed value of \"" +
                  focus_reset_behavior_->AsString() + "\"."));
    }
    focus_reset_behavior_ = options->focusReset();
  }

  if (options->hasScroll()) {
    if (scroll_behavior_ &&
        scroll_behavior_->AsEnum() != options->scroll().AsEnum()) {
      GetExecutionContext()->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "The \"" + options->scroll().AsString() + "\" value for " +
                  "intercept()'s scroll option "
                  "will override the previously-passed value of \"" +
                  scroll_behavior_->AsString() + "\"."));
    }
    scroll_behavior_ = options->scroll();
  }

  if (RuntimeEnabledFeatures::NavigateEventCommitBehaviorEnabled()) {
    if (options->hasCommit()) {
      if (commit_behavior_ &&
          commit_behavior_->AsEnum() != options->commit().AsEnum()) {
        GetExecutionContext()->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kJavaScript,
                mojom::blink::ConsoleMessageLevel::kWarning,
                "The \"" + options->commit().AsString() + "\" value for " +
                    "intercept()'s commit option "
                    "will override the previously-passed value of \"" +
                    commit_behavior_->AsString() + "\"."));
      }
      commit_behavior_ = options->commit();
    }
  }

  CHECK(intercept_state_ == InterceptState::kNone ||
        intercept_state_ == InterceptState::kIntercepted);
  intercept_state_ = InterceptState::kIntercepted;
  if (options->hasHandler())
    navigation_action_handlers_list_.push_back(options->handler());
}

void NavigateEvent::commit(ExceptionState& exception_state) {
  if (!PerformSharedChecks("commit", exception_state)) {
    return;
  }

  if (intercept_state_ == InterceptState::kNone) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "intercept() must be called before commit().");
    return;
  }
  if (ShouldCommitImmediately()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "commit() may only be used if { commit: "
                                      "'after-transition' } was specified.");
    return;
  }
  if (IsBeingDispatched()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "commit() may not be called during event dispatch");
    return;
  }
  if (intercept_state_ == InterceptState::kFinished) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "commit() may not be called after transition completes.");
    return;
  }
  if (intercept_state_ == InterceptState::kCommitted ||
      intercept_state_ == InterceptState::kScrolled) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "commit() already called.");
    return;
  }
  CommitNow();
}

void NavigateEvent::MaybeCommitImmediately(ScriptState* script_state) {
  delayed_load_start_task_handle_ = PostDelayedCancellableTask(
      *DomWindow()->GetTaskRunner(TaskType::kInternalLoading), FROM_HERE,
      WTF::BindOnce(&NavigateEvent::DelayedLoadStartTimerFired,
                    WrapWeakPersistent(this)),
      kDelayLoadStart);

  if (ShouldCommitImmediately()) {
    CommitNow();
    return;
  }

  DomWindow()->GetFrame()->Loader().Progress().ProgressStarted();
  FinalizeNavigationActionPromisesList();
}

bool NavigateEvent::ShouldCommitImmediately() {
  return !commit_behavior_ || commit_behavior_->AsEnum() ==
                                  V8NavigationCommitBehavior::Enum::kImmediate;
}

void NavigateEvent::CommitNow() {
  CHECK_EQ(intercept_state_, InterceptState::kIntercepted);
  CHECK(!dispatch_params_->destination_item || !dispatch_params_->state_object);

  intercept_state_ = InterceptState::kCommitted;

  auto* state_object = dispatch_params_->destination_item
                           ? dispatch_params_->destination_item->StateObject()
                           : dispatch_params_->state_object.get();

  // In the spec, the URL and history update steps are not called for reloads.
  // In our implementation, we call the corresponding function anyway, but
  // |type| being a reload type makes it do none of the spec-relevant
  // steps. Instead it does stuff like the loading spinner and use counters.
  DomWindow()->document()->Loader()->RunURLAndHistoryUpdateSteps(
      dispatch_params_->url, dispatch_params_->destination_item,
      mojom::blink::SameDocumentNavigationType::kNavigationApiIntercept,
      state_object, dispatch_params_->frame_load_type,
      dispatch_params_->event_type == NavigateEventType::kHistoryApi
          ? FirePopstate::kNo
          : FirePopstate::kYes,
      dispatch_params_->is_browser_initiated,
      dispatch_params_->is_synchronously_committed_same_document,
      dispatch_params_->soft_navigation_heuristics_task_id);
}

void NavigateEvent::React(ScriptState* script_state) {
  CHECK(navigation_action_handlers_list_.empty());

  if (navigation_action_promises_list_.empty()) {
    // There is a subtle timing difference between the fast-path for zero
    // promises and the path for 1+ promises, in both spec and implementation.
    // In most uses of Promise.all() / the Web IDL spec's "wait for
    // all", this does not matter. However for us there are so many events and
    // promise handlers firing around the same time (navigatesuccess, committed
    // promise, finished promise, ...) that the difference is pretty easily
    // observable by web developers and web platform tests. So, let's make sure
    // we always go down the 1+ promises path.
    navigation_action_promises_list_.push_back(
        ToResolvedUndefinedPromise(script_state));
  }

  auto promise = PromiseAll<IDLUndefined>::Create(
      script_state, navigation_action_promises_list_);
  promise.Then(script_state, MakeGarbageCollected<FulfillReaction>(this),
               MakeGarbageCollected<RejectReaction>(this));

  if (HasNavigationActions() && DomWindow()) {
    if (AXObjectCache* cache =
            DomWindow()->document()->ExistingAXObjectCache()) {
      cache->HandleLoadStart(DomWindow()->document());
    }
  }
}

void NavigateEvent::ReactDone(ScriptValue value, bool did_fulfill) {
  CHECK_NE(intercept_state_, InterceptState::kFinished);

  LocalDOMWindow* window = DomWindow();
  if (signal_->aborted() || !window) {
    return;
  }

  delayed_load_start_task_handle_.Cancel();

  CHECK_EQ(this, window->navigation()->ongoing_navigate_event_);
  window->navigation()->ongoing_navigate_event_ = nullptr;

  if (intercept_state_ == InterceptState::kIntercepted) {
    if (did_fulfill) {
      CommitNow();
    } else {
      DomWindow()->GetFrame()->Client()->DidFailAsyncSameDocumentCommit();
    }
  }

  if (intercept_state_ >= InterceptState::kCommitted) {
    PotentiallyResetTheFocus();
    if (did_fulfill) {
      PotentiallyProcessScrollBehavior();
    }
    intercept_state_ = InterceptState::kFinished;
  }

  if (did_fulfill) {
    window->navigation()->DidFinishOngoingNavigation();
  } else {
    window->navigation()->DidFailOngoingNavigation(value);
  }

  if (HasNavigationActions()) {
    if (LocalFrame* frame = window->GetFrame()) {
      frame->Loader().DidFinishNavigation(
          did_fulfill ? FrameLoader::NavigationFinishState::kSuccess
                      : FrameLoader::NavigationFinishState::kFailure);
    }
    if (AXObjectCache* cache = window->document()->ExistingAXObjectCache()) {
      cache->HandleLoadComplete(window->document());
    }
  }
}

void NavigateEvent::Abort(ScriptState* script_state, ScriptValue error) {
  if (IsBeingDispatched()) {
    preventDefault();
  }
  CHECK(controller_);
  controller_->abort(script_state, error);
  delayed_load_start_task_handle_.Cancel();
}

void NavigateEvent::DelayedLoadStartTimerFired() {
  if (!DomWindow()) {
    return;
  }

  auto& frame_host = DomWindow()->GetFrame()->GetLocalFrameHostRemote();
  frame_host.StartLoadingForAsyncNavigationApiCommit();
}

void NavigateEvent::FinalizeNavigationActionPromisesList() {
  HeapVector<Member<V8NavigationInterceptHandler>> handlers_list;
  handlers_list.swap(navigation_action_handlers_list_);

  for (auto& function : handlers_list) {
    ScriptPromise<IDLUndefined> result;
    if (function->Invoke(this).To(&result))
      navigation_action_promises_list_.push_back(result);
  }
}

void NavigateEvent::PotentiallyResetTheFocus() {
  CHECK(intercept_state_ == InterceptState::kCommitted ||
        intercept_state_ == InterceptState::kScrolled);
  auto* document = DomWindow()->document();
  document->RemoveFocusedElementChangeObserver(this);

  // If focus has changed since intercept() was invoked, don't reset
  // focus.
  if (did_change_focus_during_intercept_)
    return;

  // If we're in "navigation API mode" per the above, then either leaving focus
  // reset behavior as the default, or setting it to "after-transition"
  // explicitly, should reset the focus.
  if (focus_reset_behavior_ &&
      focus_reset_behavior_->AsEnum() !=
          V8NavigationFocusReset::Enum::kAfterTransition) {
    return;
  }

  if (Element* focus_delegate = document->GetAutofocusDelegate()) {
    focus_delegate->Focus(FocusParams(FocusTrigger::kUserGesture));
  } else {
    document->ClearFocusedElement();
    document->SetSequentialFocusNavigationStartingPoint(nullptr);
  }
}

void NavigateEvent::DidChangeFocus() {
  CHECK(HasNavigationActions());
  did_change_focus_during_intercept_ = true;
}

void NavigateEvent::scroll(ExceptionState& exception_state) {
  if (!PerformSharedChecks("scroll", exception_state)) {
    return;
  }

  if (intercept_state_ == InterceptState::kFinished) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "scroll() may not be called after transition completes");
    return;
  }
  if (intercept_state_ == InterceptState::kScrolled) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "scroll() already called");
    return;
  }
  if (intercept_state_ == InterceptState::kNone) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "intercept() must be called before scroll()");
    return;
  }
  if (intercept_state_ == InterceptState::kIntercepted) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "scroll() may not be called before commit.");
    return;
  }

  ProcessScrollBehavior();
}

void NavigateEvent::PotentiallyProcessScrollBehavior() {
  CHECK(intercept_state_ == InterceptState::kCommitted ||
        intercept_state_ == InterceptState::kScrolled);
  if (intercept_state_ == InterceptState::kScrolled) {
    return;
  }
  if (scroll_behavior_ &&
      scroll_behavior_->AsEnum() == V8NavigationScrollBehavior::Enum::kManual) {
    return;
  }
  ProcessScrollBehavior();
}

WebFrameLoadType LoadTypeFromNavigation(
    V8NavigationType::Enum navigation_type) {
  switch (navigation_type) {
    case V8NavigationType::Enum::kPush:
      return WebFrameLoadType::kStandard;
    case V8NavigationType::Enum::kReplace:
      return WebFrameLoadType::kReplaceCurrentItem;
    case V8NavigationType::Enum::kTraverse:
      return WebFrameLoadType::kBackForward;
    case V8NavigationType::Enum::kReload:
      return WebFrameLoadType::kReload;
  }
  NOTREACHED();
}

void NavigateEvent::ProcessScrollBehavior() {
  CHECK_EQ(intercept_state_, InterceptState::kCommitted);
  intercept_state_ = InterceptState::kScrolled;

  std::optional<HistoryItem::ViewState> view_state =
      dispatch_params_->destination_item
          ? dispatch_params_->destination_item->GetViewState()
          : std::nullopt;
  auto scroll_behavior = has_ua_visual_transition_
                             ? mojom::blink::ScrollBehavior::kInstant
                             : mojom::blink::ScrollBehavior::kAuto;
  // Use mojom::blink::ScrollRestorationType::kAuto unconditionally here
  // because we are certain that we want to actually scroll if we reach this
  // point. Using mojom::blink::ScrollRestorationType::kManual would block the
  // scroll.
  DomWindow()->GetFrame()->Loader().ProcessScrollForSameDocumentNavigation(
      dispatch_params_->url, LoadTypeFromNavigation(navigation_type_),
      view_state, mojom::blink::ScrollRestorationType::kAuto, scroll_behavior);
}

const AtomicString& NavigateEvent::InterfaceName() const {
  return event_interface_names::kNavigateEvent;
}

void NavigateEvent::Trace(Visitor* visitor) const {
  Event::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  visitor->Trace(dispatch_params_);
  visitor->Trace(destination_);
  visitor->Trace(controller_);
  visitor->Trace(signal_);
  visitor->Trace(form_data_);
  visitor->Trace(info_);
  visitor->Trace(source_element_);
  visitor->Trace(navigation_action_promises_list_);
  visitor->Trace(navigation_action_handlers_list_);
}

}  // namespace blink
```