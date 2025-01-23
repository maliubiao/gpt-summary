Response:
Let's break down the thought process for analyzing the `history.cc` file.

1. **Understand the Goal:** The request is to analyze the `history.cc` file in the Chromium Blink engine, identify its functionalities, and connect them to web technologies (JavaScript, HTML, CSS). It also asks for examples of logic, potential errors, and their inputs/outputs.

2. **Initial Scan and Keywords:**  Read through the code, looking for keywords and familiar concepts. Keywords like `History`, `pushState`, `replaceState`, `back`, `forward`, `go`, `state`, `scrollRestoration`, `URL`, `navigation`, `Document`, `Frame`, `Window`, `ExceptionState`, `ScriptValue`, `SerializedScriptValue` immediately stand out. These suggest the file is about managing the browser's history and navigation.

3. **Identify Core Functionalities:** Based on the keywords and function names, start listing the primary responsibilities of this file:

    * **Navigation:**  `back()`, `forward()`, `go()` clearly indicate handling navigation through the browser's history.
    * **State Management:** `pushState()`, `replaceState()`, `state()` deal with manipulating and retrieving state associated with history entries.
    * **History Length:** `length()` provides the number of entries in the history.
    * **Scroll Restoration:** `setScrollRestoration()`, `scrollRestoration()` manage how scroll positions are restored during navigation.
    * **Internal State Tracking:**  Variables like `last_state_object_requested_` and functions like `StateInternal()` hint at internal mechanisms for tracking history state.

4. **Connect to Web Technologies:**  Now, link these functionalities to how they are used in web development:

    * **JavaScript:** The function names are almost identical to the JavaScript `window.history` API. The parameters (`data`, `title`, `url`) of `pushState` and `replaceState` are the same. The return value of `state` is used in JavaScript. This is a very strong connection.
    * **HTML:**  Changes to the history via `pushState` or `replaceState` can update the browser's address bar, which is directly visible to the user in the HTML context. The scroll restoration feature impacts how the user perceives the page after navigation.
    * **CSS:** While not directly manipulating CSS, changes in history *can* trigger JavaScript that modifies CSS. For example, a single-page application might change its layout based on the current history state.

5. **Explain Functionalities with Examples:** Provide concrete examples to illustrate how each function works and its impact.

    * **`length`:**  Simple example showing how the number of history entries changes with navigation.
    * **`state`:** Show how `pushState` can store data and how `state` retrieves it.
    * **`pushState`:**  Demonstrate changing the URL and storing data.
    * **`replaceState`:** Show how it modifies the current history entry.
    * **`back`/`forward`/`go`:** Simple navigation examples.
    * **`scrollRestoration`:** Explain the `auto` and `manual` options.

6. **Identify Logic and Assumptions:** Look for conditional statements and internal logic that might have specific inputs and outputs.

    * **`state` caching:** The code caches the `state` object to avoid unnecessary deserialization. Hypothesize inputs where the cached value is used versus when it's refreshed.
    * **URL handling in `pushState`/`replaceState`:** The code checks if the new URL is valid based on origin. Consider input URLs that are same-origin and cross-origin.
    * **Trivial history:**  The handling of `pushState` in trivial history contexts is a specific logic point. Show an example where `replaceState` is implicitly called.

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using the History API.

    * **Security errors:**  Trying to access `history` from an inactive document or setting a cross-origin URL.
    * **Incorrect data types:**  Passing non-serializable data to `pushState`/`replaceState`.
    * **Rate limiting:**  Excessive calls to history manipulation functions.
    * **Misunderstanding `scrollRestoration`:**  Not realizing the browser's default behavior or how to control it.

8. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Ensure the explanations are easy to understand and the examples are illustrative. Review for clarity and accuracy. For instance, initially, I might just say "handles navigation," but then refine it to be more specific, listing `back`, `forward`, and `go`.

9. **Consider Edge Cases (Self-Correction):** Initially, I might overlook the trivial history case. Rereading the code and comments reveals this specific handling. Similarly, paying closer attention to the security checks leads to the examples of security errors.

By following these steps, we can systematically analyze the `history.cc` file and produce a comprehensive and informative response that addresses all aspects of the original request. The process involves understanding the code's purpose, connecting it to web technologies, providing examples, and anticipating potential issues.
这个 `blink/renderer/core/frame/history.cc` 文件是 Chromium Blink 渲染引擎中负责处理浏览器历史记录的核心组件。它实现了 `window.history` JavaScript API 的底层逻辑，允许网页通过 JavaScript 与用户的浏览历史进行交互。

以下是该文件的主要功能及其与 JavaScript、HTML 和 CSS 的关系，以及可能的逻辑推理和常见错误：

**主要功能：**

1. **管理浏览历史状态:**  它维护和管理当前浏览会话的历史记录，包括访问过的 URL、状态对象和滚动位置等信息。
2. **实现 `window.history` API:** 该文件实现了 `window.history` 对象提供的各种方法和属性，例如 `back()`, `forward()`, `go()`, `pushState()`, `replaceState()`, `length`, `state`, 和 `scrollRestoration`。
3. **处理导航操作:** 它负责处理用户发起的后退、前进和刷新操作，以及通过 JavaScript 调用的历史记录操作。
4. **状态对象管理:** 它允许网页将自定义的状态对象与历史记录条目关联起来，并在导航时恢复这些状态。
5. **滚动位置恢复:** 它负责在后退和前进时恢复页面的滚动位置。
6. **URL 更新:** 当使用 `pushState()` 或 `replaceState()` 时，它会更新浏览器的地址栏 URL，而无需重新加载整个页面。
7. **安全性和权限控制:** 它会检查跨域和安全限制，防止恶意网页操纵浏览历史。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * **直接关联:**  该文件直接实现了 `window.history` API，JavaScript 代码通过这个 API 与浏览历史进行交互。例如，`window.history.pushState({ page: 1 }, "title 1", "?page=1")` 会调用 `History::pushState` 方法。
    * **事件触发:**  `pushState` 和 `replaceState` 不会触发 `popstate` 事件，而后退、前进或 `go()` 会触发 `popstate` 事件，JavaScript 可以监听这个事件来响应历史记录的改变。
    * **`state` 属性:** JavaScript 可以通过 `window.history.state` 属性访问当前历史记录条目的状态对象，该对象由 `History::state` 方法返回。
    * **`scrollRestoration` 属性:** JavaScript 可以通过 `window.history.scrollRestoration` 属性获取或设置滚动恢复行为，这对应于 `History::scrollRestoration` 和 `History::setScrollRestoration` 方法。

    **举例:**
    ```javascript
    // 使用 pushState 添加一个历史记录条目
    window.history.pushState({ page: "home" }, "Homepage", "/");

    // 使用 replaceState 替换当前历史记录条目
    window.history.replaceState({ page: "about" }, "About Us", "/about");

    // 后退
    window.history.back();

    // 前进
    window.history.forward();

    // 跳转到指定历史记录条目
    window.history.go(-2);

    // 获取当前状态对象
    console.log(window.history.state);

    // 设置滚动恢复为手动
    window.history.scrollRestoration = 'manual';

    // 监听 popstate 事件
    window.addEventListener('popstate', function(event) {
      console.log("Location changed!");
      if (event.state) {
        console.log("State:", event.state);
      }
    });
    ```

* **HTML:**
    * **URL 显示:**  `pushState` 和 `replaceState` 修改的 URL 会显示在浏览器的地址栏中。
    * **链接行为:**  传统的 HTML 链接 `<a href="...">` 会导致新的历史记录条目被添加到浏览历史中。

    **举例:**
    一个单页应用 (SPA) 可以使用 `pushState` 来更新地址栏 URL，模拟多页面的导航体验，而无需实际加载新的 HTML 页面。

* **CSS:**
    * **间接影响:**  虽然 `history.cc` 不直接操作 CSS，但历史记录的改变可以触发 JavaScript 代码，而这些 JavaScript 代码可能会修改页面的 CSS 样式。例如，根据不同的历史状态显示或隐藏特定的元素。

    **举例:**
    一个使用 `pushState` 实现标签页功能的 SPA，可以根据当前的 URL（通过 `history.pushState` 更新）来动态修改标签页的样式，高亮当前选中的标签。

**逻辑推理和假设输入与输出：**

* **假设输入:** 用户在浏览器中访问了页面 A，然后通过 JavaScript 执行了 `window.history.pushState({ data: 'pageB' }, 'Page B', '/pageB')`，接着又执行了 `window.history.pushState({ data: 'pageC' }, 'Page C', '/pageC')`。
* **逻辑推理:**  `pushState` 会在浏览历史中添加新的条目。
* **输出:**
    * `history.length` 的值会增加到初始值加 2。
    * 当前的历史记录条目的状态对象为 `{ data: 'pageC' }`。
    * 浏览器的地址栏会显示 `/pageC`。
* **假设输入:**  在上述状态下，用户点击了浏览器的“后退”按钮。
* **逻辑推理:** 浏览器会导航到上一个历史记录条目，并触发 `popstate` 事件。
* **输出:**
    * `history.length` 的值不变。
    * 当前的历史记录条目的状态对象会变为 `{ data: 'pageB' }`。
    * 浏览器的地址栏会显示 `/pageB`。
    * 触发一个 `popstate` 事件，其 `event.state` 属性为 `{ data: 'pageB' }`。

**用户或编程常见的使用错误：**

1. **跨域安全错误:**
    * **错误示例:** 在 `example.com` 的页面中尝试使用 `pushState` 或 `replaceState` 设置一个来自 `another-domain.com` 的 URL。
    * **后果:**  浏览器会抛出一个安全错误，阻止操作。
    * **`ExceptionState` 抛出:**  代码中的 `exception_state.ThrowSecurityError(...)` 会被调用。

2. **在非活动文档中使用 `History` 对象:**
    * **错误示例:** 尝试在一个尚未完全加载或已经卸载的文档中访问 `window.history` 的属性或方法。
    * **后果:**  可能会抛出安全错误或导致未定义的行为。
    * **`ExceptionState` 检查:** 代码中多处检查 `DomWindow()` 的存在，如果为空则会抛出安全错误。

3. **传递不可序列化的状态对象:**
    * **错误示例:**  将包含函数或循环引用的对象传递给 `pushState` 或 `replaceState`。
    * **后果:**  状态对象可能无法正确序列化和反序列化，导致数据丢失或错误。
    * **`SerializedScriptValue::Serialize`:**  此方法负责序列化状态对象，如果序列化失败，`exception_state.HadException()` 会返回 true。

4. **过度频繁地调用 `pushState` 或 `replaceState`:**
    * **错误示例:**  在短时间内大量调用 `pushState` 或 `replaceState`，例如在 `scroll` 事件中每次滚动都调用。
    * **后果:**  可能会导致浏览器性能下降，甚至触发浏览器的速率限制。
    * **`Frame::navigation_rate_limiter()`:**  代码中使用了导航速率限制器来防止滥用历史记录 API。

5. **误解 `pushState` 和 `replaceState` 的行为:**
    * **错误示例:**  认为 `pushState` 会立即导致页面跳转或重新加载。
    * **后果:**  可能导致应用逻辑错误，例如在状态更新后没有正确地更新页面内容。
    * **理解:** `pushState` 和 `replaceState` 只会修改浏览历史和 URL，需要开发者自己编写代码来响应这些变化并更新页面。

6. **忽略 `popstate` 事件:**
    * **错误示例:**  在使用 `pushState` 构建 SPA 时，没有正确监听和处理 `popstate` 事件。
    * **后果:**  当用户点击浏览器的后退或前进按钮时，应用的状态不会同步更新，导致页面显示错误。

7. **在 trivial session history 中使用 `pushState`:**
    * **场景:** 在某些特殊情况下（例如，通过 `<iframe>` 加载某些类型的文档），Blink 可能会使用一个“trivial session history”，它只维护一个历史记录条目。
    * **后果:**  在这种情况下调用 `pushState` 实际上会变成 `replaceState`，并会产生一个控制台警告。
    * **代码逻辑:**  `ShouldMaintainTrivialSessionHistory()` 会检查这种情况，并发出警告并修改 `load_type`。

了解 `blink/renderer/core/frame/history.cc` 的功能对于理解浏览器如何管理浏览历史以及如何正确使用 `window.history` API 至关重要。 开发者需要注意潜在的安全风险和常见的编程错误，以确保网页的导航行为符合预期。

### 提示词
```
这是目录为blink/renderer/core/frame/history.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2007 Apple Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/history.h"

#include <optional>

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/common/scheduler/task_attribution_id.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_restoration.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/history_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/history_item.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_info.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"

namespace blink {

History::History(LocalDOMWindow* window)
    : ExecutionContextClient(window), last_state_object_requested_(nullptr) {}

void History::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

unsigned History::length(ExceptionState& exception_state) const {
  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a History object associated with a Document that is not "
        "fully active");
    return 0;
  }

  return DomWindow()->GetFrame()->Client()->BackForwardLength();
}

ScriptValue History::state(ScriptState* script_state,
                           ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  static const V8PrivateProperty::SymbolKey kHistoryStatePrivateProperty;
  auto private_prop =
      V8PrivateProperty::GetSymbol(isolate, kHistoryStatePrivateProperty);
  v8::Local<v8::Object> v8_history =
      ToV8Traits<History>::ToV8(script_state, this)
          .As<v8::Object>();
  v8::Local<v8::Value> v8_state;

  // Returns the same V8 value unless the history gets updated.  This
  // implementation is mostly the same as the one of [CachedAttribute], but
  // it's placed in this function rather than in Blink-V8 bindings layer so
  // that PopStateEvent.state can also access the same V8 value.
  scoped_refptr<SerializedScriptValue> current_state = StateInternal();
  if (last_state_object_requested_ == current_state) {
    if (!private_prop.GetOrUndefined(v8_history).ToLocal(&v8_state))
      return ScriptValue::CreateNull(isolate);
    if (!v8_state->IsUndefined())
      return ScriptValue(isolate, v8_state);
  }

  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a History object associated with a Document that is "
        "not fully active");
    v8_state = v8::Null(isolate);
  } else if (!current_state) {
    v8_state = v8::Null(isolate);
  } else {
    ScriptState::EscapableScope target_context_scope(script_state);
    v8_state = target_context_scope.Escape(current_state->Deserialize(isolate));
  }

  last_state_object_requested_ = current_state;
  private_prop.Set(v8_history, v8_state);
  return ScriptValue(isolate, v8_state);
}

SerializedScriptValue* History::StateInternal() const {
  if (HistoryItem* history_item = GetHistoryItem())
    return history_item->StateObject();
  return nullptr;
}

void History::setScrollRestoration(const V8ScrollRestoration& value,
                                   ExceptionState& exception_state) {
  HistoryItem* item = GetHistoryItem();
  if (!item) {
    exception_state.ThrowSecurityError(
        "May not use a History object associated with a Document that is not "
        "fully active");
    return;
  }

  mojom::blink::ScrollRestorationType scroll_restoration =
      value.AsEnum() == V8ScrollRestoration::Enum::kManual
          ? mojom::blink::ScrollRestorationType::kManual
          : mojom::blink::ScrollRestorationType::kAuto;
  if (scroll_restoration == ScrollRestorationInternal())
    return;

  item->SetScrollRestorationType(scroll_restoration);
  DomWindow()->GetFrame()->Client()->DidUpdateCurrentHistoryItem();
}

V8ScrollRestoration History::scrollRestoration(
    ExceptionState& exception_state) {
  if (!DomWindow()) {
    exception_state.ThrowSecurityError(
        "May not use a History object associated with a Document that is not "
        "fully active");
    return V8ScrollRestoration(V8ScrollRestoration::Enum::kAuto);
  }
  return V8ScrollRestoration(
      ScrollRestorationInternal() ==
              mojom::blink::ScrollRestorationType::kManual
          ? V8ScrollRestoration::Enum::kManual
          : V8ScrollRestoration::Enum::kAuto);
}

mojom::blink::ScrollRestorationType History::ScrollRestorationInternal() const {
  if (HistoryItem* history_item = GetHistoryItem())
    return history_item->ScrollRestorationType();
  return mojom::blink::ScrollRestorationType::kAuto;
}

HistoryItem* History::GetHistoryItem() const {
  return DomWindow() ? DomWindow()->document()->Loader()->GetHistoryItem()
                     : nullptr;
}

bool History::IsSameAsCurrentState(SerializedScriptValue* state) const {
  return state == StateInternal();
}

void History::back(ScriptState* script_state, ExceptionState& exception_state) {
  go(script_state, -1, exception_state);
}

void History::forward(ScriptState* script_state,
                      ExceptionState& exception_state) {
  go(script_state, 1, exception_state);
}

void History::go(ScriptState* script_state,
                 int delta,
                 ExceptionState& exception_state) {
  LocalDOMWindow* window = DomWindow();
  if (!window) {
    exception_state.ThrowSecurityError(
        "May not use a History object associated with a Document that is not "
        "fully active");
    return;
  }
  LocalFrame* frame = window->GetFrame();
  DCHECK(frame);

  if (!frame->IsNavigationAllowed())
    return;

  DCHECK(IsMainThread());

  if (!frame->navigation_rate_limiter().CanProceed())
    return;

  // TODO(crbug.com/1262022): Remove this condition when Fenced Frames
  // transition to MPArch completely.
  if (frame->IsInFencedFrameTree())
    return;

  if (delta) {
    // Set up propagating the current task state to the navigation commit.
    std::optional<scheduler::TaskAttributionId> soft_navigation_task_id;
    if (script_state->World().IsMainWorld() && frame->IsOutermostMainFrame()) {
      if (auto* heuristics = SoftNavigationHeuristics::From(*window)) {
        soft_navigation_task_id =
            heuristics->AsyncSameDocumentNavigationStarted();
      }
    }
    DCHECK(frame->Client());
    if (frame->Client()->NavigateBackForward(delta, soft_navigation_task_id)) {
      if (Page* page = frame->GetPage())
        page->HistoryNavigationVirtualTimePauser().PauseVirtualTime();
    }
  } else {
    // We intentionally call reload() for the current frame if delta is zero.
    // Otherwise, navigation happens on the root frame.
    // This behavior is designed in the following spec.
    // https://html.spec.whatwg.org/C/#dom-history-go
    frame->Reload(WebFrameLoadType::kReload);
  }
}

void History::pushState(ScriptState* script_state,
                        const ScriptValue& data,
                        const String& title,
                        const String& url,
                        ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  WebFrameLoadType load_type = WebFrameLoadType::kStandard;
  if (LocalDOMWindow* window = DomWindow()) {
    DCHECK(window->GetFrame());
    if (window->GetFrame()->ShouldMaintainTrivialSessionHistory()) {
      window->AddConsoleMessage(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kJavaScript,
              mojom::blink::ConsoleMessageLevel::kWarning,
              "Use of history.pushState in a trivial session history context, "
              "which maintains only one session history entry, is treated as "
              "history.replaceState."),
          /* discard_duplicates */ true);
      load_type = WebFrameLoadType::kReplaceCurrentItem;
    }
  }

  scoped_refptr<SerializedScriptValue> serialized_data =
      SerializedScriptValue::Serialize(isolate, data.V8Value(),
                                       SerializedScriptValue::SerializeOptions(
                                           SerializedScriptValue::kForStorage),
                                       exception_state);
  if (exception_state.HadException())
    return;

  StateObjectAdded(std::move(serialized_data), title, url, load_type,
                   script_state, exception_state);
}

void History::replaceState(ScriptState* script_state,
                           const ScriptValue& data,
                           const String& title,
                           const String& url,
                           ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();
  scoped_refptr<SerializedScriptValue> serialized_data =
      SerializedScriptValue::Serialize(isolate, data.V8Value(),
                                       SerializedScriptValue::SerializeOptions(
                                           SerializedScriptValue::kForStorage),
                                       exception_state);
  if (exception_state.HadException())
    return;

  StateObjectAdded(std::move(serialized_data), title, url,
                   WebFrameLoadType::kReplaceCurrentItem, script_state,
                   exception_state);
}

KURL History::UrlForState(const String& url_string) {
  if (url_string.IsNull())
    return DomWindow()->Url();
  if (url_string.empty())
    return DomWindow()->BaseURL();

  return KURL(DomWindow()->BaseURL(), url_string);
}

void History::StateObjectAdded(scoped_refptr<SerializedScriptValue> data,
                               const String& /* title */,
                               const String& url_string,
                               WebFrameLoadType type,
                               ScriptState* script_state,
                               ExceptionState& exception_state) {
  LocalDOMWindow* window = DomWindow();
  if (!window) {
    exception_state.ThrowSecurityError(
        "May not use a History object associated with a Document that is not "
        "fully active");
    return;
  }

  KURL full_url = UrlForState(url_string);
  bool can_change = CanChangeToUrlForHistoryApi(
      full_url, window->GetSecurityOrigin(), window->Url());

  if (window->GetSecurityOrigin()->IsGrantedUniversalAccess()) {
    // Log the case when 'pushState'/'replaceState' is allowed only because
    // of IsGrantedUniversalAccess ie there is no other condition which should
    // allow the change (!can_change).
    base::UmaHistogramBoolean(
        "Android.WebView.UniversalAccess.OriginUrlMismatchInHistoryUtil",
        !can_change);
    can_change = true;
  }

  if (!can_change) {
    // We can safely expose the URL to JavaScript, as a) no redirection takes
    // place: JavaScript already had this URL, b) JavaScript can only access a
    // same-origin History object.
    exception_state.ThrowSecurityError(
        "A history state object with URL '" + full_url.ElidedString() +
        "' cannot be created in a document with origin '" +
        window->GetSecurityOrigin()->ToString() + "' and URL '" +
        window->Url().ElidedString() + "'.");
    return;
  }

  if (!window->GetFrame()->navigation_rate_limiter().CanProceed()) {
    // TODO(769592): Get an API spec change so that we can throw an exception:
    //
    //  exception_state.ThrowDOMException(DOMExceptionCode::kQuotaExceededError,
    //                                    "Throttling history state changes to "
    //                                    "prevent the browser from hanging.");
    //
    // instead of merely warning.
    return;
  }

  auto* params = MakeGarbageCollected<NavigateEventDispatchParams>(
      full_url, NavigateEventType::kHistoryApi, type);
  params->state_object = data.get();
  if (window->navigation()->DispatchNavigateEvent(params) !=
      NavigationApi::DispatchResult::kContinue) {
    return;
  }

  window->document()->Loader()->RunURLAndHistoryUpdateSteps(
      full_url, nullptr, mojom::blink::SameDocumentNavigationType::kHistoryApi,
      std::move(data), type, FirePopstate::kNo);
}

}  // namespace blink
```