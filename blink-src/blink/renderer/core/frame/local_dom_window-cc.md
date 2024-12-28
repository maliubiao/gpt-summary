Response:
The user wants to understand the functionality of the `local_dom_window.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and identify its core responsibilities. The request also asks for connections to Javascript, HTML, and CSS, along with examples, logical reasoning with input/output, and common usage errors. Finally, the user wants a summary of the functionalities in this first part of the file.

**Plan:**

1. **Identify Core Functionalities:** Scan the code for class declarations, method implementations, and key data members to understand the primary responsibilities of `LocalDOMWindow`.
2. **Relate to Web Technologies:**  Look for code sections that interact with Javascript (script execution, event handling), HTML (DOM manipulation, document context), and CSS (style resolution, media queries).
3. **Provide Examples:**  For each identified relationship, construct a simple example demonstrating the interaction.
4. **Infer Logical Reasoning:**  If the code snippet shows clear conditional logic or data processing, try to deduce the input and output.
5. **Identify Potential Errors:** Consider common programming or user mistakes that could arise from interacting with the functionalities of `LocalDOMWindow`.
6. **Summarize Functionalities:** Condense the identified functionalities into a concise summary.
这是 `blink/renderer/core/frame/local_dom_window.cc` 文件的前一部分代码，它定义了 `LocalDOMWindow` 类。 从这部分代码来看，`LocalDOMWindow` 的主要功能是：

**核心功能归纳：**

1. **代表一个浏览上下文（Window）：** `LocalDOMWindow` 是 Blink 中用于表示浏览器窗口的 C++ 类。它关联着一个 `LocalFrame`，并作为 Javascript 代码执行的全局对象（`window` 对象）在渲染进程中的表示。
2. **管理脚本执行环境：** 它负责初始化和管理与 Javascript 相关的组件，例如 `ScriptController` (控制脚本的执行)，以及提供访问 V8 隔离环境的能力。
3. **处理文档和帧的生命周期：** 它与 `Document` 对象关联，并在文档加载和卸载过程中执行相应的操作，例如清除资源和重置状态。
4. **处理窗口相关的事件：**  它负责分发和处理与窗口相关的事件，例如 `online`、`offline` 和 `languagechange`。
5. **提供对浏览器功能的访问：** 它通过成员变量和方法，提供对浏览器各种功能的访问，例如导航 (`History`)、屏幕信息 (`Screen`)、用户代理 (`Navigator`)、以及 CSS 相关的功能。
6. **管理安全策略：**  它负责处理内容安全策略 (CSP) 和其他安全相关的机制，以控制页面中的资源加载和脚本执行。
7. **提供性能监控接口：**  它关联着 `WindowPerformance` 对象，用于提供性能监控数据。
8. **处理帧间通信：** 虽然这部分代码没有直接体现，但 `LocalDOMWindow` 在帧间通信中扮演着关键角色。
9. **支持扩展和调试：** 它为浏览器扩展和开发者工具提供了必要的接口和功能。

**与 Javascript, HTML, CSS 的关系及举例说明：**

1. **Javascript:**
    * **全局对象：** `LocalDOMWindow` 实例在 Javascript 中表现为 `window` 对象。你可以通过 `window.someProperty` 或 `window.someMethod()` 来访问其属性和方法。
        * **例子：** Javascript 代码 `console.log(window.location.href);`  会访问 `LocalDOMWindow` 提供的 `location` 属性来获取当前页面的 URL。
    * **事件处理：** Javascript 可以通过 `addEventListener` 监听 `LocalDOMWindow` 上发生的事件。
        * **例子：**  Javascript 代码 `window.addEventListener('load', function() { console.log('页面加载完成'); });`  监听 `LocalDOMWindow` 的 `load` 事件。
    * **API 提供：** `LocalDOMWindow` 提供了大量的 Web API，供 Javascript 调用。
        * **例子：** Javascript 代码 `window.setTimeout(function() { alert('Hello'); }, 1000);` 使用了 `LocalDOMWindow` 提供的 `setTimeout` API。
    * **脚本执行控制：** `ScriptController` 负责执行页面中的 Javascript 代码，这部分由 `LocalDOMWindow` 管理。

2. **HTML:**
    * **文档上下文：** `LocalDOMWindow` 关联着一个 `Document` 对象，它是 HTML 文档在内存中的表示。Javascript 可以通过 `window.document` 访问这个对象，并操作 HTML 结构。
        * **例子：** Javascript 代码 `let title = window.document.title;`  通过 `LocalDOMWindow` 的 `document` 属性访问 HTML 文档的标题。
    * **帧 (Frames)：**  当 HTML 包含 `<iframe>` 等标签时，会创建新的浏览上下文，每个上下文对应一个 `LocalDOMWindow` 实例。
        * **例子：** 如果页面包含一个 ID 为 `myFrame` 的 `<iframe>`， Javascript 可以通过 `window.frames['myFrame'].contentWindow` 访问到该 `<iframe>` 内部的 `LocalDOMWindow` 对象。

3. **CSS:**
    * **样式访问：** `LocalDOMWindow` 提供了访问和操作 CSS 样式的功能。
        * **例子：** Javascript 代码 `let bodyStyle = window.getComputedStyle(document.body);` 使用 `LocalDOMWindow` 提供的 `getComputedStyle` 方法获取 `<body>` 元素的最终样式。
    * **媒体查询：**  `MediaQueryList` 和 `MediaQueryMatcher` 与 `LocalDOMWindow` 关联，允许 Javascript 查询当前的媒体查询状态。
        * **例子：** Javascript 代码 `if (window.matchMedia('(max-width: 600px)').matches) { console.log('屏幕小于 600px'); }` 使用 `LocalDOMWindow` 的 `matchMedia` 方法检查媒体查询是否匹配。

**逻辑推理与假设输入输出：**

* **假设输入：**  Javascript 代码调用 `window.open('https://example.com', '_blank');`
* **逻辑推理：** `LocalDOMWindow` 的相关方法（虽然这部分代码未完全展示 `window.open` 的实现）会调用 Blink 内部的机制去创建一个新的浏览上下文和对应的 `LocalDOMWindow` 实例，并加载 `https://example.com`。
* **输出：**  一个新的浏览器窗口或标签页被打开，显示 `https://example.com` 的内容。

* **假设输入：**  网络状态从断开变为连接。
* **逻辑推理：** `NetworkStateObserver` 检测到网络状态变化，并调用 `LocalDOMWindow::DispatchEvent` 方法。
* **输出：**  `LocalDOMWindow` 会分发一个 `online` 事件，Javascript 可以监听并执行相应的处理逻辑。

**用户或编程常见的使用错误：**

1. **在不正确的上下文中访问 `window` 对象：**  在 Service Workers 或 Web Workers 等环境中，`window` 对象并不总是存在，尝试访问会导致错误。
    * **例子：** 在 Service Worker 脚本中直接使用 `window.location` 会导致 `ReferenceError: window is not defined`。
2. **误解 `this` 关键字在事件处理函数中的指向：** 在某些情况下，事件处理函数中的 `this` 关键字可能不会指向 `LocalDOMWindow`，需要注意绑定或使用箭头函数。
3. **不正确地使用跨域的 `window` 对象：**  由于安全限制，Javascript 无法直接访问不同源的 `LocalDOMWindow` 对象的属性和方法，除非进行了特定的跨域配置。
    * **例子：**  在一个 `iframe` 中，尝试从父窗口访问 `parent.someVariable`，如果父窗口和 `iframe` 的源不同，可能会抛出安全错误。
4. **忘记清理事件监听器导致内存泄漏：**  如果在一个 `LocalDOMWindow` 对象被销毁后，仍然有 Javascript 代码持有对其事件监听器的引用，可能会导致内存泄漏。

**总结：**

总而言之，`blink/renderer/core/frame/local_dom_window.cc` 的这部分代码定义了 `LocalDOMWindow` 类，它是 Blink 渲染引擎中代表浏览器窗口的核心组件。它负责管理脚本执行环境、处理窗口生命周期和事件、提供对浏览器功能的访问、管理安全策略以及提供性能监控接口。 它与 Javascript、HTML 和 CSS 紧密相关，是前端开发中 `window` 对象的底层实现。

Prompt: 
```
这是目录为blink/renderer/core/frame/local_dom_window.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2008, 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
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

#include "third_party/blink/renderer/core/frame/local_dom_window.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/containers/contains.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_id_helper.h"
#include "base/trace_event/typed_macros.h"
#include "build/build_config.h"
#include "cc/input/snap_selection_strategy.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/storage_access_api/status.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/navigation/impression.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions_policy/policy_disposition.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/web_agent_group_scheduler.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_picture_in_picture_window_options.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_to_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_void_function.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy_manager.h"
#include "third_party/blink/renderer/core/accessibility/ax_context.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/dom_window_css.h"
#include "third_party/blink/renderer/core/css/media_query_list.h"
#include "third_party/blink/renderer/core/css/media_query_matcher.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_media.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/frame_request_callback_collection.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/suggestion/text_suggestion_controller.h"
#include "third_party/blink/renderer/core/events/hash_change_event.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/events/page_transition_event.h"
#include "third_party/blink/renderer/core/events/pop_state_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/core/execution_context/window_agent.h"
#include "third_party/blink/renderer/core/frame/attribution_src_loader.h"
#include "third_party/blink/renderer/core/frame/bar_prop.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/document_policy_violation_report_body.h"
#include "third_party/blink/renderer/core/frame/dom_viewport.h"
#include "third_party/blink/renderer/core/frame/dom_visual_viewport.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/external.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/history.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/permissions_policy_violation_report_body.h"
#include "third_party/blink/renderer/core/frame/report.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fence.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_storage.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/create_window.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/sync_scroll_attempt_heuristic.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scheduler/scripted_idle_task_controller.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_type_policy_factory.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/platform/back_forward_cache_buffer_limit_tracker.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/blob/blob_url.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/dummy_schedulers.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/storage/blink_storage_key.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"
#include "ui/display/screen_info.h"
#include "v8/include/v8.h"

namespace blink {

namespace {
bool IsRunningMicrotasks(ScriptState* script_state) {
  if (auto* microtask_queue = ToMicrotaskQueue(script_state))
    return microtask_queue->IsRunningMicrotasks();
  return v8::MicrotasksScope::IsRunningMicrotasks(script_state->GetIsolate());
}

void SetCurrentTaskAsCallbackParent(
    CallbackFunctionWithTaskAttributionBase* callback) {
  ScriptState* script_state = callback->CallbackRelevantScriptState();
  auto* tracker =
      scheduler::TaskAttributionTracker::From(script_state->GetIsolate());
  if (tracker && script_state->World().IsMainWorld()) {
    callback->SetParentTask(tracker->RunningTask());
  }
}

int RequestAnimationFrame(Document* document,
                          V8FrameRequestCallback* callback,
                          bool legacy) {
  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidRequestAnimationFrame();
  SetCurrentTaskAsCallbackParent(callback);
  auto* frame_callback = MakeGarbageCollected<V8FrameCallback>(callback);
  frame_callback->SetUseLegacyTimeBase(legacy);
  return document->RequestAnimationFrame(frame_callback);
}

}  // namespace

class LocalDOMWindow::NetworkStateObserver final
    : public GarbageCollected<LocalDOMWindow::NetworkStateObserver>,
      public NetworkStateNotifier::NetworkStateObserver,
      public ExecutionContextLifecycleObserver {
 public:
  explicit NetworkStateObserver(ExecutionContext* context)
      : ExecutionContextLifecycleObserver(context) {}

  void Initialize() {
    online_observer_handle_ = GetNetworkStateNotifier().AddOnLineObserver(
        this, GetExecutionContext()->GetTaskRunner(TaskType::kNetworking));
  }

  void OnLineStateChange(bool on_line) override {
    AtomicString event_name =
        on_line ? event_type_names::kOnline : event_type_names::kOffline;
    auto* window = To<LocalDOMWindow>(GetExecutionContext());
    window->DispatchEvent(*Event::Create(event_name));
  }

  void ContextDestroyed() override { online_observer_handle_ = nullptr; }

  void Trace(Visitor* visitor) const override {
    ExecutionContextLifecycleObserver::Trace(visitor);
  }

 private:
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle>
      online_observer_handle_;
};

LocalDOMWindow::LocalDOMWindow(LocalFrame& frame, WindowAgent* agent)
    : DOMWindow(frame),
      ExecutionContext(agent->isolate(),
                       agent,
                       /*Same value as IsWindow(). is_window=*/true),
      script_controller_(MakeGarbageCollected<ScriptController>(
          *this,
          *static_cast<LocalWindowProxyManager*>(
              frame.GetWindowProxyManager()))),
      viewport_(MakeGarbageCollected<DOMViewport>(this)),
      visualViewport_(MakeGarbageCollected<DOMVisualViewport>(this)),
      should_print_when_finished_loading_(false),
      input_method_controller_(
          MakeGarbageCollected<InputMethodController>(*this, frame)),
      spell_checker_(MakeGarbageCollected<SpellChecker>(*this)),
      text_suggestion_controller_(
          MakeGarbageCollected<TextSuggestionController>(*this)),
      isolated_world_csp_map_(
          MakeGarbageCollected<
              HeapHashMap<int, Member<ContentSecurityPolicy>>>()),
      token_(frame.GetLocalFrameToken()),
      network_state_observer_(MakeGarbageCollected<NetworkStateObserver>(this)),
      closewatcher_stack_(
          MakeGarbageCollected<CloseWatcher::WatcherStack>(this)),
      navigation_id_(WTF::CreateCanonicalUUIDString()) {}

void LocalDOMWindow::BindContentSecurityPolicy() {
  DCHECK(!GetContentSecurityPolicy()->IsBound());
  GetContentSecurityPolicy()->BindToDelegate(
      GetContentSecurityPolicyDelegate());
}

void LocalDOMWindow::Initialize() {
  GetAgent()->AttachContext(this);
  network_state_observer_->Initialize();
}

void LocalDOMWindow::ClearForReuse() {
  is_dom_window_reused_ = true;
  // update event listener counts before clearing document_
  if (document_ && HasEventListeners()) {
    GetEventTargetData()->event_listener_map.ForAllEventListenerTypes(
        [this](const AtomicString& event_type, uint32_t count) {
          document_->DidRemoveEventListeners(count);
        });
  }
  document_ = nullptr;
}

void LocalDOMWindow::ResetWindowAgent(WindowAgent* agent) {
  GetAgent()->DetachContext(this);
  ResetAgent(agent);
  if (document_) {
    document_->ResetAgent(*agent);
  }

  CHECK(GetFrame());
  GetFrame()->GetFrameScheduler()->SetAgentClusterId(GetAgentClusterID());

  // This is only called on Android WebView, we need to reassign the microtask
  // queue if there already is one for the associated context. There shouldn't
  // be any other worlds with Android WebView so using the MainWorld is fine.
  auto* microtask_queue = agent->event_loop()->microtask_queue();
  if (microtask_queue) {
    v8::HandleScope handle_scope(GetIsolate());
    v8::Local<v8::Context> main_world_context = ToV8ContextMaybeEmpty(
        GetFrame(), DOMWrapperWorld::MainWorld(GetIsolate()));
    if (!main_world_context.IsEmpty())
      main_world_context->SetMicrotaskQueue(microtask_queue);
  }

  GetAgent()->AttachContext(this);
}

void LocalDOMWindow::AcceptLanguagesChanged() {
  if (navigator_)
    navigator_->SetLanguagesDirty();

  DispatchEvent(*Event::Create(event_type_names::kLanguagechange));
}

ScriptValue LocalDOMWindow::event(ScriptState* script_state) {
  // If current event is null, return undefined.
  if (!current_event_) {
    return ScriptValue(script_state->GetIsolate(),
                       v8::Undefined(script_state->GetIsolate()));
  }

  return ScriptValue(script_state->GetIsolate(),
                     ToV8Traits<Event>::ToV8(script_state, CurrentEvent()));
}

Event* LocalDOMWindow::CurrentEvent() const {
  return current_event_.Get();
}

void LocalDOMWindow::SetCurrentEvent(Event* new_event) {
  current_event_ = new_event;
}

TrustedTypePolicyFactory* LocalDOMWindow::GetTrustedTypesForWorld(
    const DOMWrapperWorld& world) const {
  DCHECK(world.IsMainWorld() || world.IsIsolatedWorld());
  DCHECK(IsMainThread());
  auto iter = trusted_types_map_.find(&world);
  if (iter != trusted_types_map_.end())
    return iter->value.Get();
  return trusted_types_map_
      .insert(&world, MakeGarbageCollected<TrustedTypePolicyFactory>(
                          GetExecutionContext()))
      .stored_value->value;
}

TrustedTypePolicyFactory* LocalDOMWindow::trustedTypes(
    ScriptState* script_state) const {
  return GetTrustedTypesForWorld(script_state->World());
}

bool LocalDOMWindow::IsCrossSiteSubframe() const {
  if (!GetFrame())
    return false;
  if (GetFrame()->IsInFencedFrameTree())
    return true;
  // It'd be nice to avoid the url::Origin temporaries, but that would require
  // exposing the net internal helper.
  // TODO: If the helper gets exposed, we could do this without any new
  // allocations using StringUTF8Adaptor.
  auto* top_origin =
      GetFrame()->Tree().Top().GetSecurityContext()->GetSecurityOrigin();
  return !net::registry_controlled_domains::SameDomainOrHost(
      top_origin->ToUrlOrigin(), GetSecurityOrigin()->ToUrlOrigin(),
      net::registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES);
}

bool LocalDOMWindow::IsCrossSiteSubframeIncludingScheme() const {
  if (!GetFrame())
    return false;
  if (GetFrame()->IsInFencedFrameTree())
    return true;
  return top()->GetFrame() &&
         !top()
              ->GetFrame()
              ->GetSecurityContext()
              ->GetSecurityOrigin()
              ->IsSameSiteWith(GetSecurityContext().GetSecurityOrigin());
}

LocalDOMWindow* LocalDOMWindow::From(const ScriptState* script_state) {
  return blink::ToLocalDOMWindow(script_state);
}

mojom::blink::V8CacheOptions LocalDOMWindow::GetV8CacheOptions() const {
  if (LocalFrame* frame = GetFrame()) {
    if (const Settings* settings = frame->GetSettings())
      return settings->GetV8CacheOptions();
  }

  return mojom::blink::V8CacheOptions::kDefault;
}

bool LocalDOMWindow::IsContextThread() const {
  return IsMainThread();
}

bool LocalDOMWindow::ShouldInstallV8Extensions() const {
  return GetFrame()->Client()->AllowScriptExtensions();
}

ContentSecurityPolicy* LocalDOMWindow::GetContentSecurityPolicyForWorld(
    const DOMWrapperWorld* world) {
  if (!world || !world->IsIsolatedWorld())
    return GetContentSecurityPolicy();

  int32_t world_id = world->GetWorldId();
  auto it = isolated_world_csp_map_->find(world_id);
  if (it != isolated_world_csp_map_->end())
    return it->value.Get();

  ContentSecurityPolicy* policy =
      IsolatedWorldCSP::Get().CreateIsolatedWorldCSP(*this, world_id);
  if (!policy)
    return GetContentSecurityPolicy();

  isolated_world_csp_map_->insert(world_id, policy);
  return policy;
}

const KURL& LocalDOMWindow::Url() const {
  return document()->Url();
}

const KURL& LocalDOMWindow::BaseURL() const {
  return document()->BaseURL();
}

KURL LocalDOMWindow::CompleteURL(const String& url) const {
  return document()->CompleteURL(url);
}

void LocalDOMWindow::DisableEval(const String& error_message) {
  GetScriptController().DisableEval(error_message);
}

void LocalDOMWindow::SetWasmEvalErrorMessage(const String& error_message) {
  GetScriptController().SetWasmEvalErrorMessage(error_message);
}

String LocalDOMWindow::UserAgent() const {
  if (!GetFrame())
    return String();

  return GetFrame()->Loader().UserAgent();
}

UserAgentMetadata LocalDOMWindow::GetUserAgentMetadata() const {
  return GetFrame()->Loader().UserAgentMetadata().value_or(
      blink::UserAgentMetadata());
}

HttpsState LocalDOMWindow::GetHttpsState() const {
  // TODO(https://crbug.com/880986): Implement Document's HTTPS state in more
  // spec-conformant way.
  return CalculateHttpsState(GetSecurityOrigin());
}

ResourceFetcher* LocalDOMWindow::Fetcher() {
  return document()->Fetcher();
}

bool LocalDOMWindow::CanExecuteScripts(
    ReasonForCallingCanExecuteScripts reason) {
  if (!GetFrame()) {
    return false;
  }

  // Detached frames should not be attempting to execute script.
  DCHECK(!GetFrame()->IsDetached());

  // Normally, scripts are not allowed in sandboxed contexts that disallow them.
  // However, there is an exception for cases when the script should bypass the
  // main world's CSP (such as for privileged isolated worlds). See
  // https://crbug.com/811528.
  if (IsSandboxed(network::mojom::blink::WebSandboxFlags::kScripts) &&
      !ContentSecurityPolicy::ShouldBypassMainWorldDeprecated(this)) {
    // FIXME: This message should be moved off the console once a solution to
    // https://bugs.webkit.org/show_bug.cgi?id=103274 exists.
    if (reason == kAboutToExecuteScript) {
      AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kSecurity,
          mojom::blink::ConsoleMessageLevel::kError,
          "Blocked script execution in '" + Url().ElidedString() +
              "' because the document's frame is sandboxed and the "
              "'allow-scripts' permission is not set."));
    }
    return false;
  }
  bool script_enabled = GetFrame()->ScriptEnabled();
  if (!script_enabled && reason == kAboutToExecuteScript) {
    WebContentSettingsClient* settings_client =
        GetFrame()->GetContentSettingsClient();
    if (settings_client) {
      settings_client->DidNotAllowScript();
    }
  }
  return script_enabled;
}

String LocalDOMWindow::CheckAndGetJavascriptUrl(
    const DOMWrapperWorld* world,
    const KURL& url,
    Element* element,
    network::mojom::CSPDisposition csp_disposition) {
  const int kJavascriptSchemeLength = sizeof("javascript:") - 1;
  String decoded_url = DecodeURLEscapeSequences(
      url.GetString(), DecodeURLMode::kUTF8OrIsomorphic);
  String script_source = decoded_url.Substring(kJavascriptSchemeLength);

  if (csp_disposition == network::mojom::CSPDisposition::DO_NOT_CHECK)
    return script_source;

  // Check the CSP of the caller (the "source browsing context") if required,
  // as per https://html.spec.whatwg.org/C/#javascript-protocol.
  if (!GetContentSecurityPolicyForWorld(world)->AllowInline(
          ContentSecurityPolicy::InlineType::kNavigation, element, decoded_url,
          String() /* nonce */, Url(), OrdinalNumber::First()))
    return String();

  // TODO(crbug.com/896041): Investigate how trusted type checks can be
  // implemented for isolated worlds.
  if (ContentSecurityPolicy::ShouldBypassMainWorldDeprecated(world))
    return script_source;

  // https://w3c.github.io/trusted-types/dist/spec/#require-trusted-types-for-pre-navigation-check
  // 4.9.1.1. require-trusted-types-for Pre-Navigation check
  script_source =
      TrustedTypesCheckForJavascriptURLinNavigation(script_source, this);

  return script_source;
}

void LocalDOMWindow::ExceptionThrown(ErrorEvent* event) {
  MainThreadDebugger::Instance(GetIsolate())->ExceptionThrown(this, event);
}

// https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer
String LocalDOMWindow::OutgoingReferrer() const {
  // Step 3.1: "If environment's global object is a Window object, then"
  // Step 3.1.1: "Let document be the associated Document of environment's
  // global object."

  // Step 3.1.2: "If document's origin is an opaque origin, return no referrer."
  if (GetSecurityOrigin()->IsOpaque())
    return String();

  // Step 3.1.3: "While document is an iframe srcdoc document, let document be
  // document's browsing context's browsing context container's node document."
  Document* referrer_document = document();
  if (LocalFrame* frame = GetFrame()) {
    while (frame->GetDocument()->IsSrcdocDocument()) {
      // Srcdoc documents must be local within the containing frame.
      frame = To<LocalFrame>(frame->Tree().Parent());
      // Srcdoc documents cannot be top-level documents, by definition,
      // because they need to be contained in iframes with the srcdoc.
      DCHECK(frame);
    }
    referrer_document = frame->GetDocument();
  }

  // Step: 3.1.4: "Let referrerSource be document's URL."
  return referrer_document->Url().StrippedForUseAsReferrer();
}

CoreProbeSink* LocalDOMWindow::GetProbeSink() {
  return probe::ToCoreProbeSink(GetFrame());
}

const BrowserInterfaceBrokerProxy& LocalDOMWindow::GetBrowserInterfaceBroker()
    const {
  if (!GetFrame())
    return GetEmptyBrowserInterfaceBroker();

  return GetFrame()->GetBrowserInterfaceBroker();
}

FrameOrWorkerScheduler* LocalDOMWindow::GetScheduler() {
  if (GetFrame())
    return GetFrame()->GetFrameScheduler();
  if (!detached_scheduler_)
    detached_scheduler_ = scheduler::CreateDummyFrameScheduler(GetIsolate());
  return detached_scheduler_.get();
}

scoped_refptr<base::SingleThreadTaskRunner> LocalDOMWindow::GetTaskRunner(
    TaskType type) {
  if (GetFrame())
    return GetFrame()->GetTaskRunner(type);
  TRACE_EVENT_INSTANT("blink",
                      "LocalDOMWindow::GetTaskRunner_ThreadTaskRunner");
  // In most cases, the ExecutionContext will get us to a relevant Frame. In
  // some cases, though, there isn't a good candidate (most commonly when either
  // the passed-in document or the ExecutionContext used to be attached to a
  // Frame but has since been detached) so we will use the default task runner
  // of the AgentGroupScheduler that created this window.
  return To<WindowAgent>(GetAgent())
      ->GetAgentGroupScheduler()
      .DefaultTaskRunner();
}

void LocalDOMWindow::ReportPermissionsPolicyViolation(
    mojom::blink::PermissionsPolicyFeature feature,
    mojom::blink::PolicyDisposition disposition,
    const std::optional<String>& reporting_endpoint,
    const String& message) const {
  if (disposition == mojom::blink::PolicyDisposition::kEnforce) {
    const_cast<LocalDOMWindow*>(this)->CountPermissionsPolicyUsage(
        feature, UseCounterImpl::PermissionsPolicyUsageType::kViolation);
  }

  if (!GetFrame()) {
    return;
  }

  // Construct the permissions policy violation report.
  bool is_isolated_context =
      GetExecutionContext() && GetExecutionContext()->IsIsolatedContext();
  const String& feature_name = GetNameForFeature(feature, is_isolated_context);
  const String& disp_str =
      (disposition == mojom::blink::PolicyDisposition::kReport ? "report"
                                                               : "enforce");

  PermissionsPolicyViolationReportBody* body =
      MakeGarbageCollected<PermissionsPolicyViolationReportBody>(
          feature_name, message, disp_str);

  Report* report = MakeGarbageCollected<Report>(
      ReportType::kPermissionsPolicyViolation, Url().GetString(), body);

  // Send the permissions policy violation report to the specified endpoint,
  // if one exists, as well as any ReportingObservers.
  if (reporting_endpoint) {
    ReportingContext::From(this)->QueueReport(report, {*reporting_endpoint});
  } else {
    ReportingContext::From(this)->QueueReport(report);
  }

  // TODO(iclelland): Report something different in report-only mode
  if (disposition == mojom::blink::PolicyDisposition::kEnforce) {
    GetFrame()->Console().AddMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kViolation,
        mojom::blink::ConsoleMessageLevel::kError, body->message()));
  }
}

void LocalDOMWindow::ReportDocumentPolicyViolation(
    mojom::blink::DocumentPolicyFeature feature,
    mojom::blink::PolicyDisposition disposition,
    const String& message,
    const String& source_file) const {
  if (!GetFrame())
    return;

  // Construct the document policy violation report.
  const String& feature_name =
      GetDocumentPolicyFeatureInfoMap().at(feature).feature_name.c_str();
  bool is_report_only = disposition == mojom::blink::PolicyDisposition::kReport;
  const String& disp_str = is_report_only ? "report" : "enforce";
  const DocumentPolicy* relevant_document_policy =
      is_report_only ? GetSecurityContext().GetReportOnlyDocumentPolicy()
                     : GetSecurityContext().GetDocumentPolicy();

  DocumentPolicyViolationReportBody* body =
      MakeGarbageCollected<DocumentPolicyViolationReportBody>(
          feature_name, message, disp_str, source_file);

  Report* report = MakeGarbageCollected<Report>(
      ReportType::kDocumentPolicyViolation, Url().GetString(), body);

  // Avoids sending duplicate reports, by comparing the generated MatchId.
  // The match ids are not guaranteed to be unique.
  // There are trade offs on storing full objects and storing match ids. Storing
  // full objects takes more memory. Storing match id has the potential of hash
  // collision. Since reporting is not a part critical system or have security
  // concern, dropping a valid report due to hash collision seems a reasonable
  // price to pay for the memory saving.
  unsigned report_id = report->MatchId();
  DCHECK(report_id);

  if (document_policy_violation_reports_sent_.Contains(report_id))
    return;
  document_policy_violation_reports_sent_.insert(report_id);

  // Send the document policy violation report to any ReportingObservers.
  const std::optional<std::string> endpoint =
      relevant_document_policy->GetFeatureEndpoint(feature);

  if (is_report_only) {
    UMA_HISTOGRAM_ENUMERATION("Blink.UseCounter.DocumentPolicy.ReportOnly",
                              feature);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Blink.UseCounter.DocumentPolicy.Enforced",
                              feature);
  }

  ReportingContext::From(this)->QueueReport(
      report, endpoint ? Vector<String>{endpoint->c_str()} : Vector<String>{});

  // TODO(iclelland): Report something different in report-only mode
  if (!is_report_only) {
    GetFrame()->Console().AddMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kViolation,
        mojom::blink::ConsoleMessageLevel::kError, body->message()));
  }
}

void LocalDOMWindow::AddConsoleMessageImpl(ConsoleMessage* console_message,
                                           bool discard_duplicates) {
  CHECK(IsContextThread());

  if (!GetFrame())
    return;

  if (document() && console_message->Location()->IsUnknown()) {
    // TODO(dgozman): capture correct location at call places instead.
    unsigned line_number = 0;
    if (!document()->IsInDocumentWrite() &&
        document()->GetScriptableDocumentParser()) {
      ScriptableDocumentParser* parser =
          document()->GetScriptableDocumentParser();
      if (parser->IsParsingAtLineNumber())
        line_number = parser->LineNumber().OneBasedInt();
    }
    Vector<DOMNodeId> nodes(console_message->Nodes());
    std::optional<mojom::blink::ConsoleMessageCategory> category =
        console_message->Category();
    console_message = MakeGarbageCollected<ConsoleMessage>(
        console_message->GetSource(), console_message->GetLevel(),
        console_message->Message(),
        std::make_unique<SourceLocation>(Url().GetString(), String(),
                                         line_number, 0, nullptr));
    console_message->SetNodes(GetFrame(), std::move(nodes));
    if (category)
      console_message->SetCategory(*category);
  }

  GetFrame()->Console().AddMessage(console_message, discard_duplicates);
}

scoped_refptr<base::SingleThreadTaskRunner>
LocalDOMWindow::GetAgentGroupSchedulerCompositorTaskRunner() {
  if (!GetFrame())
    return nullptr;
  auto* frame_scheduler = GetFrame()->GetFrameScheduler();
  return frame_scheduler->GetAgentGroupScheduler()->CompositorTaskRunner();
}

void LocalDOMWindow::AddInspectorIssue(AuditsIssue issue) {
  if (Ge
"""


```