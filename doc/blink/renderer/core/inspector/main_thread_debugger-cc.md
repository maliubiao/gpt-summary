Response:
The user wants to understand the functionality of the `main_thread_debugger.cc` file in the Chromium Blink engine. I need to analyze the code and explain its purpose, focusing on its interactions with JavaScript, HTML, and CSS. I should also identify any logical inferences, provide example inputs and outputs for those inferences, and highlight common usage errors related to this component.

Here's a plan:

1. **Identify the core responsibility:**  The file name suggests debugging capabilities on the main thread.
2. **Analyze key methods:** Look for methods that handle events like context creation/destruction, exceptions, console messages, and pausing/resuming execution.
3. **Relate to web technologies:** Determine how these methods interact with JavaScript execution, DOM manipulation (HTML), and potentially CSS (through styling and layout).
4. **Identify logical reasoning:**  Look for conditional statements and decision-making processes within the methods.
5. **Consider user/programming errors:**  Think about scenarios where incorrect usage of debugging features or underlying browser mechanisms could lead to issues.
`blink/renderer/core/inspector/main_thread_debugger.cc` 文件是 Chromium Blink 引擎中负责处理主线程 JavaScript 调试的核心组件。它将 Blink 的内部机制与 Chrome DevTools 等调试工具连接起来，允许开发者在浏览器中进行断点调试、查看调用栈、检查变量等操作。

以下是其主要功能：

1. **管理 JavaScript 上下文的生命周期:**
   - **`ContextCreated(ScriptState* script_state, LocalFrame* frame, const SecurityOrigin* origin)`:** 当一个新的 JavaScript 执行上下文被创建时（例如，页面加载、iframe 创建），此方法会被调用。它会将该上下文的信息（例如，所属的 frame、是否是主世界等）通知给 V8 Inspector（V8 引擎的调试接口）。这使得调试器能够跟踪不同的执行上下文。
   - **`ContextWillBeDestroyed(ScriptState* script_state)`:** 当一个 JavaScript 执行上下文即将被销毁时，此方法会被调用，并通知 V8 Inspector。
   - **与 JavaScript 的关系:**  这些方法直接关联 JavaScript 的运行环境，确保调试器能正确跟踪 JavaScript 代码的执行。

2. **报告控制台消息:**
   - **`ReportConsoleMessage(ExecutionContext* context, mojom::ConsoleMessageSource source, mojom::ConsoleMessageLevel level, const String& message, SourceLocation* location)`:**  当 JavaScript 代码或 Blink 内部产生控制台消息（例如 `console.log()`、错误信息）时，此方法会被调用，并将消息传递给 `FrameConsole`，最终显示在 DevTools 的控制台面板中。
   - **与 JavaScript 的关系:**  `console.log()`, `console.error()` 等 JavaScript API 的调用会触发此方法。

3. **处理 JavaScript 异常:**
   - **`ExceptionThrown(ExecutionContext* context, ErrorEvent* event)`:** 当 JavaScript 代码抛出未捕获的异常时，此方法会被调用。它会将错误信息、堆栈信息等传递给 V8 Inspector 和 `FrameConsole`，以便在 DevTools 中显示错误详情。
   - **与 JavaScript 的关系:**  JavaScript 运行时错误（例如，类型错误、引用错误）会导致此方法被调用。

4. **控制 JavaScript 代码的执行:**
   - **`runMessageLoopOnInstrumentationPause(int context_group_id)`:** 当代码执行因为某些插桩事件（例如，DevTools 设置了 "Pause on caught exceptions" 或 "Pause on uncaught exceptions"）而暂停时调用。它会启动一个消息循环，暂停当前线程的执行，直到调试器发出继续执行的指令。
   - **`runMessageLoopOnPause(int context_group_id)`:** 当代码执行遇到断点时调用。同样会启动消息循环，暂停执行，等待调试器的指令。
   - **`quitMessageLoopOnPause()`:**  当调试器指示继续执行时调用，停止消息循环，恢复代码执行。
   - **与 JavaScript 的关系:**  这些方法允许调试器暂停和恢复 JavaScript 代码的执行，是断点调试的核心功能。

5. **管理 Metrics 的静音状态:**
   - **`muteMetrics(int context_group_id)`:**  在调试过程中，为了避免调试操作影响性能指标的收集，此方法可以静音某些 Metrics 的上报。
   - **`unmuteMetrics(int context_group_id)`:** 恢复 Metrics 的正常上报。
   - **与 JavaScript, HTML, CSS 的关系:**  虽然不直接关联，但 Metrics 的收集可能涉及到 JavaScript 的执行时间、HTML 渲染性能、CSS 样式计算等。静音状态可以确保调试操作不会扭曲这些指标。

6. **确保 JavaScript 上下文的存在:**
   - **`ensureDefaultContextInGroup(int context_group_id)`:** 确保指定 frame 的主世界 JavaScript 上下文存在。
   - **`beginEnsureAllContextsInGroup(int context_group_id)` / `endEnsureAllContextsInGroup(int context_group_id)`:**  强制初始化指定 frame 的所有 JavaScript 上下文（包括隔离 world）。这在某些调试场景下是必要的。
   - **与 JavaScript 的关系:**  这些方法确保调试器可以访问到需要调试的 JavaScript 代码所在的上下文。

7. **检查脚本执行权限:**
   - **`canExecuteScripts(int context_group_id)`:** 检查是否允许在指定的 frame 中执行脚本。这会考虑到一些安全策略和 DevTools 的限制。
   - **与 JavaScript 的关系:**  如果此方法返回 false，调试器可能无法正常工作，无法执行 JavaScript 代码或设置断点。

8. **在等待调试器时运行消息循环:**
   - **`runIfWaitingForDebugger(int context_group_id)`:**  如果页面加载时遇到了 `debugger;` 语句或者设置了 "Pause on start"，此方法会运行消息循环，等待调试器连接。
   - **与 JavaScript 的关系:**  `debugger;` 语句是 JavaScript 中用于触发断点的机制。

9. **处理来自 V8 Inspector 的控制台 API 消息:**
   - **`consoleAPIMessage(int context_group_id, v8::Isolate::MessageErrorLevel level, const v8_inspector::StringView& message, const v8_inspector::StringView& url, unsigned line_number, unsigned column_number, v8_inspector::V8StackTrace* stack_trace)`:**  接收来自 V8 Inspector 的控制台 API 调用信息，并将其转发到 `FrameConsole`。
   - **与 JavaScript 的关系:**  这是 V8 Inspector 将 JavaScript `console.*` 调用信息传递给 Blink 的桥梁。

10. **清空控制台:**
    - **`consoleClear(int context_group_id)`:**  当 DevTools 控制台被清空时调用，清空 Blink 内部的控制台消息存储。
    - **与 JavaScript 的关系:** 响应用户在 DevTools 中清空控制台的操作。

11. **提供内存信息:**
    - **`memoryInfo(v8::Isolate* isolate, v8::Local<v8::Context> context)`:**  提供当前 JavaScript 上下文的内存使用信息，用于 DevTools 的内存面板。
    - **与 JavaScript 的关系:**  返回与 JavaScript 对象相关的内存使用情况。

12. **安装额外的命令行 API:**
    - **`installAdditionalCommandLineAPI(v8::Local<v8::Context> context, v8::Local<v8::Object> object)`:**  在控制台环境中注入一些方便的函数，例如 `$`, `$$`, `$x`。
    - **与 JavaScript, HTML 的关系:**
        - **`$()`:**  类似于 `document.querySelector()`，用于在 DOM 中查找第一个匹配的元素。
            - **假设输入:**  用户在控制台输入 `$('div.my-class')`。
            - **输出:** 返回页面中第一个 class 为 `my-class` 的 `div` 元素对应的 JavaScript 对象。
        - **`$$()`:** 类似于 `document.querySelectorAll()`，用于在 DOM 中查找所有匹配的元素。
            - **假设输入:** 用户在控制台输入 `$$('p')`。
            - **输出:** 返回一个包含页面中所有 `<p>` 元素对应的 JavaScript 对象的数组。
        - **`$x()`:**  允许使用 XPath 查询 DOM 元素。
            - **假设输入:** 用户在控制台输入 `$x('//a[@href]')`。
            - **输出:** 返回一个包含页面中所有带有 `href` 属性的 `<a>` 元素对应的 JavaScript 对象的数组。
    - **与 CSS 的关系:**  `$()` 和 `$$()` 可以使用 CSS 选择器来查找元素，因此与 CSS 选择器语法有关。

**与 HTML, CSS 的功能关系举例说明:**

* **JavaScript 异常:** 当 JavaScript 代码尝试访问一个不存在的 HTML 元素或操作一个错误的 CSS 属性时，会导致异常抛出，`ExceptionThrown` 方法会被调用，并在 DevTools 中显示错误，指示问题出在哪个 HTML 元素或 CSS 属性上。
* **控制台消息:**  JavaScript 可以通过 `console.log(document.body)` 输出 HTML `<body>` 元素的 JavaScript 对象到控制台。同样，也可以输出 CSSStyleDeclaration 对象来查看元素的样式信息。
* **命令行 API (`$`, `$$`)**: 这些 API 直接操作 DOM 结构 (HTML) 并使用 CSS 选择器来查找元素。
* **断点调试:** 可以在 JavaScript 代码中设置断点，当代码执行到操作某个 HTML 元素或修改其 CSS 样式的语句时暂停，允许开发者检查当时的 DOM 状态和样式信息。

**逻辑推理举例说明:**

* **假设输入:** `MainThreadDebugger::ContextGroupId(LocalFrame* frame)` 接收到一个指向特定 `LocalFrame` 的指针。
* **逻辑推理:**  该方法会找到该 `LocalFrame` 所在的根 frame (使用 `frame->LocalFrameRoot()`)，然后使用 `WeakIdentifierMap` 将根 frame 映射到一个唯一的整数 ID。
* **输出:** 返回一个表示该 frame 组的整数 ID。

**用户或编程常见的使用错误举例说明:**

1. **在错误的上下文中调试:**  开发者可能会在主线程的上下文中尝试调试 Service Worker 或 Web Worker 的代码，反之亦然。 `MainThreadDebugger` 只负责主线程的调试，因此在其他线程的上下文中设置断点或检查变量可能不会生效。
2. **忘记启用 DevTools:**  如果没有打开 Chrome DevTools，`MainThreadDebugger` 的功能虽然在运行，但用户无法直观地看到调试信息或控制代码执行。
3. **阻止了主线程:**  如果在主线程执行了耗时的同步操作（例如，死循环），会导致浏览器卡顿，DevTools 也可能失去响应，无法正常进行调试。
4. **误解命令行 API 的作用域:**  开发者可能会认为在控制台中输入的 `$()` 或 `$$()` 可以访问到所有 iframe 中的元素，但默认情况下它们只作用于当前 frame 的文档。需要使用 `switchTo()` 命令切换到其他 iframe 的上下文才能访问其元素。

总而言之，`blink/renderer/core/inspector/main_thread_debugger.cc` 是 Blink 引擎中至关重要的调试组件，它连接了 JavaScript 执行环境和开发者工具，为 Web 开发提供了强大的调试能力。它与 JavaScript 的执行、HTML DOM 的操作以及 CSS 样式的应用都有着密切的关系。

### 提示词
```
这是目录为blink/renderer/core/inspector/main_thread_debugger.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (c) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"

#include <memory>
#include <set>

#include "base/feature_list.h"
#include "base/synchronization/lock.h"
#include "base/unguessable_token.h"
#include "build/chromeos_buildflags.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_node.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_window.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/events/error_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/console_message_storage.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/timing/memory_info.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/core/xml/xpath_evaluator.h"
#include "third_party/blink/renderer/core/xml/xpath_result.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_set_return_value.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

LocalFrame* ToFrame(ExecutionContext* context) {
  if (!context)
    return nullptr;
  if (auto* window = DynamicTo<LocalDOMWindow>(context))
    return window->GetFrame();
  if (context->IsMainThreadWorkletGlobalScope())
    return To<WorkletGlobalScope>(context)->GetFrame();
  return nullptr;
}
}

MainThreadDebugger::MainThreadDebugger(v8::Isolate* isolate)
    : ThreadDebuggerCommonImpl(isolate), paused_(false) {
}

MainThreadDebugger::~MainThreadDebugger() = default;

void MainThreadDebugger::ReportConsoleMessage(
    ExecutionContext* context,
    mojom::ConsoleMessageSource source,
    mojom::ConsoleMessageLevel level,
    const String& message,
    SourceLocation* location) {
  if (LocalFrame* frame = ToFrame(context))
    frame->Console().ReportMessageToClient(source, level, message, location);
}

int MainThreadDebugger::ContextGroupId(ExecutionContext* context) {
  LocalFrame* frame = ToFrame(context);
  return frame ? ContextGroupId(frame) : 0;
}

void MainThreadDebugger::SetClientMessageLoop(
    std::unique_ptr<ClientMessageLoop> client_message_loop) {
  DCHECK(!client_message_loop_);
  DCHECK(client_message_loop);
  client_message_loop_ = std::move(client_message_loop);
}

void MainThreadDebugger::DidClearContextsForFrame(LocalFrame* frame) {
  DCHECK(IsMainThread());
  if (frame->LocalFrameRoot() == frame)
    GetV8Inspector()->resetContextGroup(ContextGroupId(frame));
}

void MainThreadDebugger::ContextCreated(ScriptState* script_state,
                                        LocalFrame* frame,
                                        const SecurityOrigin* origin) {
  DCHECK(IsMainThread());
  v8::HandleScope handles(script_state->GetIsolate());
  DOMWrapperWorld& world = script_state->World();
  StringBuilder aux_data_builder;
  aux_data_builder.Append("{\"isDefault\":");
  aux_data_builder.Append(world.IsMainWorld() ? "true" : "false");
  if (world.IsMainWorld()) {
    aux_data_builder.Append(",\"type\":\"default\"");
  } else if (world.IsIsolatedWorld()) {
    aux_data_builder.Append(",\"type\":\"isolated\"");
  } else if (world.IsWorkerOrWorkletWorld()) {
    aux_data_builder.Append(",\"type\":\"worker\"");
  }
  aux_data_builder.Append(",\"frameId\":\"");
  aux_data_builder.Append(IdentifiersFactory::FrameId(frame));
  aux_data_builder.Append("\"}");
  String aux_data = aux_data_builder.ToString();
  String human_readable_name =
      !world.IsMainWorld() ? world.NonMainWorldHumanReadableName() : String();
  String origin_string = origin ? origin->ToRawString() : String();
  v8_inspector::V8ContextInfo context_info(
      script_state->GetContext(), ContextGroupId(frame),
      ToV8InspectorStringView(human_readable_name));
  context_info.origin = ToV8InspectorStringView(origin_string);
  context_info.auxData = ToV8InspectorStringView(aux_data);
  context_info.hasMemoryOnConsole = LocalDOMWindow::From(script_state);
  GetV8Inspector()->contextCreated(context_info);
}

void MainThreadDebugger::ContextWillBeDestroyed(ScriptState* script_state) {
  v8::HandleScope handles(script_state->GetIsolate());
  GetV8Inspector()->contextDestroyed(script_state->GetContext());
}

void MainThreadDebugger::ExceptionThrown(ExecutionContext* context,
                                         ErrorEvent* event) {
  LocalFrame* frame = nullptr;
  ScriptState* script_state = nullptr;
  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    frame = window->GetFrame();
    if (!frame)
      return;
    script_state =
        event->World() ? ToScriptState(frame, *event->World()) : nullptr;
  } else if (context->IsMainThreadWorkletGlobalScope()) {
    auto* scope = To<WorkletGlobalScope>(context);
    frame = scope->GetFrame();
    if (!frame)
      return;
    script_state = scope->ScriptController()->GetScriptState();
  } else {
    NOTREACHED();
  }

  frame->Console().ReportMessageToClient(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kError, event->MessageForConsole(),
      event->Location());

  const String default_message = "Uncaught";
  if (script_state && script_state->ContextIsValid()) {
    ScriptState::Scope scope(script_state);
    ScriptValue error = event->error(script_state);
    v8::Local<v8::Value> exception =
        error.IsEmpty()
            ? v8::Local<v8::Value>(v8::Null(script_state->GetIsolate()))
            : error.V8Value();

    SourceLocation* location = event->Location();
    String message = event->MessageForConsole();
    String url = location->Url();
    GetV8Inspector()->exceptionThrown(
        script_state->GetContext(), ToV8InspectorStringView(default_message),
        exception, ToV8InspectorStringView(message),
        ToV8InspectorStringView(url), location->LineNumber(),
        location->ColumnNumber(), location->TakeStackTrace(),
        location->ScriptId());
  }
}

int MainThreadDebugger::ContextGroupId(LocalFrame* frame) {
  LocalFrame& local_frame_root = frame->LocalFrameRoot();
  return WeakIdentifierMap<LocalFrame>::Identifier(&local_frame_root);
}

MainThreadDebugger* MainThreadDebugger::Instance(v8::Isolate* isolate) {
  DCHECK(IsMainThread());
  ThreadDebugger* debugger = ThreadDebugger::From(isolate);
  DCHECK(debugger && !debugger->IsWorker());
  return static_cast<MainThreadDebugger*>(debugger);
}

void MainThreadDebugger::runMessageLoopOnInstrumentationPause(
    int context_group_id) {
  LocalFrame* paused_frame =
      WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  // Do not pause in Context of detached frame.
  if (!paused_frame) {
    return;
  }

  DCHECK_EQ(paused_frame, &paused_frame->LocalFrameRoot());
  paused_ = true;

  // Wait until the execution gets resumed.
  if (client_message_loop_) {
    client_message_loop_->Run(paused_frame,
                              ClientMessageLoop::kInstrumentationPause);
  }
}

void MainThreadDebugger::runMessageLoopOnPause(int context_group_id) {
  LocalFrame* paused_frame =
      WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  // Do not pause in Context of detached frame.
  if (!paused_frame)
    return;
  // If we hit a break point in the paint() function for CSS paint, then we are
  // in the middle of document life cycle. In this case, we should not allow
  // any style update or layout, which could be triggered by resizing the
  // browser window, or clicking at the element panel on devtool.
  if (paused_frame->GetDocument() &&
      !paused_frame->GetDocument()->Lifecycle().StateAllowsTreeMutations()) {
    postponed_transition_scope_ =
        std::make_unique<DocumentLifecycle::PostponeTransitionScope>(
            paused_frame->GetDocument()->Lifecycle());
  }
  DCHECK_EQ(paused_frame, &paused_frame->LocalFrameRoot());
  paused_ = true;

  // Wait for continue or step command.
  if (client_message_loop_)
    client_message_loop_->Run(paused_frame, ClientMessageLoop::kNormalPause);
}

void MainThreadDebugger::quitMessageLoopOnPause() {
  paused_ = false;
  postponed_transition_scope_.reset();
  if (client_message_loop_)
    client_message_loop_->QuitNow();
}

void MainThreadDebugger::muteMetrics(int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  if (!frame)
    return;
  if (frame->GetDocument() && frame->GetDocument()->Loader())
    frame->GetDocument()->Loader()->GetUseCounter().MuteForInspector();
  if (frame->GetPage())
    frame->GetPage()->GetDeprecation().MuteForInspector();
}

void MainThreadDebugger::unmuteMetrics(int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  if (!frame)
    return;
  if (frame->GetDocument() && frame->GetDocument()->Loader())
    frame->GetDocument()->Loader()->GetUseCounter().UnmuteForInspector();
  if (frame->GetPage())
    frame->GetPage()->GetDeprecation().UnmuteForInspector();
}

v8::Local<v8::Context> MainThreadDebugger::ensureDefaultContextInGroup(
    int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  if (!frame)
    return v8::Local<v8::Context>();

  // This is a workaround code with a bailout to avoid crashing in
  // LocalWindowProxy::Initialize().
  // We cannot request a ScriptState on a provisional frame as it would lead
  // to a context creation on it, which is not allowed. Remove this extra check
  // when provisional frames concept gets eliminated. See crbug.com/897816
  // The DCHECK is kept to catch additional regressions earlier.
  // TODO(crbug.com/1182538): DCHECKs are disabled during automated testing on
  // CrOS and this check failed when tested on an experimental builder. Revert
  // https://crrev.com/c/2727867 to enable it.
  // See go/chrome-dcheck-on-cros or http://crbug.com/1113456 for more details.
#if !BUILDFLAG(IS_CHROMEOS_ASH)
  DCHECK(!frame->IsProvisional());
#endif
  if (frame->IsProvisional())
    return v8::Local<v8::Context>();

  ScriptState* script_state = ToScriptStateForMainWorld(frame);
  return script_state ? script_state->GetContext() : v8::Local<v8::Context>();
}

void MainThreadDebugger::beginEnsureAllContextsInGroup(int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  frame->GetSettings()->SetForceMainWorldInitialization(true);
}

void MainThreadDebugger::endEnsureAllContextsInGroup(int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  frame->GetSettings()->SetForceMainWorldInitialization(false);
}

bool MainThreadDebugger::canExecuteScripts(int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  if (!frame->DomWindow()->CanExecuteScripts(kNotAboutToExecuteScript)) {
    return false;
  }

  if (base::FeatureList::IsEnabled(
          features::kAllowDevToolsMainThreadDebuggerForMultipleMainFrames)) {
    return true;
  }

  std::set<base::UnguessableToken> browsing_context_group_tokens;
  for (auto& page : Page::OrdinaryPages()) {
    if (page->MainFrame() && page->MainFrame()->IsOutermostMainFrame()) {
      browsing_context_group_tokens.insert(page->BrowsingContextGroupToken());
    }
  }

  if (browsing_context_group_tokens.size() > 1) {
    String message = String(
        "DevTools debugger is disabled because it is attached to a process "
        "that hosts multiple top-level frames, where DevTools debugger doesn't "
        "work properly. To enable debugger, visit "
        "chrome://flags/#enable-process-per-site-up-to-main-frame-threshold "
        "and disable the feature.");
    frame->Console().AddMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kError, message));
    return false;
  }

  return true;
}

void MainThreadDebugger::runIfWaitingForDebugger(int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  if (client_message_loop_)
    client_message_loop_->RunIfWaitingForDebugger(frame);
}

void MainThreadDebugger::consoleAPIMessage(
    int context_group_id,
    v8::Isolate::MessageErrorLevel level,
    const v8_inspector::StringView& message,
    const v8_inspector::StringView& url,
    unsigned line_number,
    unsigned column_number,
    v8_inspector::V8StackTrace* stack_trace) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  if (!frame)
    return;
  // TODO(dgozman): we can save a copy of message and url here by making
  // FrameConsole work with StringView.
  std::unique_ptr<SourceLocation> location = std::make_unique<SourceLocation>(
      ToCoreString(url), String(), line_number, column_number,
      stack_trace ? stack_trace->clone() : nullptr, 0);
  frame->Console().ReportMessageToClient(
      mojom::ConsoleMessageSource::kConsoleApi,
      V8MessageLevelToMessageLevel(level), ToCoreString(message),
      location.get());
}

void MainThreadDebugger::consoleClear(int context_group_id) {
  LocalFrame* frame = WeakIdentifierMap<LocalFrame>::Lookup(context_group_id);
  if (!frame)
    return;
  if (frame->GetPage())
    frame->GetPage()->GetConsoleMessageStorage().Clear();
}

v8::MaybeLocal<v8::Value> MainThreadDebugger::memoryInfo(
    v8::Isolate* isolate,
    v8::Local<v8::Context> context) {
  DCHECK(ToLocalDOMWindow(context));
  return ToV8Traits<MemoryInfo>::ToV8(
      ScriptState::From(isolate, context),
      MakeGarbageCollected<MemoryInfo>(MemoryInfo::Precision::kBucketized));
}

void MainThreadDebugger::installAdditionalCommandLineAPI(
    v8::Local<v8::Context> context,
    v8::Local<v8::Object> object) {
  ThreadDebuggerCommonImpl::installAdditionalCommandLineAPI(context, object);
  CreateFunctionProperty(
      context, object, "$", MainThreadDebugger::QuerySelectorCallback,
      "function $(selector, [startNode]) { [Command Line API] }",
      v8::SideEffectType::kHasNoSideEffect);
  CreateFunctionProperty(
      context, object, "$$", MainThreadDebugger::QuerySelectorAllCallback,
      "function $$(selector, [startNode]) { [Command Line API] }",
      v8::SideEffectType::kHasNoSideEffect);
  CreateFunctionProperty(
      context, object, "$x", MainThreadDebugger::XpathSelectorCallback,
      "function $x(xpath, [startNode]) { [Command Line API] }",
      v8::SideEffectType::kHasNoSideEffect);
}

static Node* SecondArgumentAsNode(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() > 1) {
    if (Node* node = V8Node::ToWrappable(info.GetIsolate(), info[1])) {
      return node;
    }
  }
  auto* window = CurrentDOMWindow(info.GetIsolate());
  return window ? window->document() : nullptr;
}

void MainThreadDebugger::QuerySelectorCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 1)
    return;
  const String& selector =
      ToCoreStringWithUndefinedOrNullCheck(info.GetIsolate(), info[0]);
  if (selector.empty())
    return;
  auto* container_node = DynamicTo<ContainerNode>(SecondArgumentAsNode(info));
  if (!container_node)
    return;
  ScriptState* script_state =
      ScriptState::ForRelevantRealm(info.GetIsolate(), info.This());
  v8::TryCatch try_catch(info.GetIsolate());
  Element* element = container_node->QuerySelector(
      AtomicString(selector), PassThroughException(info.GetIsolate()));
  if (try_catch.HasCaught()) {
    ApplyContextToException(script_state, try_catch.Exception(),
                            ExceptionContext(v8::ExceptionContext::kOperation,
                                             "CommandLineAPI", "$"));
    try_catch.ReThrow();
    return;
  }
  if (element) {
    info.GetReturnValue().Set(ToV8Traits<Element>::ToV8(script_state, element));
  } else {
    info.GetReturnValue().Set(v8::Null(info.GetIsolate()));
  }
}

void MainThreadDebugger::QuerySelectorAllCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 1)
    return;
  const String& selector =
      ToCoreStringWithUndefinedOrNullCheck(info.GetIsolate(), info[0]);
  if (selector.empty())
    return;
  auto* container_node = DynamicTo<ContainerNode>(SecondArgumentAsNode(info));
  if (!container_node)
    return;
  ScriptState* script_state =
      ScriptState::ForRelevantRealm(info.GetIsolate(), info.This());
  v8::TryCatch try_catch(info.GetIsolate());
  // ToV8(elementList) doesn't work here, since we need a proper Array instance,
  // not NodeList.
  StaticElementList* element_list = container_node->QuerySelectorAll(
      AtomicString(selector), PassThroughException(info.GetIsolate()));
  if (try_catch.HasCaught()) {
    ApplyContextToException(script_state, try_catch.Exception(),
                            ExceptionContext(v8::ExceptionContext::kOperation,
                                             "CommandLineAPI", "$$"));
    try_catch.ReThrow();
    return;
  }
  if (!element_list) {
    return;
  }
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Array> nodes = v8::Array::New(isolate, element_list->length());
  for (wtf_size_t i = 0; i < element_list->length(); ++i) {
    Element* element = element_list->item(i);
    v8::Local<v8::Value> value =
        ToV8Traits<Element>::ToV8(script_state, element);
    if (!CreateDataPropertyInArray(context, nodes, i, value).FromMaybe(false)) {
      return;
    }
  }
  info.GetReturnValue().Set(nodes);
}

void MainThreadDebugger::XpathSelectorCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 1)
    return;
  v8::Isolate* isolate = info.GetIsolate();
  const String& selector =
      ToCoreStringWithUndefinedOrNullCheck(isolate, info[0]);
  if (selector.empty())
    return;
  Node* node = SecondArgumentAsNode(info);
  if (!node || !node->IsContainerNode())
    return;

  ScriptState* script_state =
      ScriptState::ForRelevantRealm(isolate, info.This());
  v8::TryCatch try_catch(isolate);
  XPathResult* result = XPathEvaluator::Create()->evaluate(
      nullptr, selector, node, nullptr, XPathResult::kAnyType, ScriptValue(),
      PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    ApplyContextToException(script_state, try_catch.Exception(),
                            ExceptionContext(v8::ExceptionContext::kOperation,
                                             "CommandLineAPI", "$x"));
    try_catch.ReThrow();
    return;
  }
  if (!result) {
    return;
  }

  if (result->resultType() == XPathResult::kNumberType) {
    bindings::V8SetReturnValue(
        info, result->numberValue(PassThroughException(isolate)));
  } else if (result->resultType() == XPathResult::kStringType) {
    bindings::V8SetReturnValue(
        info, result->stringValue(PassThroughException(isolate)), isolate,
        bindings::V8ReturnValue::kNonNullable);
  } else if (result->resultType() == XPathResult::kBooleanType) {
    bindings::V8SetReturnValue(
        info, result->booleanValue(PassThroughException(isolate)));
  } else {
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    v8::Local<v8::Array> nodes = v8::Array::New(isolate);
    wtf_size_t index = 0;
    while (Node* next_node =
               result->iterateNext(PassThroughException(isolate))) {
      v8::Local<v8::Value> value =
          ToV8Traits<Node>::ToV8(script_state, next_node);
      if (!CreateDataPropertyInArray(context, nodes, index++, value)
               .FromMaybe(false)) {
        return;
      }
    }
    if (try_catch.HasCaught()) {
      ApplyContextToException(script_state, try_catch.Exception(),
                              ExceptionContext(v8::ExceptionContext::kOperation,
                                               "CommandLineAPI", "$x"));
      try_catch.ReThrow();
      return;
    }
    info.GetReturnValue().Set(nodes);
  }
}

}  // namespace blink
```