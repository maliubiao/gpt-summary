Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from the Chromium Blink engine. I need to:

1. **Identify the core purpose of the `v8_initializer.cc` file.** Based on the name, it likely handles the initialization and configuration of the V8 JavaScript engine within Blink.

2. **List the specific functionalities implemented in the code.** This involves analyzing the different functions and callbacks registered with the V8 engine. Key areas seem to be:
    * Handling JavaScript messages and errors.
    * Managing rejected promises.
    * Security checks related to code generation (CSP, Trusted Types).
    * WebAssembly integration.
    * Module loading and `import.meta`.
    * Out-of-memory handling.

3. **Explain the relationship of these functionalities to JavaScript, HTML, and CSS.**  This will involve connecting the code's actions to how these web technologies interact.

4. **Provide examples of how these functionalities work.** This could involve scenarios, input/output examples, or demonstrations of common errors.

5. **Trace how a user action might lead to this code being executed.** This requires understanding the browser's architecture and how user interactions trigger JavaScript execution.

6. **Focus on summarizing the functionalities for Part 1 of the request.**

**High-level Plan:**

* **Identify the main role:** V8 engine initialization and integration within Blink.
* **Categorize functionalities:** Error handling, promise management, security, WebAssembly, modules, memory management.
* **Relate to web technologies:** Explain how each category impacts JavaScript execution and security in the browser context.
* **Provide brief examples:**  Simple illustrations for each category.
* **Outline user interaction flow:**  A general path from user action to JavaScript execution.
好的，这是对提供的 `blink/renderer/bindings/core/v8/v8_initializer.cc` 文件（第一部分）功能的归纳：

**主要功能：V8 JavaScript 引擎的初始化和核心集成**

`v8_initializer.cc` 文件的主要职责是配置和初始化 Chromium Blink 引擎中使用的 V8 JavaScript 引擎，并将其与 Blink 的核心功能集成起来。  它定义了 V8 引擎在 Blink 环境中运行时的行为和特性。

**具体功能点归纳：**

1. **错误和消息处理：**
   - 设置 V8 的消息处理器 (`MessageHandlerInMainThread`, `MessageHandlerInWorker`)，用于捕获和处理 JavaScript 运行时产生的错误和非致命消息。
   - 将 V8 的消息（包括错误级别、消息内容、位置信息等）转化为 Blink 的 `ConsoleMessage` 和 `ErrorEvent` 对象，以便在开发者工具中显示，并触发相应的事件处理。

2. **Promise 拒绝处理：**
   - 设置 V8 的 Promise 拒绝处理器 (`PromiseRejectHandlerInMainThread`, `PromiseRejectHandlerInWorker`)，用于捕获未处理的 Promise 拒绝。
   - 跟踪 Promise 的状态变化，区分是由于没有处理器而拒绝，还是在解决后/拒绝后又被处理。
   - 将未处理的 Promise 拒绝信息转化为 Blink 的事件，方便开发者调试。

3. **异常传播回调：**
   - 设置 V8 的异常传播回调 (`ExceptionPropagationCallback`)，用于在异常跨越 V8 对象边界传播时添加上下文信息，以便更清晰地定位异常发生的根源。

4. **访问权限检查失败回调：**
   - 设置 V8 的访问权限检查失败回调 (`FailedAccessCheckCallbackInMainThread`)，当 JavaScript 代码尝试访问没有权限访问的属性或方法时触发，用于进行安全检查和抛出异常。

5. **代码生成安全检查（CSP 和 Trusted Types）：**
   - 设置 V8 的代码生成检查回调 (`CodeGenerationCheckCallbackInMainThread`)，在执行 `eval()` 或 `Function()` 构造函数等动态代码生成操作时触发。
   - 与 Blink 的内容安全策略（CSP）模块集成，检查 CSP 策略是否允许执行这段代码。
   - 与 Trusted Types 集成，检查动态生成的代码是否符合 Trusted Types 的策略，并可能对代码进行字符串化或修改。
   - 设置 WebAssembly 代码生成检查回调 (`WasmCodeGenerationCheckCallbackInMainThread`)，用于检查 CSP 是否允许 WebAssembly 代码的生成。

6. **WebAssembly 集成：**
   - 设置 WebAssembly 异步 Promise 解决回调 (`WasmAsyncResolvePromiseCallback`)，用于处理异步 WebAssembly 编译的 Promise 结果。
   - 提供了回调函数 (`SharedArrayBufferConstructorEnabledCallback`, `WasmJSStringBuiltinsEnabledCallback`, `WasmJSPromiseIntegrationEnabledCallback`)来控制 WebAssembly 相关特性的启用状态。
   - 针对主线程同步编译/实例化大型 WebAssembly 模块提供了限制 (`WasmModuleOverride`, `WasmInstanceOverride`)，防止阻塞 UI 线程。

7. **模块加载 (Modules)：**
   - 设置 V8 的动态模块导入回调 (`HostImportModuleDynamically`)，用于处理 JavaScript 中 `import()` 表达式触发的动态模块加载。
   - 与 Blink 的模块加载器 (`Modulator`) 集成，负责解析、加载和执行模块。
   - 设置 V8 的 `import.meta` 属性获取回调 (`HostGetImportMetaProperties`)，用于提供模块的元数据信息（例如 URL）。

8. **内存管理（OOM）：**
   - 在 `InitializeV8Common` 中设置了垃圾回收的回调函数 (`V8GCController::GcPrologue`, `V8GCController::GcEpilogue`)，用于在垃圾回收前后执行特定的 Blink 逻辑。
   - 定义了处理 V8 内存溢出（OOM）的结构体 `PrintV8OOM`。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**  这个文件是 Blink 如何与 V8 这个 JavaScript 引擎紧密结合的核心体现。它定义了 JavaScript 代码在浏览器中运行时的各种行为，例如错误处理、异步操作（Promise）、模块加载、安全策略等。
    * **举例：** 当 JavaScript 代码中出现 `throw new Error("Something went wrong");` 时，V8 的消息处理器会被调用，然后 `MessageHandlerInMainThread` 会将这个错误转化为一个 `ErrorEvent` 对象，并分发到相应的 JavaScript 环境中，开发者可以在控制台中看到这个错误信息。
    * **举例：** 当 JavaScript 代码中使用 `import('./my-module.js')` 进行动态导入时，V8 会调用 `HostImportModuleDynamically`，这个函数会调用 Blink 的模块加载器去加载并执行 `my-module.js`。

* **HTML:**  HTML 结构中 `<script>` 标签引入的 JavaScript 代码，以及内联的 JavaScript 代码，都将由 V8 引擎执行，并受到 `v8_initializer.cc` 中配置的各种处理器的影响。
    * **举例：** 如果 HTML 中包含 `<script>eval("alert('hello')");</script>`，`CodeGenerationCheckCallbackInMainThread` 会被调用，检查当前页面的 CSP 是否允许 `eval()`，如果 CSP 不允许，则会阻止代码执行并抛出错误。

* **CSS:** 虽然这个文件本身不直接处理 CSS，但 JavaScript 可以操作 CSS（例如通过 `document.styleSheets` 或 `element.style`），而 JavaScript 的执行受到 `v8_initializer.cc` 的控制。
    * **举例：**  JavaScript 代码可能会动态生成包含 CSS 的 `<style>` 标签并将其添加到 DOM 中。如果 CSP 中对 `style-src` 有限制，虽然 `v8_initializer.cc` 不直接处理 CSS，但 CSP 的限制会影响到这段 JavaScript 代码的行为。

**假设输入与输出 (逻辑推理):**

假设输入是一个包含以下 JavaScript 代码的网页在浏览器中加载：

```html
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" content="script-src 'self'">
</head>
<body>
  <script>
    try {
      eval("window.foo = 'bar'");
    } catch (e) {
      console.error(e);
    }
  </script>
</body>
</html>
```

**假设输出:**

1. 当 V8 执行到 `eval("window.foo = 'bar'")` 时，`CodeGenerationCheckCallbackInMainThread` 会被调用。
2. `CodeGenerationCheckCallbackInMainThread` 会检查页面的 CSP，发现 `script-src 'self'` 不允许 `eval()`。
3. `CodeGenerationCheckCallbackInMainThread` 返回 `false`，阻止代码生成。
4. V8 会抛出一个 `EvalError` 异常。
5. 异常被 `try...catch` 捕获。
6. `console.error(e)` 被执行，`MessageHandlerInMainThread` 会将这个错误信息输出到开发者工具的控制台，显示类似 "EvalError: Refused to evaluate a string as JavaScript because 'unsafe-eval' is not an allowed source of script in the following Content Security Policy directive: "script-src 'self'"." 的错误信息。

**用户或编程常见的使用错误举例说明:**

* **错误地认为没有 `catch` 的 Promise 拒绝不会有任何影响:**  `PromiseRejectHandlerInMainThread` 会捕获这些拒绝，并在控制台中显示警告，帮助开发者发现潜在的错误。
* **在启用了 Trusted Types 的情况下，直接将字符串传递给可能执行代码的 API (例如 `innerHTML`)：** Trusted Types 的检查会阻止这种不安全的操作，并抛出错误。
* **在 CSP 限制了 `eval()` 的情况下，仍然尝试使用 `eval()` 或 `Function()`：**  代码执行会被阻止，并抛出安全相关的错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接导航到网页。**
2. **浏览器解析 HTML 页面。**
3. **当解析到 `<script>` 标签或遇到需要执行的 JavaScript 代码时，Blink 会请求 V8 引擎执行这段代码。**
4. **V8 引擎在执行代码的过程中，可能会触发 `v8_initializer.cc` 中设置的各种回调函数：**
   - 如果代码抛出异常，会触发消息处理器。
   - 如果代码中有未处理的 Promise 拒绝，会触发 Promise 拒绝处理器。
   - 如果代码尝试动态生成代码，会触发代码生成检查回调。
   - 如果代码尝试访问受限的对象或属性，会触发访问权限检查回调。
   - 如果代码中使用了模块导入，会触发模块加载回调。
5. **开发者可以通过浏览器开发者工具（Console 面板、Sources 面板等）观察到这些回调函数产生的影响，例如错误信息、警告信息等。**  在 Sources 面板中设置断点在这些回调函数中，可以更深入地了解代码执行流程。

这就是 `v8_initializer.cc` 文件（第一部分）的主要功能归纳。接下来，请提供第二部分的文件内容，以便进行更全面的分析。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/v8_initializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/v8_initializer.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/system/sys_info.h"
#include "build/build_config.h"
#include "components/crash/core/common/crash_key.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/capture_source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/referrer_script_info.h"
#include "third_party/blink/renderer/bindings/core/v8/rejected_promises.h"
#include "third_party/blink/renderer/bindings/core/v8/sanitize_script_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/shadow_realm_context.h"
#include "third_party/blink/renderer/bindings/core/v8/use_counter_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_context_snapshot.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_embedder_graph_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_error_event.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_idle_task_runner.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_metrics.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_trusted_script.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_trustedscript.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_wasm_response_extensions.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/events/error_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/shadow_realm/shadow_realm_global_scope.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/active_script_wrappable_manager.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_context_data.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/heap/thread_state_storage.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/public/cooperative_scheduling_manager.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/wtf/sanitizers.h"
#include "third_party/blink/renderer/platform/wtf/stack_util.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "tools/v8_context_snapshot/buildflags.h"
#include "v8/include/v8-profiler.h"
#include "v8/include/v8.h"

#if defined(V8_USE_EXTERNAL_STARTUP_DATA)
#include "gin/public/v8_snapshot_file_type.h"
#endif

namespace blink {

#if BUILDFLAG(IS_WIN)
// Defined in v8_initializer_win.cc.
bool FilterETWSessionByURLCallback(v8::Local<v8::Context> context,
                                   const std::string& json_payload);
#endif  // BUILDFLAG(IS_WIN)

namespace {

String ExtractMessageForConsole(v8::Isolate* isolate,
                                v8::Local<v8::Value> data) {
  DOMException* exception = V8DOMException::ToWrappable(isolate, data);
  return exception ? exception->ToStringForConsole() : String();
}

mojom::ConsoleMessageLevel MessageLevelFromNonFatalErrorLevel(int error_level) {
  mojom::ConsoleMessageLevel level = mojom::ConsoleMessageLevel::kError;
  switch (error_level) {
    case v8::Isolate::kMessageDebug:
      level = mojom::ConsoleMessageLevel::kVerbose;
      break;
    case v8::Isolate::kMessageLog:
    case v8::Isolate::kMessageInfo:
      level = mojom::ConsoleMessageLevel::kInfo;
      break;
    case v8::Isolate::kMessageWarning:
      level = mojom::ConsoleMessageLevel::kWarning;
      break;
    case v8::Isolate::kMessageError:
      level = mojom::ConsoleMessageLevel::kInfo;
      break;
    default:
      NOTREACHED();
  }
  return level;
}

// NOTE: when editing this, please also edit the error messages we throw when
// the size is exceeded (see uses of the constant), which use the human-friendly
// "8MB" text.
const size_t kWasmWireBytesLimit = 1 << 23;

}  // namespace

void V8Initializer::MessageHandlerInMainThread(v8::Local<v8::Message> message,
                                               v8::Local<v8::Value> data) {
  DCHECK(IsMainThread());
  v8::Isolate* isolate = message->GetIsolate();

  if (isolate->GetEnteredOrMicrotaskContext().IsEmpty())
    return;

  // If called during context initialization, there will be no entered context.
  ScriptState* script_state = ScriptState::ForCurrentRealm(isolate);
  if (!script_state->ContextIsValid())
    return;

  ExecutionContext* context = ExecutionContext::From(script_state);

  UseCounter::Count(context, WebFeature::kUnhandledExceptionCountInMainThread);
  base::UmaHistogramBoolean("V8.UnhandledExceptionCountInMainThread", true);
  // TODO(b/338241225): Reenable the
  // ThirdPartyCookies.BreakageIndicator.UncaughtJSError event with logic that
  // caps the number of times the event can be sent per client.

  std::unique_ptr<SourceLocation> location =
      CaptureSourceLocation(isolate, message, context);

  if (message->ErrorLevel() != v8::Isolate::kMessageError) {
    context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        MessageLevelFromNonFatalErrorLevel(message->ErrorLevel()),
        ToCoreStringWithNullCheck(isolate, message->Get()),
        std::move(location)));
    return;
  }

  const auto sanitize_script_errors = message->IsSharedCrossOrigin()
                                          ? SanitizeScriptErrors::kDoNotSanitize
                                          : SanitizeScriptErrors::kSanitize;

  ErrorEvent* event = ErrorEvent::Create(
      ToCoreStringWithNullCheck(isolate, message->Get()), std::move(location),
      ScriptValue(isolate, data), &script_state->World());

  String message_for_console = ExtractMessageForConsole(isolate, data);
  if (!message_for_console.empty())
    event->SetUnsanitizedMessage(message_for_console);

  context->DispatchErrorEvent(event, sanitize_script_errors);
}

void V8Initializer::MessageHandlerInWorker(v8::Local<v8::Message> message,
                                           v8::Local<v8::Value> data) {
  v8::Isolate* isolate = message->GetIsolate();
  // During the frame teardown, there may not be a valid context.
  ScriptState* script_state = ScriptState::ForCurrentRealm(isolate);
  if (!script_state->ContextIsValid())
    return;

  ExecutionContext* context = ExecutionContext::From(script_state);
  CHECK(context);

  UseCounter::Count(context, WebFeature::kUnhandledExceptionCountInWorker);
  base::UmaHistogramBoolean("V8.UnhandledExceptionCountInWorker", true);

  std::unique_ptr<SourceLocation> location =
      CaptureSourceLocation(isolate, message, context);

  if (message->ErrorLevel() != v8::Isolate::kMessageError) {
    context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        MessageLevelFromNonFatalErrorLevel(message->ErrorLevel()),
        ToCoreStringWithNullCheck(isolate, message->Get()),
        std::move(location)));
    return;
  }

  ErrorEvent* event = ErrorEvent::Create(
      ToCoreStringWithNullCheck(isolate, message->Get()), std::move(location),
      ScriptValue(isolate, data), &script_state->World());

  const auto sanitize_script_errors = message->IsSharedCrossOrigin()
                                          ? SanitizeScriptErrors::kDoNotSanitize
                                          : SanitizeScriptErrors::kSanitize;

  // If execution termination has been triggered as part of constructing
  // the error event from the v8::Message, quietly leave.
  if (!isolate->IsExecutionTerminating()) {
    ExecutionContext::From(script_state)
        ->DispatchErrorEvent(event, sanitize_script_errors);
  }
}

static void PromiseRejectHandler(v8::PromiseRejectMessage data,
                                 RejectedPromises& rejected_promises,
                                 ScriptState* script_state) {
  if (data.GetEvent() == v8::kPromiseHandlerAddedAfterReject) {
    rejected_promises.HandlerAdded(data);
    return;
  } else if (data.GetEvent() == v8::kPromiseRejectAfterResolved ||
             data.GetEvent() == v8::kPromiseResolveAfterResolved) {
    // Ignore reject/resolve after resolved.
    return;
  }

  DCHECK_EQ(v8::kPromiseRejectWithNoHandler, data.GetEvent());

  v8::Isolate* isolate = script_state->GetIsolate();
  ExecutionContext* context = ExecutionContext::From(script_state);

  v8::Local<v8::Value> exception = data.GetValue();
  String error_message;
  SanitizeScriptErrors sanitize_script_errors = SanitizeScriptErrors::kSanitize;
  std::unique_ptr<SourceLocation> location;

  v8::Local<v8::Message> message =
      v8::Exception::CreateMessage(isolate, exception);
  if (!message.IsEmpty()) {
    // message->Get() can be empty here. https://crbug.com/450330
    error_message = ToCoreStringWithNullCheck(isolate, message->Get());
    location = CaptureSourceLocation(isolate, message, context);
    if (message->IsSharedCrossOrigin())
      sanitize_script_errors = SanitizeScriptErrors::kDoNotSanitize;
  } else {
    location = std::make_unique<SourceLocation>(context->Url().GetString(),
                                                String(), 0, 0, nullptr);
  }

  String message_for_console =
      ExtractMessageForConsole(isolate, data.GetValue());
  if (!message_for_console.empty()) {
    error_message = std::move(message_for_console);
  }

  rejected_promises.RejectedWithNoHandler(script_state, data, error_message,
                                          std::move(location),
                                          sanitize_script_errors);
}

// static
void V8Initializer::PromiseRejectHandlerInMainThread(
    v8::PromiseRejectMessage data) {
  DCHECK(IsMainThread());

  v8::Local<v8::Promise> promise = data.GetPromise();

  v8::Isolate* isolate = promise->GetIsolate();

  // TODO(ikilpatrick): Remove this check, extensions tests that use
  // extensions::ModuleSystemTest incorrectly don't have a valid script state.
  LocalDOMWindow* window = CurrentDOMWindow(isolate);
  if (!window || !window->IsCurrentlyDisplayedInFrame())
    return;

  // Bail out if called during context initialization.
  ScriptState* script_state = ScriptState::ForCurrentRealm(isolate);
  if (!script_state->ContextIsValid())
    return;

  RejectedPromises* rejected_promises =
      &window->GetAgent()->GetRejectedPromises();
  PromiseRejectHandler(data, *rejected_promises, script_state);
}

void V8Initializer::ExceptionPropagationCallback(
    v8::ExceptionPropagationMessage v8_message) {
  v8::Isolate* isolate = v8_message.GetIsolate();
  v8::Local<v8::Object> exception = v8_message.GetException();

  v8::ExceptionContext context_type = v8_message.GetExceptionContext();
  String class_name = ToCoreString(isolate, v8_message.GetInterfaceName());
  if (class_name == "global") {
    class_name = "Window";
  }
  String property_name = ToCoreString(isolate, v8_message.GetPropertyName());
  if ((context_type == v8::ExceptionContext::kAttributeGet &&
       property_name.StartsWith("get ")) ||
      (context_type == v8::ExceptionContext::kAttributeSet &&
       property_name.StartsWith("set "))) {
    property_name = property_name.Substring(4);
  }
  if (property_name == "[Symbol.toPrimitive]") {
    property_name = String();
  }
  if (context_type == v8::ExceptionContext::kConstructor) {
    // Constructors are reported by v8 as the property name, but
    // our plumbing expects it as the class name.
    class_name = property_name;
  }
  DCHECK(class_name.Is8Bit());

  for (auto* dictionary_context =
           V8PerIsolateData::From(isolate)->TopOfDictionaryStack();
       dictionary_context;
       dictionary_context = dictionary_context->Previous()) {
    ApplyContextToException(isolate, isolate->GetCurrentContext(), exception,
                            v8::ExceptionContext::kAttributeGet,
                            dictionary_context->DictionaryName(),
                            dictionary_context->PropertyName());
  }

  ApplyContextToException(isolate, isolate->GetCurrentContext(), exception,
                          context_type, class_name.Utf8().data(),
                          property_name);
}

static void PromiseRejectHandlerInWorker(v8::PromiseRejectMessage data) {
  v8::Local<v8::Promise> promise = data.GetPromise();

  // Bail out if called during context initialization.
  v8::Isolate* isolate = promise->GetIsolate();
  ScriptState* script_state = ScriptState::ForCurrentRealm(isolate);
  if (!script_state->ContextIsValid())
    return;

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  if (!execution_context)
    return;

  ExecutionContext* root_worker_context =
      execution_context->IsShadowRealmGlobalScope()
          ? To<ShadowRealmGlobalScope>(execution_context)
                ->GetRootInitiatorExecutionContext()
          : execution_context;
  DCHECK(root_worker_context->IsWorkerOrWorkletGlobalScope());

  auto* script_controller =
      To<WorkerOrWorkletGlobalScope>(root_worker_context)->ScriptController();
  DCHECK(script_controller);

  PromiseRejectHandler(data, *script_controller->GetRejectedPromises(),
                       script_state);
}

// static
void V8Initializer::FailedAccessCheckCallbackInMainThread(
    v8::Local<v8::Object> holder,
    v8::AccessType type,
    v8::Local<v8::Value> data) {
  // FIXME: This is the access check callback of last resort. We should modify
  // V8 to pass in more contextual information, so that we can build a full
  // ExceptionState.
  ExceptionState exception_state(
      holder->GetIsolate(), v8::ExceptionContext::kUnknown, nullptr, nullptr);
  BindingSecurity::FailedAccessCheckFor(holder->GetIsolate(),
                                        WrapperTypeInfo::Unwrap(data), holder,
                                        exception_state);
}

// Check whether Content Security Policy allows script execution.
static bool ContentSecurityPolicyCodeGenerationCheck(
    v8::Local<v8::Context> context,
    v8::Local<v8::String> source) {
  if (ExecutionContext* execution_context = ToExecutionContext(context)) {
    // Note this callback is only triggered for contexts which have eval
    // disabled. Hence we don't need to handle the case of isolated world
    // contexts with no CSP specified. (They should be exempt from the page CSP.
    // See crbug.com/982388.)

    if (ContentSecurityPolicy* policy =
            execution_context->GetContentSecurityPolicyForCurrentWorld()) {
      v8::Context::Scope scope(context);
      v8::String::Value source_str(context->GetIsolate(), source);
      UChar snippet[ContentSecurityPolicy::kMaxSampleLength + 1];
      size_t len = std::min((sizeof(snippet) / sizeof(UChar)) - 1,
                            static_cast<size_t>(source_str.length()));
      memcpy(snippet, *source_str, len * sizeof(UChar));
      snippet[len] = 0;
      return policy->AllowEval(ReportingDisposition::kReport,
                               ContentSecurityPolicy::kWillThrowException,
                               snippet);
    }
  }
  return false;
}

static std::pair<bool, v8::MaybeLocal<v8::String>>
TrustedTypesCodeGenerationCheck(v8::Local<v8::Context> context,
                                v8::Local<v8::Value> source,
                                bool is_code_like) {
  v8::Isolate* isolate = context->GetIsolate();
  // If the input is not a string or TrustedScript, pass it through.
  if (!source->IsString() && !is_code_like &&
      !V8TrustedScript::HasInstance(isolate, source)) {
    return {true, v8::MaybeLocal<v8::String>()};
  }

  v8::TryCatch try_catch(isolate);
  V8UnionStringOrTrustedScript* string_or_trusted_script =
      NativeValueTraits<V8UnionStringOrTrustedScript>::NativeValue(
          isolate, source, PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    // The input was a string or TrustedScript but the conversion failed.
    // Block, just in case.
    return {false, v8::MaybeLocal<v8::String>()};
  }

  if (is_code_like && string_or_trusted_script->IsString()) {
    string_or_trusted_script->Set(MakeGarbageCollected<TrustedScript>(
        string_or_trusted_script->GetAsString()));
  }

  String stringified_source = TrustedTypesCheckForScript(
      string_or_trusted_script, ToExecutionContext(context), "eval", "",
      PassThroughException(isolate));
  if (try_catch.HasCaught()) {
    return {false, v8::MaybeLocal<v8::String>()};
  }

  return {true, V8String(context->GetIsolate(), stringified_source)};
}

// static
v8::ModifyCodeGenerationFromStringsResult
V8Initializer::CodeGenerationCheckCallbackInMainThread(
    v8::Local<v8::Context> context,
    v8::Local<v8::Value> source,
    bool is_code_like) {
  // The TC39 "Dynamic Code Brand Check" feature is currently behind a flag.
  if (!RuntimeEnabledFeatures::TrustedTypesUseCodeLikeEnabled())
    is_code_like = false;

  // With Trusted Types, we always run the TT check first because of reporting,
  // and because a default policy might want to stringify or modify the original
  // source. When TT enforcement is disabled, codegen is always allowed, and we
  // just use the check to stringify any trusted type source.
  bool codegen_allowed_by_tt = false;
  v8::MaybeLocal<v8::String> stringified_source;
  std::tie(codegen_allowed_by_tt, stringified_source) =
      TrustedTypesCodeGenerationCheck(context, source, is_code_like);

  if (!codegen_allowed_by_tt) {
    return {false, v8::MaybeLocal<v8::String>()};
  }

  if (stringified_source.IsEmpty()) {
    return {true, v8::MaybeLocal<v8::String>()};
  }

  if (!ContentSecurityPolicyCodeGenerationCheck(
          context, stringified_source.ToLocalChecked())) {
    return {false, v8::MaybeLocal<v8::String>()};
  }

  return {true, std::move(stringified_source)};
}

bool V8Initializer::WasmCodeGenerationCheckCallbackInMainThread(
    v8::Local<v8::Context> context,
    v8::Local<v8::String> source) {
  ExecutionContext* execution_context = ToExecutionContext(context);
  if (!execution_context) {
    return false;
  }
  ContentSecurityPolicy* policy = execution_context->GetContentSecurityPolicy();
  if (!policy) {
    return false;
  }
  v8::String::Value source_str(context->GetIsolate(), source);
  UChar snippet[ContentSecurityPolicy::kMaxSampleLength + 1];
  size_t len = std::min((sizeof(snippet) / sizeof(UChar)) - 1,
                        static_cast<size_t>(source_str.length()));
  memcpy(snippet, *source_str, len * sizeof(UChar));
  snippet[len] = 0;
  if (!policy->AllowWasmCodeGeneration(
          ReportingDisposition::kReport,
          ContentSecurityPolicy::kWillThrowException, snippet)) {
    return false;
  }

  // Set a crash key so we know if a crash report could have been caused by
  // Wasm.
  static crash_reporter::CrashKeyString<1> has_wasm_key("has-wasm");
  has_wasm_key.Set("1");
  return true;
}

void V8Initializer::WasmAsyncResolvePromiseCallback(
    v8::Isolate* isolate,
    v8::Local<v8::Context> context,
    v8::Local<v8::Promise::Resolver> resolver,
    v8::Local<v8::Value> compilation_result,
    v8::WasmAsyncSuccess success) {
  ScriptState* script_state = ScriptState::MaybeFrom(isolate, context);
  if (!script_state ||
      !IsInParallelAlgorithmRunnable(ExecutionContext::From(script_state),
                                     script_state)) {
    return;
  }
  v8::MicrotasksScope microtasks_scope(
      isolate, context->GetMicrotaskQueue(),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  if (success == v8::WasmAsyncSuccess::kSuccess) {
    CHECK(resolver->Resolve(context, compilation_result).FromJust());
  } else {
    CHECK(resolver->Reject(context, compilation_result).FromJust());
  }
}

namespace {
bool SharedArrayBufferConstructorEnabledCallback(
    v8::Local<v8::Context> context) {
  ExecutionContext* execution_context = ToExecutionContext(context);
  if (!execution_context)
    return false;
  return execution_context->SharedArrayBufferTransferAllowed();
}

v8::Local<v8::Value> NewRangeException(v8::Isolate* isolate,
                                       const char* message) {
  return v8::Exception::RangeError(
      v8::String::NewFromOneByte(isolate,
                                 reinterpret_cast<const uint8_t*>(message),
                                 v8::NewStringType::kNormal)
          .ToLocalChecked());
}

void ThrowRangeException(v8::Isolate* isolate, const char* message) {
  isolate->ThrowException(NewRangeException(isolate, message));
}

BASE_FEATURE(kWebAssemblyUnlimitedSyncCompilation,
             "WebAssemblyUnlimitedSyncCompilation",
             base::FEATURE_DISABLED_BY_DEFAULT);

bool WasmModuleOverride(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // Return false if we want the base behavior to proceed.
  if (!WTF::IsMainThread() || args.Length() < 1 ||
      base::FeatureList::IsEnabled(kWebAssemblyUnlimitedSyncCompilation)) {
    return false;
  }
  v8::Local<v8::Value> source = args[0];
  if ((source->IsArrayBuffer() &&
       v8::Local<v8::ArrayBuffer>::Cast(source)->ByteLength() >
           kWasmWireBytesLimit) ||
      (source->IsArrayBufferView() &&
       v8::Local<v8::ArrayBufferView>::Cast(source)->ByteLength() >
           kWasmWireBytesLimit)) {
    ThrowRangeException(
        args.GetIsolate(),
        "WebAssembly.Compile is disallowed on the main thread, "
        "if the buffer size is larger than 8MB. Use "
        "WebAssembly.compile, compile on a worker thread, or use the flag "
        "`--enable-features=WebAssemblyUnlimitedSyncCompilation`.");
    // Return true because we injected new behavior and we do not
    // want the default behavior.
    return true;
  }
  return false;
}

bool WasmInstanceOverride(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // Return false if we want the base behavior to proceed.
  if (!WTF::IsMainThread() || args.Length() < 1 ||
      base::FeatureList::IsEnabled(kWebAssemblyUnlimitedSyncCompilation)) {
    return false;
  }
  v8::Local<v8::Value> source = args[0];
  if (!source->IsWasmModuleObject())
    return false;

  v8::CompiledWasmModule compiled_module =
      v8::Local<v8::WasmModuleObject>::Cast(source)->GetCompiledModule();
  if (compiled_module.GetWireBytesRef().size() > kWasmWireBytesLimit) {
    ThrowRangeException(
        args.GetIsolate(),
        "WebAssembly.Instance is disallowed on the main thread, "
        "if the buffer size is larger than 8MB. Use "
        "WebAssembly.instantiate, or use the flag "
        "`--enable-features=WebAssemblyUnlimitedSyncCompilation`.");
    return true;
  }
  return false;
}

bool WasmJSStringBuiltinsEnabledCallback(v8::Local<v8::Context> context) {
  ExecutionContext* execution_context = ToExecutionContext(context);
  if (!execution_context) {
    return false;
  }
  return RuntimeEnabledFeatures::WebAssemblyJSStringBuiltinsEnabled(
      execution_context);
}

bool WasmJSPromiseIntegrationEnabledCallback(v8::Local<v8::Context> context) {
  ExecutionContext* execution_context = ToExecutionContext(context);
  if (!execution_context) {
    return false;
  }
  return RuntimeEnabledFeatures::WebAssemblyJSPromiseIntegrationEnabled(
      execution_context);
}

v8::MaybeLocal<v8::Promise> HostImportModuleDynamically(
    v8::Local<v8::Context> context,
    v8::Local<v8::Data> v8_host_defined_options,
    v8::Local<v8::Value> v8_referrer_resource_url,
    v8::Local<v8::String> v8_specifier,
    v8::Local<v8::FixedArray> v8_import_attributes) {
  v8::Isolate* isolate = context->GetIsolate();
  ScriptState* script_state = ScriptState::From(isolate, context);

  Modulator* modulator = Modulator::From(script_state);
  if (!modulator) {
    // Inactive browsing context (detached frames) doesn't have a modulator.
    // We chose to return a rejected promise (which may never get to catch(),
    // since MicrotaskQueue for a detached frame is never consumed).
    //
    // This is a hack to satisfy V8 API expectation, which are:
    // - return non-empty v8::Promise value
    //   (can either be fulfilled/rejected), or
    // - throw exception && return Empty value
    // See crbug.com/972960 .
    //
    // We use the v8 promise API directly here.
    // We can't use ScriptPromiseResolverBase here since it assumes a valid
    // ScriptState.
    v8::Local<v8::Promise::Resolver> resolver;
    if (!v8::Promise::Resolver::New(script_state->GetContext())
             .ToLocal(&resolver)) {
      // Note: V8 should have thrown an exception in this case,
      //       so we return Empty.
      return v8::MaybeLocal<v8::Promise>();
    }

    v8::Local<v8::Promise> promise = resolver->GetPromise();
    v8::Local<v8::Value> error = V8ThrowException::CreateError(
        script_state->GetIsolate(),
        "Cannot import module from an inactive browsing context.");
    resolver->Reject(script_state->GetContext(), error).ToChecked();
    return promise;
  }

  String specifier =
      ToCoreStringWithNullCheck(script_state->GetIsolate(), v8_specifier);
  KURL referrer_resource_url;
  if (v8_referrer_resource_url->IsString()) {
    String referrer_resource_url_str =
        ToCoreString(script_state->GetIsolate(),
                     v8::Local<v8::String>::Cast(v8_referrer_resource_url));
    if (!referrer_resource_url_str.empty())
      referrer_resource_url = KURL(NullURL(), referrer_resource_url_str);
  }

  ModuleRequest module_request(
      specifier, TextPosition::MinimumPosition(),
      ModuleRecord::ToBlinkImportAttributes(
          script_state->GetContext(), v8::Local<v8::Module>(),
          v8_import_attributes, /*v8_import_attributes_has_positions=*/false));

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state,
      ExceptionContext(v8::ExceptionContext::kUnknown, "", "import"));

  String invalid_attribute_key;
  if (module_request.HasInvalidImportAttributeKey(&invalid_attribute_key)) {
    resolver->Reject(V8ThrowException::CreateTypeError(
        script_state->GetIsolate(),
        "Invalid attribute key \"" + invalid_attribute_key + "\"."));
  } else {
    ReferrerScriptInfo referrer_info =
        ReferrerScriptInfo::FromV8HostDefinedOptions(
            context, v8_host_defined_options, referrer_resource_url);

    modulator->ResolveDynamically(module_request, referrer_info, resolver);
  }

  return resolver->Promise().V8Promise();
}

// https://html.spec.whatwg.org/C/#hostgetimportmetaproperties
void HostGetImportMetaProperties(v8::Local<v8::Context> context,
                                 v8::Local<v8::Module> module,
                                 v8::Local<v8::Object> meta) {
  v8::Isolate* isolate = context->GetIsolate();
  ScriptState* script_state = ScriptState::From(isolate, context);
  v8::HandleScope handle_scope(isolate);

  Modulator* modulator = Modulator::From(script_state);
  if (!modulator)
    return;

  ModuleImportMeta host_meta = modulator->HostGetImportMetaProperties(module);

  // 6. Return « Record { [[Key]]: "url", [[Value]]: urlString }, Record {
  // [[Key]]: "resolve", [[Value]]: resolveFunction } ». [spec text]
  v8::Local<v8::String> url_key = V8String(isolate, "url");
  v8::Local<v8::String> url_value = V8String(isolate, host_meta.Url());

  v8::Local<v8::String> resolve_key = V8String(isolate, "resolve");
  v8::Local<v8::Function> resolve_value =
      host_meta.MakeResolveV8Function(modulator);
  resolve_value->SetName(resolve_key);

  meta->CreateDataProperty(context, url_key, url_value).ToChecked();
  meta->CreateDataProperty(context, resolve_key, resolve_value).ToChecked();
}

struct PrintV8OOM {
  const char* location;
  const v8::OOMDetails& details;
};

std::ostream& operator<<(std::ostream& os, const PrintV8OOM& oom_details) {
  const auto [location, details] = oom_details;
  os << "V8 " << (details.is_heap_oom ? "javascript" : "process") << " OOM ("
     << location;
  if (details.detail) {
    os << "; detail: " << details.detail;
  }
  os << ").";
  return os;
}

}  // namespace

// static
void V8Initializer::InitializeV8Common(v8::Isolate* isolate) {
  // Set up garbage collection before setting up anything else as V8 may trigger
  // GCs during Blink setup.
  V8PerIsolateData::From(isolate)->SetGCCallbacks(
      isolate, V8GCController::GcPrologue, V8GCController::GcEpilogue);
  ThreadState::Current()->AttachToIsolate(
      
"""


```