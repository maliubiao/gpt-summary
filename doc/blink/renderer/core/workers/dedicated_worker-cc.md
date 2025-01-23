Response:
The user wants to understand the functionality of the `dedicated_worker.cc` file in the Chromium Blink engine. They are particularly interested in how it relates to JavaScript, HTML, and CSS, and want examples, logical reasoning with input/output, and common usage errors. This is the first part of a two-part request, so the current goal is to provide a summary of the file's purpose based on the provided code.

**Plan:**

1. **Identify the core responsibility:** The file manages the lifecycle and communication of dedicated workers.
2. **Relate to web technologies:**  Dedicated workers execute JavaScript, interact with resources fetched via URLs (HTML, CSS, JS, etc.), and communicate using messages.
3. **Look for examples in the code:**  `postMessage` clearly relates to JavaScript communication. The loading of scripts (`Start`, `OnResponse`, `OnFinished`) shows interaction with resources.
4. **Infer logical reasoning:** The `Start` method initiates the worker. Based on flags (`features::kPlzDedicatedWorker`), different paths are taken. This suggests conditional logic based on browser features.
5. **Consider common errors:**  The `Create` method checks for invalid contexts, suggesting a potential user error.
6. **Summarize the functionality for Part 1:** Focus on the core responsibilities identified in step 1.
```
这是目录为blink/renderer/core/workers/dedicated_worker.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

**`blink/renderer/core/workers/dedicated_worker.cc` 的功能归纳 (第 1 部分):**

这个 C++ 文件 `dedicated_worker.cc`  在 Chromium Blink 渲染引擎中负责管理 **专用 worker (Dedicated Worker)** 的生命周期和行为。 它的核心功能可以归纳为以下几点：

1. **创建和启动专用 Worker:**
   -  提供了 `DedicatedWorker::Create` 方法，用于在主线程或其他 worker 线程中创建新的专用 worker 实例。
   -  处理 worker 脚本的 URL 解析和验证。
   -  初始化 worker 的内部状态，包括创建 `DedicatedWorkerMessagingProxy` 用于跨线程通信。
   -  负责启动 worker 的加载过程，根据是否启用 `features::kPlzDedicatedWorker` (Plz stands for "Process-per-site-instance")  选择不同的启动流程。

2. **处理与 Worker 相关的消息通信:**
   -  实现了 `postMessage` 方法，允许主线程或其他 worker 线程向该专用 worker 发送消息。
   -  负责序列化 JavaScript 对象，以便跨线程安全地传递消息（涉及到 `PostMessageHelper::SerializeMessageByMove`）。
   -  处理消息传输列表 (`transfer`)，允许高效地转移对象的所有权。
   -  支持发送包含 `MessagePort` 的消息，用于建立更复杂的双向通信通道。

3. **加载和执行 Worker 脚本:**
   -  根据 worker 的类型 (`classic` 或 `module`)，选择不同的脚本加载器 (`WorkerClassicScriptLoader`) 或直接进入 `ContinueStart` 流程。
   -  处理 worker 脚本的获取和加载，包括处理 Blob URL。
   -  在脚本加载完成后，调用 `ContinueStart` 或 `ContinueStartInternal` 来创建 worker 的全局作用域 (`WorkerGlobalScope`) 并执行脚本。

4. **处理 Worker 的终止:**
   -  提供了 `terminate` 方法，用于强制终止专用 worker 的执行。
   -  在 `ContextDestroyed` 中处理 worker 上下文的销毁和清理工作。

5. **集成到 Chromium 的基础设施:**
   -  使用 Mojo 进行进程间通信 (IPC)，与浏览器进程中的 WorkerHost 进行交互。
   -  使用 `WebContentSettingsClient` 获取与内容设置相关的策略。
   -  使用 `UseCounter` 记录 worker 的使用情况。
   -  集成到 DevTools，支持调试和性能分析（通过 `TRACE_EVENT` 等宏）。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    - **创建 Worker:**  JavaScript 代码可以使用 `new Worker('script.js')` 来创建一个新的专用 worker。`DedicatedWorker::Create` 方法就是在 Blink 引擎内部处理这个 JavaScript API 调用的。
    - **发送消息:** JavaScript 可以使用 `worker.postMessage({data: 'hello'})` 向 worker 发送消息。 `DedicatedWorker::postMessage` 实现了这一功能，负责序列化 JavaScript 对象并将其发送到 worker 线程。
    - **接收消息:**  虽然这段代码没有直接体现 worker 接收消息的过程（那是 `DedicatedWorkerGlobalScope` 的职责），但发送的消息最终会在 worker 内部的 JavaScript 代码中通过 `onmessage` 事件处理程序接收。

* **HTML:**
    - **引用 Worker 脚本:** HTML 中的 `<script>` 标签或通过 JavaScript 动态创建的脚本标签可以启动创建 worker 的过程。`DedicatedWorker::Create` 接收的 `url` 参数通常指向一个包含 JavaScript 代码的 HTML 文件（尽管 worker 通常是独立的 JS 文件）。
    - **Blob URL:** HTML 或 JavaScript 可以创建 Blob URL，然后将其作为 worker 的脚本 URL 传递。代码中处理了 `script_request_url_.ProtocolIs("blob")` 的情况，并使用 `PublicURLManager` 来解析 Blob URL。

* **CSS:**
    - **间接关系:**  Worker 本身不直接操作 CSS。但是，worker 中执行的 JavaScript 代码可能会发起网络请求去获取 CSS 资源（例如，通过 `fetch` API），或者执行一些可能影响页面 CSS 样式的计算（例如，通过 `OffscreenCanvas` 进行渲染）。 `DedicatedWorker` 负责加载 worker 的主脚本，这个脚本可能会包含执行这些操作的代码。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. 在主线程 JavaScript 中调用 `new Worker('my_worker.js')`。
2. `my_worker.js` 的内容是一个简单的 JavaScript 文件，例如 `console.log('Worker started'); self.onmessage = function(e) { console.log('Message received:', e.data); }`。

**逻辑推理:**

*   `DedicatedWorker::Create` 会被调用，接收 `'my_worker.js'` 作为 `url` 参数。
*   `ResolveURL` 会解析 `'my_worker.js'` 相对于当前文档的 URL。
*   根据 `features::kPlzDedicatedWorker` 的状态，选择不同的启动路径。
*   如果未启用 `kPlzDedicatedWorker`，`WorkerClassicScriptLoader` 将会加载 `my_worker.js` 的内容。
*   `OnFinished` 会在脚本加载完成后被调用，并触发 `ContinueStart`。
*   `ContinueStartInternal` 会创建 worker 的全局作用域，并开始执行 `my_worker.js` 中的 JavaScript 代码。

**预期输出:**

*   在浏览器的控制台中，你会看到来自 worker 的日志消息 "Worker started"。
*   如果主线程随后使用 `worker.postMessage({msg: 'test'})` 发送消息，worker 的 `onmessage` 处理程序会被触发，控制台会输出 "Message received: {msg: 'test'}"。

**涉及用户或编程常见的使用错误举例说明:**

1. **无效的 Worker 脚本 URL:**
   - **错误:** 在 JavaScript 中使用 `new Worker('invalid_url')`，其中 `invalid_url` 指向一个不存在的文件或发生网络错误。
   - **后果:** `ResolveURL` 可能会返回无效的 URL，或者脚本加载过程会失败，导致 worker 无法启动。在 `DedicatedWorker::Start` 或 `OnFinished` 中会检测到加载失败，并可能触发错误事件。

2. **跨域问题:**
   - **错误:** 主页面位于 `http://example.com`，尝试创建一个指向 `http://another-domain.com/worker.js` 的 worker，并且没有正确的 CORS 头信息。
   - **后果:** 浏览器会阻止跨域 worker 的加载，因为这违反了同源策略。`DedicatedWorker` 的加载过程会失败，并可能在控制台中显示 CORS 相关的错误信息。

3. **在已销毁的上下文中创建 Worker:**
   - **错误:** 尝试在一个已经卸载或销毁的文档或 worker 中创建新的 worker。
   - **后果:** `DedicatedWorker::Create` 中的 `context->IsContextDestroyed()` 检查会捕获这个错误，并抛出一个 `DOMExceptionCode::kInvalidAccessError` 异常。

**总结 (第 1 部分):**

`dedicated_worker.cc` 是 Chromium Blink 中负责创建、启动、管理和终止专用 worker 的核心组件。 它处理 worker 脚本的加载、消息的传递，并与浏览器的其他部分（如网络栈、DevTools）进行集成。 这个文件对于理解专用 worker 的内部工作原理至关重要，因为它连接了 JavaScript API 和底层的 C++ 实现。

### 提示词
```
这是目录为blink/renderer/core/workers/dedicated_worker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/workers/dedicated_worker.h"

#include <optional>
#include <utility>

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/typed_macros.h"
#include "base/unguessable_token.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/network/public/cpp/cross_origin_embedder_policy.h"
#include "services/network/public/mojom/fetch_api.mojom-blink.h"
#include "third_party/blink/public/common/blob/blob_utils.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/browser_interface_broker.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/script/script_type.mojom-blink.h"
#include "third_party/blink/public/mojom/worker/dedicated_worker_host_factory.mojom-blink.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/platform/web_fetch_client_settings_object.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/post_message_helper.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_post_message_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_structured_serialize_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/request.h"
#include "third_party/blink/renderer/core/fileapi/public_url_manager.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/worker_fetch_context.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/script_type_names.h"
#include "third_party/blink/renderer/core/workers/custom_event_message.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker_messaging_proxy.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_classic_script_loader.h"
#include "third_party/blink/renderer/core/workers/worker_clients.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/enumeration_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/begin_frame_provider.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/dedicated_or_shared_worker_fetch_context_impl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"

namespace blink {

DedicatedWorker* DedicatedWorker::Create(ExecutionContext* context,
                                         const String& url,
                                         const WorkerOptions* options,
                                         ExceptionState& exception_state) {
  DCHECK(context->IsContextThread());
  UseCounter::Count(context, WebFeature::kWorkerStart);
  if (context->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The context provided is invalid.");
    return nullptr;
  }

  KURL script_request_url = ResolveURL(context, url, exception_state);
  if (!script_request_url.IsValid()) {
    // Don't throw an exception here because it's already thrown in
    // ResolveURL().
    return nullptr;
  }

  if (context->IsWorkerGlobalScope())
    UseCounter::Count(context, WebFeature::kNestedDedicatedWorker);

  DedicatedWorker* worker = MakeGarbageCollected<DedicatedWorker>(
      context, script_request_url, options);
  worker->UpdateStateIfNeeded();
  worker->Start();
  return worker;
}

DedicatedWorker::DedicatedWorker(ExecutionContext* context,
                                 const KURL& script_request_url,
                                 const WorkerOptions* options)
    : DedicatedWorker(
          context,
          script_request_url,
          options,
          [context](DedicatedWorker* worker) {
            return MakeGarbageCollected<DedicatedWorkerMessagingProxy>(context,
                                                                       worker);
          }) {}

DedicatedWorker::DedicatedWorker(
    ExecutionContext* context,
    const KURL& script_request_url,
    const WorkerOptions* options,
    base::FunctionRef<DedicatedWorkerMessagingProxy*(DedicatedWorker*)>
        context_proxy_factory)
    : AbstractWorker(context),
      ActiveScriptWrappable<DedicatedWorker>({}),
      script_request_url_(script_request_url),
      options_(options),
      context_proxy_(context_proxy_factory(this)),
      factory_client_(
          Platform::Current()->CreateDedicatedWorkerHostFactoryClient(
              this,
              GetExecutionContext()->GetBrowserInterfaceBroker())) {
  DCHECK(context->IsContextThread());
  DCHECK(script_request_url_.IsValid());
  DCHECK(context_proxy_);

  outside_fetch_client_settings_object_ =
      MakeGarbageCollected<FetchClientSettingsObjectSnapshot>(
          context->Fetcher()->GetProperties().GetFetchClientSettingsObject());
}

DedicatedWorker::~DedicatedWorker() = default;

void DedicatedWorker::Dispose() {
  DCHECK(!GetExecutionContext() || GetExecutionContext()->IsContextThread());
  context_proxy_->ParentObjectDestroyed();
  factory_client_.reset();
}

void DedicatedWorker::postMessage(ScriptState* script_state,
                                  const ScriptValue& message,
                                  HeapVector<ScriptValue> transfer,
                                  ExceptionState& exception_state) {
  PostMessageOptions* options = PostMessageOptions::Create();
  if (!transfer.empty())
    options->setTransfer(std::move(transfer));
  postMessage(script_state, message, options, exception_state);
}

void DedicatedWorker::postMessage(ScriptState* script_state,
                                  const ScriptValue& message,
                                  const PostMessageOptions* options,
                                  ExceptionState& exception_state) {
  DCHECK(!GetExecutionContext() || GetExecutionContext()->IsContextThread());
  if (!GetExecutionContext())
    return;

  BlinkTransferableMessage transferable_message;
  Transferables transferables;
  scoped_refptr<SerializedScriptValue> serialized_message =
      PostMessageHelper::SerializeMessageByMove(script_state->GetIsolate(),
                                                message, options, transferables,
                                                exception_state);
  if (exception_state.HadException())
    return;
  DCHECK(serialized_message);
  transferable_message.message = serialized_message;
  transferable_message.sender_origin =
      GetExecutionContext()->GetSecurityOrigin()->IsolatedCopy();

  // Disentangle the port in preparation for sending it to the remote context.
  transferable_message.ports = MessagePort::DisentanglePorts(
      ExecutionContext::From(script_state), transferables.message_ports,
      exception_state);
  if (exception_state.HadException())
    return;
  transferable_message.user_activation =
      PostMessageHelper::CreateUserActivationSnapshot(GetExecutionContext(),
                                                      options);

  transferable_message.sender_stack_trace_id =
      ThreadDebugger::From(script_state->GetIsolate())
          ->StoreCurrentStackTrace("Worker.postMessage");
  uint64_t trace_id = base::trace_event::GetNextGlobalTraceId();
  transferable_message.trace_id = trace_id;
  context_proxy_->PostMessageToWorkerGlobalScope(
      std::move(transferable_message));
  TRACE_EVENT_INSTANT(
      "devtools.timeline", "SchedulePostMessage", "data",
      [&](perfetto::TracedValue context) {
        inspector_schedule_post_message_event::Data(
            std::move(context), GetExecutionContext(), trace_id);
      },
      perfetto::Flow::Global(trace_id));  // SchedulePostMessage
}

void DedicatedWorker::PostCustomEvent(
    TaskType task_type,
    ScriptState* script_state,
    CrossThreadFunction<Event*(ScriptState*, CustomEventMessage)>
        event_factory_callback,
    CrossThreadFunction<Event*(ScriptState*)> event_factory_error_callback,
    const ScriptValue& message,
    HeapVector<ScriptValue> transfer,
    ExceptionState& exception_state) {
  CHECK(!GetExecutionContext() || GetExecutionContext()->IsContextThread());
  if (!GetExecutionContext()) {
    return;
  }

  StructuredSerializeOptions* options = StructuredSerializeOptions::Create();
  if (!transfer.empty()) {
    options->setTransfer(std::move(transfer));
  }
  CustomEventMessage transferable_message;
  Transferables transferables;

  if (!message.IsEmpty()) {
    scoped_refptr<SerializedScriptValue> serialized_message =
        PostMessageHelper::SerializeMessageByMove(
            script_state->GetIsolate(), message, options, transferables,
            exception_state);
    if (exception_state.HadException()) {
      return;
    }
    CHECK(serialized_message);
    transferable_message.message = serialized_message;
  }
  // Disentangle the port in preparation for sending it to the remote context.
  transferable_message.ports = MessagePort::DisentanglePorts(
      ExecutionContext::From(script_state), transferables.message_ports,
      exception_state);
  if (exception_state.HadException()) {
    return;
  }

  transferable_message.sender_stack_trace_id =
      ThreadDebugger::From(script_state->GetIsolate())
          ->StoreCurrentStackTrace("Worker.PostCustomEvent");
  uint64_t trace_id = base::trace_event::GetNextGlobalTraceId();
  transferable_message.trace_id = trace_id;
  context_proxy_->PostCustomEventToWorkerGlobalScope(
      task_type, std::move(event_factory_callback),
      std::move(event_factory_error_callback), std::move(transferable_message));
  TRACE_EVENT_INSTANT(
      "devtools.timeline", "SchedulePostCustomEvent", "data",
      [&](perfetto::TracedValue context) {
        inspector_schedule_post_message_event::Data(
            std::move(context), GetExecutionContext(), trace_id);
      },
      perfetto::Flow::Global(trace_id));  // SchedulePostCustomEvent
}

// https://html.spec.whatwg.org/C/#worker-processing-model
void DedicatedWorker::Start() {
  TRACE_EVENT("blink.worker", "DedicatedWorker::Start");
  DCHECK(GetExecutionContext()->IsContextThread());
  start_time_ = base::TimeTicks::Now();

  // This needs to be done after the UpdateStateIfNeeded is called as
  // calling into the debugger can cause a breakpoint.
  v8_stack_trace_id_ = ThreadDebugger::From(GetExecutionContext()->GetIsolate())
                           ->StoreCurrentStackTrace("Worker Created");
  if (base::FeatureList::IsEnabled(features::kPlzDedicatedWorker)) {
    TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("blink.worker",
                                      "PlzDedicatedWorker Specific Setup",
                                      TRACE_ID_LOCAL(this));
    // For classic script, always use "same-origin" credentials mode.
    // https://html.spec.whatwg.org/C/#fetch-a-classic-worker-script
    // For module script, respect the credentials mode specified by
    // WorkerOptions.
    // https://html.spec.whatwg.org/C/#workeroptions
    auto credentials_mode = network::mojom::CredentialsMode::kSameOrigin;
    if (options_->type() == script_type_names::kModule) {
      credentials_mode = Request::V8RequestCredentialsToCredentialsMode(
          options_->credentials().AsEnum());
    }

    mojo::PendingRemote<mojom::blink::BlobURLToken> blob_url_token;
    if (script_request_url_.ProtocolIs("blob")) {
      GetExecutionContext()->GetPublicURLManager().ResolveForWorkerScriptFetch(
          script_request_url_, blob_url_token.InitWithNewPipeAndPassReceiver());
    }

    factory_client_->CreateWorkerHost(
        token_, script_request_url_, credentials_mode,
        WebFetchClientSettingsObject(*outside_fetch_client_settings_object_),
        std::move(blob_url_token),
        GetExecutionContext()->GetStorageAccessApiStatus());
    // Continue in OnScriptLoadStarted() or OnScriptLoadStartFailed().
    return;
  }

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("blink.worker",
                                    "LegacyDedicatedWorker Specific Setup",
                                    TRACE_ID_LOCAL(this));
  mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
      blob_url_loader_factory;
  if (script_request_url_.ProtocolIs("blob")) {
    GetExecutionContext()->GetPublicURLManager().Resolve(
        script_request_url_,
        blob_url_loader_factory.InitWithNewPipeAndPassReceiver());
  }

  // Calculate the origin on the renderer side when PlzDedicatedWorker is not
  // enabled, as the starting of the worker will not wait for the browser side
  // host creation and origin calculation. This follows the existing logic at
  // worker_global_scope.cc, so see the comments there for details.
  if (script_request_url_.ProtocolIsData()) {
    origin_ =
        GetExecutionContext()->GetSecurityOrigin()->DeriveNewOpaqueOrigin();
  } else {
    origin_ = GetExecutionContext()->GetSecurityOrigin()->IsolatedCopy();
  }

  if (GetExecutionContext()->GetSecurityOrigin()->IsLocal()) {
    // Local resources always have empty COEP, and Worker creation
    // from a blob URL in a local resource cannot work with
    // asynchronous OnHostCreated call, so we call it directly here.
    // See https://crbug.com/1101603#c8.
    factory_client_->CreateWorkerHostDeprecated(token_, script_request_url_,
                                                WebSecurityOrigin(origin_),
                                                base::DoNothing());
    OnHostCreated(std::move(blob_url_loader_factory),
                  network::CrossOriginEmbedderPolicy(), mojo::NullRemote());
    return;
  }

  factory_client_->CreateWorkerHostDeprecated(
      token_, script_request_url_, WebSecurityOrigin(origin_),
      WTF::BindOnce(&DedicatedWorker::OnHostCreated, WrapWeakPersistent(this),
                    std::move(blob_url_loader_factory)));
}

void DedicatedWorker::OnHostCreated(
    mojo::PendingRemote<network::mojom::blink::URLLoaderFactory>
        blob_url_loader_factory,
    const network::CrossOriginEmbedderPolicy& parent_coep,
    CrossVariantMojoRemote<
        mojom::blink::BackForwardCacheControllerHostInterfaceBase>
        back_forward_cache_controller_host) {
  DCHECK(!base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
  const RejectCoepUnsafeNone reject_coep_unsafe_none(
      network::CompatibleWithCrossOriginIsolated(parent_coep));
  if (options_->type() == script_type_names::kClassic) {
    // Legacy code path (to be deprecated, see https://crbug.com/835717):
    // A worker thread will start after scripts are fetched on the current
    // thread.
    classic_script_loader_ = MakeGarbageCollected<WorkerClassicScriptLoader>();
    classic_script_loader_->LoadTopLevelScriptAsynchronously(
        *GetExecutionContext(), GetExecutionContext()->Fetcher(),
        script_request_url_, nullptr /* worker_main_script_load_params */,
        mojom::blink::RequestContextType::WORKER,
        network::mojom::RequestDestination::kWorker,
        network::mojom::RequestMode::kSameOrigin,
        network::mojom::CredentialsMode::kSameOrigin,
        WTF::BindOnce(&DedicatedWorker::OnResponse, WrapPersistent(this)),
        WTF::BindOnce(&DedicatedWorker::OnFinished, WrapPersistent(this),
                      std::move(back_forward_cache_controller_host)),
        reject_coep_unsafe_none, std::move(blob_url_loader_factory));
    return;
  }
  if (options_->type() == script_type_names::kModule) {
    // Specify empty source code etc. here because scripts will be fetched on
    // the worker thread.
    ContinueStart(script_request_url_,
                  nullptr /* worker_main_script_load_params */,
                  network::mojom::ReferrerPolicy::kDefault,
                  Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
                  String() /* source_code */, reject_coep_unsafe_none,
                  std::move(back_forward_cache_controller_host));
    return;
  }
  NOTREACHED() << "Invalid type: " << IDLEnumAsString(options_->type());
}

void DedicatedWorker::terminate() {
  DCHECK(!GetExecutionContext() || GetExecutionContext()->IsContextThread());
  context_proxy_->TerminateGlobalScope();
}

void DedicatedWorker::ContextDestroyed() {
  DCHECK(GetExecutionContext()->IsContextThread());
  if (classic_script_loader_)
    classic_script_loader_->Cancel();
  factory_client_.reset();
  terminate();
}

bool DedicatedWorker::HasPendingActivity() const {
  DCHECK(!GetExecutionContext() || GetExecutionContext()->IsContextThread());
  // The worker context does not exist while loading, so we must ensure that the
  // worker object is not collected, nor are its event listeners.
  return context_proxy_->HasPendingActivity() || classic_script_loader_;
}

void DedicatedWorker::OnWorkerHostCreated(
    CrossVariantMojoRemote<mojom::blink::BrowserInterfaceBrokerInterfaceBase>
        browser_interface_broker,
    CrossVariantMojoRemote<mojom::blink::DedicatedWorkerHostInterfaceBase>
        dedicated_worker_host,
    const WebSecurityOrigin& origin) {
  TRACE_EVENT("blink.worker", "DedicatedWorker::OnWorkerHostCreated");
  base::UmaHistogramTimes("Worker.TopLevelScript.WorkerHostCreatedTime",
                          base::TimeTicks::Now() - start_time_);
  DCHECK(!browser_interface_broker_);
  browser_interface_broker_ = std::move(browser_interface_broker);
  pending_dedicated_worker_host_ = std::move(dedicated_worker_host);
  origin_ = blink::SecurityOrigin::CreateFromUrlOrigin(url::Origin(origin));
}

void DedicatedWorker::OnScriptLoadStarted(
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    CrossVariantMojoRemote<
        mojom::blink::BackForwardCacheControllerHostInterfaceBase>
        back_forward_cache_controller_host) {
  DCHECK(base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
  TRACE_EVENT_NESTABLE_ASYNC_END0("blink.worker",
                                  "PlzDedicatedWorker Specific Setup",
                                  TRACE_ID_LOCAL(this));
  TRACE_EVENT("blink.worker", "DedicatedWorker::OnScriptLoadStarted");
  // Specify empty source code here because scripts will be fetched on the
  // worker thread.
  ContinueStart(script_request_url_, std::move(worker_main_script_load_params),
                network::mojom::ReferrerPolicy::kDefault,
                Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
                String() /* source_code */, RejectCoepUnsafeNone(false),
                std::move(back_forward_cache_controller_host));
}

void DedicatedWorker::OnScriptLoadStartFailed() {
  DCHECK(base::FeatureList::IsEnabled(features::kPlzDedicatedWorker));
  TRACE_EVENT_NESTABLE_ASYNC_END0("blink.worker",
                                  "PlzDedicatedWorker Specific Setup",
                                  TRACE_ID_LOCAL(this));
  TRACE_EVENT("blink.worker", "DedicatedWorker::OnScriptLoadStartFailed");
  // Specify empty source code here because scripts will be fetched on the
  context_proxy_->DidFailToFetchScript();
  factory_client_.reset();
}

void DedicatedWorker::DispatchErrorEventForScriptFetchFailure() {
  DCHECK(!GetExecutionContext() || GetExecutionContext()->IsContextThread());
  // TODO(nhiroki): Add a console error message.
  DispatchEvent(*Event::CreateCancelable(event_type_names::kError));
}

std::unique_ptr<WebContentSettingsClient>
DedicatedWorker::CreateWebContentSettingsClient() {
  std::unique_ptr<WebContentSettingsClient> content_settings_client;
  if (auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext())) {
    return window->GetFrame()->Client()->CreateWorkerContentSettingsClient();
  } else if (GetExecutionContext()->IsWorkerGlobalScope()) {
    WebContentSettingsClient* web_worker_content_settings_client =
        To<WorkerGlobalScope>(GetExecutionContext())->ContentSettingsClient();
    if (web_worker_content_settings_client)
      return web_worker_content_settings_client->Clone();
  }
  return nullptr;
}

void DedicatedWorker::OnResponse() {
  DCHECK(GetExecutionContext()->IsContextThread());
  probe::DidReceiveScriptResponse(GetExecutionContext(),
                                  classic_script_loader_->Identifier());
}

void DedicatedWorker::OnFinished(
    mojo::PendingRemote<mojom::blink::BackForwardCacheControllerHost>
        back_forward_cache_controller_host) {
  DCHECK(GetExecutionContext()->IsContextThread());
  TRACE_EVENT("blink.worker", "DedicatedWorker::OnFinished");
  TRACE_EVENT_NESTABLE_ASYNC_END0("blink.worker",
                                  "LegacyDedicatedWorker Specific Setup",
                                  TRACE_ID_LOCAL(this));
  if (classic_script_loader_->Canceled()) {
    // Do nothing.
  } else if (classic_script_loader_->Failed()) {
    context_proxy_->DidFailToFetchScript();
  } else {
    network::mojom::ReferrerPolicy referrer_policy =
        network::mojom::ReferrerPolicy::kDefault;
    if (!classic_script_loader_->GetReferrerPolicy().IsNull()) {
      SecurityPolicy::ReferrerPolicyFromHeaderValue(
          classic_script_loader_->GetReferrerPolicy(),
          kDoNotSupportReferrerPolicyLegacyKeywords, &referrer_policy);
    }
    const KURL script_response_url = classic_script_loader_->ResponseURL();
    DCHECK(script_request_url_ == script_response_url ||
           SecurityOrigin::AreSameOrigin(script_request_url_,
                                         script_response_url));
    ContinueStart(
        script_response_url, nullptr /* worker_main_script_load_params */,
        referrer_policy,
        classic_script_loader_->GetContentSecurityPolicy()
            ? mojo::Clone(classic_script_loader_->GetContentSecurityPolicy()
                              ->GetParsedPolicies())
            : Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
        classic_script_loader_->SourceText(), RejectCoepUnsafeNone(false),
        std::move(back_forward_cache_controller_host));
    probe::ScriptImported(GetExecutionContext(),
                          classic_script_loader_->Identifier(),
                          classic_script_loader_->SourceText());
  }
  classic_script_loader_ = nullptr;
}

void DedicatedWorker::ContinueStart(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    network::mojom::ReferrerPolicy referrer_policy,
    Vector<network::mojom::blink::ContentSecurityPolicyPtr>
        response_content_security_policies,
    const String& source_code,
    RejectCoepUnsafeNone reject_coep_unsafe_none,
    mojo::PendingRemote<mojom::blink::BackForwardCacheControllerHost>
        back_forward_cache_controller_host) {
  UMA_HISTOGRAM_TIMES("Worker.TopLevelScript.LoadStartedTime",
                      base::TimeTicks::Now() - start_time_);
  TRACE_EVENT("blink.worker", "DedicatedWorker::ContinueStart");
  if (base::FeatureList::IsEnabled(
          features::kDedicatedWorkerAblationStudyEnabled)) {
    CHECK(GetExecutionContext());
    TRACE_EVENT("blink.worker", "DedicatedWorkerAblationStudyEnabled",
                "DedicatedWorkerStartDelayInMs",
                features::kDedicatedWorkerStartDelayInMs.Get());
    GetExecutionContext()
        ->GetTaskRunner(TaskType::kInternalDefault)
        ->PostDelayedTask(
            FROM_HERE,
            WTF::BindOnce(&DedicatedWorker::ContinueStartInternal,
                          WrapWeakPersistent(this), script_url,
                          std::move(worker_main_script_load_params),
                          std::move(referrer_policy),
                          std::move(response_content_security_policies),
                          source_code, reject_coep_unsafe_none,
                          std::move(back_forward_cache_controller_host)),
            base::Milliseconds(features::kDedicatedWorkerStartDelayInMs.Get()));
    return;
  }
  ContinueStartInternal(script_url, std::move(worker_main_script_load_params),
                        std::move(referrer_policy),
                        std::move(response_content_security_policies),
                        source_code, reject_coep_unsafe_none,
                        std::move(back_forward_cache_controller_host));
}

void DedicatedWorker::ContinueStartInternal(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    network::mojom::ReferrerPolicy referrer_policy,
    Vector<network::mojom::blink::ContentSecurityPolicyPtr>
        response_content_security_policies,
    const String& source_code,
    RejectCoepUnsafeNone reject_coep_unsafe_none,
    mojo::PendingRemote<mojom::blink::BackForwardCacheControllerHost>
        back_forward_cache_controller_host) {
  TRACE_EVENT("blink.worker", "DedicatedWorker::ContinueStartInternal");
  if (!GetExecutionContext()) {
    return;
  }
  context_proxy_->StartWorkerGlobalScope(
      CreateGlobalScopeCreationParams(
          script_url, referrer_policy,
          std::move(response_content_security_policies)),
      std::move(worker_main_script_load_params), options_, script_url,
      *outside_fetch_client_settings_object_, v8_stack_trace_id_, source_code,
      reject_coep_unsafe_none, token_,
      std::move(pending_dedicated_worker_host_),
      std::move(back_forward_cache_controller_host));
}

namespace {

BeginFrameProviderParams CreateBeginFrameProviderParams(
    ExecutionContext& execution_context) {
  DCHECK(execution_context.IsContextThread());
  // If we don't have a frame or we are not in window, some of the SinkIds
  // won't be initialized. If that's the case, the Worker will initialize it by
  // itself later.
  BeginFrameProviderParams begin_frame_provider_params;
  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    auto* web_local_frame = WebLocalFrameImpl::FromFrame(window->GetFrame());
    if (web_local_frame) {
      WebFrameWidgetImpl* widget = web_local_frame->LocalRootFrameWidget();
      begin_frame_provider_params.parent_frame_sink_id =
          widget->GetFrameSinkId();
    }
    begin_frame_provider_params.frame_sink_id =
        Platform::Current()->GenerateFrameSinkId();
  }
  return begin_frame_provider_params;
}

}  // namespace

std::unique_ptr<GlobalScopeCreationParams>
DedicatedWorker::CreateGlobalScopeCreationParams(
    const KURL& script_url,
    network::mojom::ReferrerPolicy referrer_policy,
    Vector<network::mojom::blink::ContentSecurityPolicyPtr>
        response_content_security_policies) {
  base::UnguessableToken parent_devtools_token;
  std::unique_ptr<WorkerSettings> settings;
  ExecutionContext* execution_context = GetExecutionContext();
  scoped_refptr<base::SingleThreadTaskRunner>
      agent_group_scheduler_compositor_task_runner;
  const SecurityOrigin* top_level_frame_security_origin;

  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    // When the main thread creates a new DedicatedWorker.
    auto* frame = window->GetFrame();
    parent_devtools_token = frame->GetDevToolsFrameToken();
    settings = std::make_unique<WorkerSettings>(frame->GetSettings());
    agent_group_scheduler_compositor_task_runner =
        execution_context->GetScheduler()
            ->ToFrameScheduler()
            ->GetAgentGroupScheduler()
            ->CompositorTaskRunner();
    top_level_frame_security_origin =
        window->GetFrame()->Top()->GetSecurityContext()->GetSecurityOrigin();
  } else {
    // When a DedicatedWorker creates another DedicatedWorker (nested worker).
    WorkerGlobalScope* worker_global_scope =
        To<WorkerGlobalScope>(execution_context);
    parent_devtools_token =
        worker_global_scope->GetThread()->GetDevToolsWorkerToken();
    settings = WorkerSettings::Copy(worker_global_scope->GetWorkerSettings());
    agent_group_scheduler_compositor_task_runner =
        worker_global_scope->GetAgentGroupSchedulerCompositorTaskRunner();
    top_level_frame_security_origin =
        worker_global_scope->top_level_frame_security_origin();
  }
  DCHECK(agent_group_scheduler_compositor_task_runner);
  DCHECK(top_level_frame_security_origin);

  mojom::blink::ScriptType script_type =
      (options_->type() == script_type_names::kClassic)
          ? mojom::blink::ScriptType::kClassic
          : mojom::blink::ScriptType::kModule;

  auto params = std::make_unique<GlobalScopeCreationParams>(
      script_url, script_type, options_->name(), execution_context->UserAgent(),
      execution_context->GetUserAgentMetadata(), CreateWebWorkerFetchContext(),
      mojo::Clone(
          execution_context->GetContentSecurityPolicy()->GetParsedPolicies()),
      std::move(response_content_security_policies), referrer_policy,
      execution_context->GetSecurityOrigin(),
      execution_context->IsSecureContext(), execution_context->GetHttpsState(),
      MakeGarbageCollected<WorkerClients>(), CreateWebContentSettingsClient(),
      OriginTrialContext::GetInheritedTrialFeatures(execution_context).get(),
      parent_devtools_token, std::move(settings),
      mojom::blink::V8CacheOptions::kDefault,
      nullptr /* worklet_module_responses_map */,
      std::move(browser_interface_broker_),
      mojo::NullRemote() /* code_cache_host_interface */,
      mojo::NullRemote() /* blob_url_store */,
      CreateBeginFrameProviderParams(*execution_context),
      execution_context->GetSecurityContext().GetPermissionsPolicy(),
      execution_context->GetAgentClusterID(), execution_context->UkmSourceID(),
      execution_context->GetExecutionContextToken(),
      execution_context->CrossOriginIsolatedCapability(),
      execution_context->IsIsolatedContext(),
      /*interface_registry=*/nullptr,
      std::move(agent_group_scheduler_compositor_task_runner),
      top_level_frame_security_origin,
      execution_context->GetStorageAccessApiStatus(),
      /*require_cross_site_request_for_cookies=*/false,
      origin_ ? origin_->IsolatedCopy() : nullptr);
  params->dedicated_worker_start_time = start_time_;
  return params;
}

scoped_refptr<WebWorkerFetchContext>
DedicatedWorker::CreateWebWorkerFetchContext() {
  // This worker is being created by the window.
  if (auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext())) {
    scoped_refptr<WebWorkerFetchContext> web_worker_fetch_context;
    LocalFrame* frame = window->GetFrame();
    if (base::FeatureList::IsEnabled(features::kPlzDedicatedWorker)) {
      web_worker_fetch_context =
          frame->Client()->CreateWorkerFetchContextForPlzDedicatedWorker(
              factory_client_.get());
    } else {
      web_worker_fetch_context = frame->Client()->CreateWorkerFetchContext();
    }
    web_worker_fetch_context->SetIsOnSubframe(!frame->IsOutermostMainFrame());
    return web_worker_fetch_context;
  }

  // This worker is being created by an existing worker
```