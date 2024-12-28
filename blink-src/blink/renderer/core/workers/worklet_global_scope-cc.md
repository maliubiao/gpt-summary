Response:
Let's break down the thought process for analyzing the `worklet_global_scope.cc` file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ source code and explain its purpose, relating it to web technologies (JavaScript, HTML, CSS) where applicable, and providing examples.

2. **Identify Key Information:** The first step is to scan the code for keywords, class names, and included headers that provide clues about its functionality. Some initial observations:

    * **Filename and Namespace:** `worklet_global_scope.cc` and the `blink` namespace immediately tell us this is part of the Blink rendering engine, specifically related to "worklets."
    * **Included Headers:** These are extremely informative. Spotting headers like:
        * `third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h`:  Indicates interaction with JavaScript execution.
        * `third_party/blink/renderer/core/frame/frame_console.h`, `third_party/blink/renderer/core/inspector/...`:  Suggests debugging and console logging capabilities.
        * `third_party/blink/renderer/core/loader/document_loader.h`:  Implies involvement in resource loading.
        * `third_party/blink/renderer/core/workers/...`: Confirms its role in the worker infrastructure.
        * `third_party/blink/public/mojom/...`: Points to inter-process communication using Mojo.
        * `services/metrics/public/cpp/mojo_ukm_recorder.h`:  Shows involvement with usage metrics.
    * **Class Definition:** The `WorkletGlobalScope` class itself is central.
    * **Constructor Overloads:**  Multiple constructors suggest different ways to initialize a `WorkletGlobalScope`. The parameters provide hints about the context in which it's created (main thread vs. worker thread).
    * **Method Names:**  Functions like `FetchAndInvokeScript`, `AddConsoleMessageImpl`, `ExceptionThrown`, `GetCodeCacheHost`, etc., reveal specific functionalities.

3. **Infer Functionality Based on Keywords and Context:**

    * **Worklets:** Recall or research what worklets are in the context of web development (lightweight, specialized workers). This provides a high-level understanding.
    * **`WorkletGlobalScope`'s Role:**  Based on the name and included headers, it's likely the C++ representation of the global scope within a worklet, analogous to the `window` object in a browser or the global scope in a Web Worker.
    * **Main Thread vs. Worker Thread:** The constructors and conditional logic (e.g., `IsMainThreadWorkletGlobalScope()`) clearly indicate that worklets can run on either the main thread or a separate worker thread. This is a key distinction.
    * **Script Execution:** The presence of `WorkerOrWorkletScriptController` and `FetchAndInvokeScript` strongly suggests the class is responsible for loading and executing JavaScript code within the worklet.
    * **Debugging and Logging:** The inclusion of console-related headers and methods like `AddConsoleMessageImpl` points to the ability to log messages from the worklet.
    * **Resource Loading:** `FetchModuleScript` indicates that worklets can fetch and load resources, likely JavaScript modules.
    * **Security:**  Headers related to `SecurityOrigin` and Content Security Policy (CSP) show that security is a concern.
    * **Inter-Process Communication:** The use of Mojo suggests communication with other parts of the Chromium browser.
    * **Metrics:** The UKM recorder shows that usage data is collected.

4. **Structure the Explanation:**  Organize the findings into logical categories. A good structure would be:

    * **Core Function:** A high-level summary of the class's purpose.
    * **Key Responsibilities:**  Break down the functionality into specific areas. This is where the analysis of headers and methods comes in.
    * **Relationships with Web Technologies:**  Explicitly connect the C++ code to JavaScript, HTML, and CSS concepts. This is crucial for understanding the practical implications.
    * **Examples:**  Provide concrete examples to illustrate the interactions. This makes the explanation more tangible.
    * **Logical Reasoning (Assumptions and Outputs):** For methods with clear inputs and outputs (like `CompleteURL`), provide examples of how they work.
    * **Common Errors:** Think about potential pitfalls for developers using worklets.

5. **Refine and Elaborate:**  Review the initial analysis and add more detail and clarity. For instance, explain *why* the `WorkletGlobalScope` needs access to things like the console or the document loader. Explain the implications of running on the main thread vs. a worker thread.

6. **Address Specific Instructions:**  Ensure all parts of the prompt are addressed, such as providing examples and explaining logical reasoning.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about running JavaScript."  **Correction:**  Realize it's more than just running scripts. It manages the *environment* in which those scripts run, including security, resource loading, and communication.
* **Initial thought:** "The headers are just implementation details." **Correction:**  Recognize that the included headers are *essential clues* to the class's functionality.
* **Initial thought:**  Focus solely on the code. **Correction:**  Remember to relate the code back to the user-facing web technologies (JavaScript, HTML, CSS).
* **Missing details:**  Initially overlook the `UkmRecorder`. **Correction:** Notice the relevant headers and methods and explain its role in metrics collection.

By following this systematic approach, combining code analysis with knowledge of web technologies, and continuously refining the understanding, we can generate a comprehensive and accurate explanation of the `WorkletGlobalScope` class.
好的，让我们来分析一下 `blink/renderer/core/workers/worklet_global_scope.cc` 这个 Blink 引擎源代码文件的功能。

**核心功能:**

`WorkletGlobalScope` 类是 Blink 渲染引擎中用于表示 Worklet 的全局作用域的对象。它类似于 Web Worker 的全局作用域，但用于更轻量级、更特定用途的脚本执行环境，例如 CSS Houdini Worklets (Paint Worklet, Animation Worklet, Layout Worklet 等) 和 Audio Worklet。

**详细功能分解:**

1. **Worklet 环境的建立和管理:**
   - **初始化:**  `WorkletGlobalScope` 的构造函数负责初始化 Worklet 的运行环境，包括：
     - 设置安全源 (SecurityOrigin)。
     - 创建 V8 隔离区 (Isolate) 的代理 (Agent)。
     - 设置全局作用域名称。
     - 处理内容安全策略 (CSP)。
     - 管理模块响应映射 (`module_responses_map_`)，用于缓存已加载的模块。
     - 关联父上下文的信息，如父 frame 的 Token (`frame_token_`) 和跨域隔离能力 (`parent_cross_origin_isolated_capability_`).
   - **线程管理:**  区分 Worklet 运行在主线程 (`ThreadType::kMainThread`) 还是独立的 Worker 线程 (`ThreadType::kOffMainThread`)，并根据线程类型进行相应的资源管理和操作。
   - **生命周期管理:**  `Dispose()` 方法用于清理 Worklet 的资源。

2. **脚本的加载和执行:**
   - **`FetchAndInvokeScript`:**  负责获取并执行 Worklet 的脚本。这涉及到网络请求、模块加载和 JavaScript 代码的执行。它使用了 `WorkletModuleTreeClient` 来处理模块依赖关系和加载完成后的通知。
   - **`ScriptController()`:** 提供访问脚本控制器的接口，用于执行 JavaScript 代码。

3. **与 JavaScript 的交互:**
   - **全局对象:** `WorkletGlobalScope` 本身就是 Worklet 中 JavaScript 代码的全局对象 (`this` 指向它）。
   - **Console API:**  `AddConsoleMessageImpl` 方法允许 Worklet 中的 JavaScript 代码使用 `console` API 打印消息。这些消息会被转发到开发者工具的 Console 面板。
   - **错误处理:** `ExceptionThrown` 方法处理 Worklet 中抛出的 JavaScript 异常，并将其报告给开发者工具。

4. **与 HTML 和 CSS 的关系 (通过 Worklets):**
   - **CSS Houdini Worklets:** `WorkletGlobalScope` 是 Paint Worklet、Animation Worklet 和 Layout Worklet 的基础。
     - **Paint Worklet:** JavaScript 代码可以在 Paint Worklet 中注册自定义的绘制逻辑，用于绘制 CSS `background-image` 或 `border-image`。
       - **示例:** 一个 Paint Worklet 可以绘制复杂的图案或动画背景。
       - **HTML/CSS:** 在 CSS 中通过 `paint()` 函数引用注册的 Paint Worklet：
         ```css
         .my-element {
           background-image: paint(myPainter);
         }
         ```
     - **Animation Worklet:**  允许 JavaScript 代码驱动高性能的动画效果，绕过主线程的瓶颈。
       - **示例:**  创建一个平滑过渡的自定义动画。
       - **JavaScript:**  在 Animation Worklet 中注册动画时间线和效果。
     - **Layout Worklet:**  允许 JavaScript 代码自定义元素的布局方式。
       - **示例:** 实现瀑布流布局或 Masonry 布局。
   - **Audio Worklet:**  允许 JavaScript 代码直接处理音频流，进行音频合成、处理和分析。
     - **示例:**  创建一个自定义的音频合成器或音频效果器。
     - **JavaScript:**  在 AudioWorkletGlobalScope 中注册音频处理器。

5. **与其他 Blink 组件的交互:**
   - **`WorkerReportingProxy`:** 用于向主线程报告错误、控制台消息等。
   - **`Inspector...` 组件:**  用于支持开发者工具的调试功能，例如显示控制台消息、异常信息等。
   - **`DocumentLoader`:** (仅限主线程 Worklet)  用于获取代码缓存宿主 (`CodeCacheHost`)，优化脚本加载性能。
   - **`FrameConsole`:** (仅限主线程 Worklet) 用于将控制台消息添加到所属 frame 的控制台。
   - **`WorkerThreadDebugger` / `MainThreadDebugger`:** 用于支持 JavaScript 代码的断点调试。
   - **`OriginTrialContext`:** 用于激活 Origin Trials 的特性。
   - **`UkmRecorder`:** 用于记录用户行为指标 (UKM)。
   - **`BrowserInterfaceBrokerProxy`:** 用于与浏览器进程进行通信，获取浏览器提供的服务。

**逻辑推理 (假设输入与输出):**

假设 Worklet 的 JavaScript 代码中调用了 `console.log("Hello from Worklet!");`

* **输入:**
    - Worklet 的 JavaScript 代码执行到 `console.log("Hello from Worklet!");`。
    - V8 引擎将调用传递给 Blink 的 Console API 实现。
* **处理:**
    - `WorkletGlobalScope::AddConsoleMessageImpl` 方法会被调用。
    - 根据 Worklet 运行的线程：
        - **主线程:**  消息会被添加到关联的 `FrameConsole`，最终显示在开发者工具的 Console 面板中。
        - **Worker 线程:** 消息会被发送到 `WorkerReportingProxy`，然后转发到主线程的 Console 并存储在 `ConsoleMessageStorage` 中。
* **输出:**
    - 开发者工具的 Console 面板会显示 "Hello from Worklet!" 消息。

**用户或编程常见的使用错误:**

1. **在不合适的上下文中使用 Worklet API:**  例如，尝试在普通的 JavaScript 代码中使用 Paint Worklet 的 API。Paint Worklet 的代码只能在 Paint Worklet 的全局作用域中执行。
2. **跨域问题:**  Worklet 加载的脚本受到同源策略的限制。尝试加载来自不同源的模块可能会失败，除非配置了适当的 CORS 头。
3. **Worklet 内部状态管理不当:**  Worklet 的生命周期与创建它的上下文相关联。不正确地管理 Worklet 的状态可能导致意外的行为或资源泄漏。
4. **性能问题:**  虽然 Worklet 旨在提高性能，但编写低效的 Worklet 代码仍然可能导致性能问题。例如，在 Paint Worklet 中执行复杂的计算可能会阻塞渲染。
5. **忘记注册 Worklet 模块:**  在使用 CSS Houdini Worklet 之前，需要在 JavaScript 中使用 `CSS.paintWorklet.addModule()` 或类似的 API 注册 Worklet 脚本。忘记注册会导致 CSS 中无法识别该 Worklet。
6. **AudioWorklet 处理器的输入/输出格式不匹配:** 在 AudioWorklet 中，音频处理器的输入和输出必须是特定的格式 (例如，浮点数数组)。格式不匹配会导致音频处理失败。

总而言之，`WorkletGlobalScope` 是 Blink 引擎中 Worklet 功能的核心，负责创建、管理 Worklet 的运行环境，加载和执行脚本，并与浏览器的其他组件进行交互，使得开发者可以使用 Worklet 技术来扩展 Web 平台的能力。

Prompt: 
```
这是目录为blink/renderer/core/workers/worklet_global_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"

#include <memory>

#include "base/task/single_thread_task_runner.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/console_message_storage.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_storage.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/inspector/worker_inspector_controller.h"
#include "third_party/blink/renderer/core/inspector/worker_thread_debugger.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/core/workers/worklet_module_responses_map.h"
#include "third_party/blink/renderer/core/workers/worklet_module_tree_client.h"
#include "third_party/blink/renderer/core/workers/worklet_pending_tasks.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"

namespace blink {

WorkletGlobalScope::WorkletGlobalScope(
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    WorkerReportingProxy& reporting_proxy,
    LocalFrame* frame)
    : WorkletGlobalScope(std::move(creation_params),
                         reporting_proxy,
                         ToIsolate(frame),
                         ThreadType::kMainThread,
                         frame,
                         nullptr /* worker_thread */) {}

WorkletGlobalScope::WorkletGlobalScope(
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    WorkerReportingProxy& reporting_proxy,
    WorkerThread* worker_thread)
    : WorkletGlobalScope(std::move(creation_params),
                         reporting_proxy,
                         worker_thread->GetIsolate(),
                         ThreadType::kOffMainThread,
                         nullptr /* frame */,
                         worker_thread) {}

// Partial implementation of the "set up a worklet environment settings object"
// algorithm:
// https://drafts.css-houdini.org/worklets/#script-settings-for-worklets
WorkletGlobalScope::WorkletGlobalScope(
    std::unique_ptr<GlobalScopeCreationParams> creation_params,
    WorkerReportingProxy& reporting_proxy,
    v8::Isolate* isolate,
    ThreadType thread_type,
    LocalFrame* frame,
    WorkerThread* worker_thread)
    : WorkerOrWorkletGlobalScope(
          isolate,
          SecurityOrigin::CreateUniqueOpaque(),
          creation_params->starter_secure_context,
          MakeGarbageCollected<Agent>(
              isolate,
              creation_params->agent_cluster_id,
              v8::MicrotaskQueue::New(isolate, v8::MicrotasksPolicy::kScoped)),
          creation_params->global_scope_name,
          creation_params->parent_devtools_token,
          creation_params->v8_cache_options,
          creation_params->worker_clients,
          std::move(creation_params->content_settings_client),
          std::move(creation_params->web_worker_fetch_context),
          reporting_proxy,
          /*is_worker_loaded_from_data_url=*/false,
          /*is_default_world_of_isolate=*/
          creation_params->is_default_world_of_isolate),
      ActiveScriptWrappable<WorkletGlobalScope>({}),
      url_(creation_params->script_url),
      user_agent_(creation_params->user_agent),
      document_security_origin_(creation_params->starter_origin),
      module_responses_map_(creation_params->module_responses_map),
      // Step 4. "Let inheritedHTTPSState be outsideSettings's HTTPS state."
      https_state_(creation_params->starter_https_state),
      thread_type_(thread_type),
      frame_(frame),
      worker_thread_(worker_thread),
      // Worklets should often have a parent LocalFrameToken. Only shared
      // storage worklet does not have it.
      frame_token_(
          creation_params->parent_context_token
              ? creation_params->parent_context_token->GetAs<LocalFrameToken>()
              : blink::LocalFrameToken()),
      parent_cross_origin_isolated_capability_(
          creation_params->parent_cross_origin_isolated_capability),
      parent_is_isolated_context_(creation_params->parent_is_isolated_context),
      browser_interface_broker_proxy_(this) {
  DCHECK((thread_type_ == ThreadType::kMainThread && frame_) ||
         (thread_type_ == ThreadType::kOffMainThread && worker_thread_));

  // Default world implies that we are at least off main thread. Off main
  // thread may still have cases where threads are shared between multiple
  // worklets (and thus the Isolate may not be owned by this world)..
  CHECK(!creation_params->is_default_world_of_isolate ||
        thread_type == ThreadType::kOffMainThread);

  // Worklet should be in the owner's agent cluster.
  // https://html.spec.whatwg.org/C/#obtain-a-worklet-agent
  DCHECK(creation_params->agent_cluster_id ||
         !creation_params->parent_context_token);

  // Step 2: "Let inheritedAPIBaseURL be outsideSettings's API base URL."
  // |url_| is the inheritedAPIBaseURL passed from the parent Document.

  // Step 5: "Let inheritedReferrerPolicy be outsideSettings's referrer policy."
  SetReferrerPolicy(creation_params->referrer_policy);

  SetOutsideContentSecurityPolicies(
      mojo::Clone(creation_params->outside_content_security_policies));

  // https://drafts.css-houdini.org/worklets/#creating-a-workletglobalscope
  // Step 6: "Invoke the initialize a global object's CSP list algorithm given
  // workletGlobalScope."
  InitContentSecurityPolicyFromVector(
      std::move(creation_params->outside_content_security_policies));
  BindContentSecurityPolicyToExecutionContext();

  OriginTrialContext::ActivateWorkerInheritedFeatures(
      this, creation_params->inherited_trial_features.get());

  // WorkletGlobalScopes are not currently provided with UKM source IDs.
  DCHECK_EQ(creation_params->ukm_source_id, ukm::kInvalidSourceId);

  if (creation_params->code_cache_host_interface.is_valid()) {
    code_cache_host_ = std::make_unique<CodeCacheHost>(
        mojo::Remote<mojom::blink::CodeCacheHost>(
            std::move(creation_params->code_cache_host_interface)));
  }

  if (creation_params->browser_interface_broker.is_valid()) {
    browser_interface_broker_proxy_.Bind(
        ToCrossVariantMojoType(
            std::move(creation_params->browser_interface_broker)),
        GetTaskRunner(TaskType::kInternalDefault));
  }

  blob_url_store_pending_remote_ = std::move(creation_params->blob_url_store);
}

WorkletGlobalScope::~WorkletGlobalScope() = default;

const BrowserInterfaceBrokerProxy&
WorkletGlobalScope::GetBrowserInterfaceBroker() const {
  if (browser_interface_broker_proxy_.is_bound()) {
    CHECK(IsSharedStorageWorkletGlobalScope());
    return browser_interface_broker_proxy_;
  }

  return GetEmptyBrowserInterfaceBroker();
}

bool WorkletGlobalScope::IsMainThreadWorkletGlobalScope() const {
  return thread_type_ == ThreadType::kMainThread;
}

bool WorkletGlobalScope::IsThreadedWorkletGlobalScope() const {
  return thread_type_ == ThreadType::kOffMainThread;
}

ExecutionContext* WorkletGlobalScope::GetExecutionContext() const {
  return const_cast<WorkletGlobalScope*>(this);
}

bool WorkletGlobalScope::IsContextThread() const {
  if (IsMainThreadWorkletGlobalScope())
    return IsMainThread();
  return worker_thread_->IsCurrentThread();
}

void WorkletGlobalScope::AddConsoleMessageImpl(ConsoleMessage* console_message,
                                               bool discard_duplicates) {
  if (IsMainThreadWorkletGlobalScope()) {
    frame_->Console().AddMessage(console_message, discard_duplicates);
    return;
  }
  worker_thread_->GetWorkerReportingProxy().ReportConsoleMessage(
      console_message->GetSource(), console_message->GetLevel(),
      console_message->Message(), console_message->Location());
  worker_thread_->GetConsoleMessageStorage()->AddConsoleMessage(
      worker_thread_->GlobalScope(), console_message, discard_duplicates);
}

void WorkletGlobalScope::AddInspectorIssue(AuditsIssue issue) {
  if (IsMainThreadWorkletGlobalScope()) {
    frame_->DomWindow()->AddInspectorIssue(std::move(issue));
  } else {
    worker_thread_->GetInspectorIssueStorage()->AddInspectorIssue(
        this, std::move(issue));
  }
}

void WorkletGlobalScope::ExceptionThrown(ErrorEvent* error_event) {
  if (IsMainThreadWorkletGlobalScope()) {
    MainThreadDebugger::Instance(GetIsolate())
        ->ExceptionThrown(this, error_event);
    return;
  }
  if (WorkerThreadDebugger* debugger =
          WorkerThreadDebugger::From(GetThread()->GetIsolate())) {
    debugger->ExceptionThrown(worker_thread_, error_event);
  }
}

void WorkletGlobalScope::Dispose() {
  frame_ = nullptr;
  worker_thread_ = nullptr;
  WorkerOrWorkletGlobalScope::Dispose();
}

WorkerThread* WorkletGlobalScope::GetThread() const {
  DCHECK(!IsMainThreadWorkletGlobalScope());
  return worker_thread_;
}

const base::UnguessableToken& WorkletGlobalScope::GetDevToolsToken() const {
  if (IsMainThreadWorkletGlobalScope()) {
    return frame_->GetDevToolsFrameToken();
  }
  return GetThread()->GetDevToolsWorkerToken();
}

CodeCacheHost* WorkletGlobalScope::GetCodeCacheHost() {
  if (IsMainThreadWorkletGlobalScope())
    return frame_->Loader().GetDocumentLoader()->GetCodeCacheHost();
  if (!code_cache_host_)
    return nullptr;
  return code_cache_host_.get();
}

CoreProbeSink* WorkletGlobalScope::GetProbeSink() {
  switch (thread_type_) {
    case ThreadType::kMainThread:
      DCHECK(frame_);
      return probe::ToCoreProbeSink(frame_);
    case ThreadType::kOffMainThread:
      DCHECK(worker_thread_);
      return worker_thread_->GetWorkerInspectorController()->GetProbeSink();
  }
}

scoped_refptr<base::SingleThreadTaskRunner> WorkletGlobalScope::GetTaskRunner(
    TaskType task_type) {
  if (IsMainThreadWorkletGlobalScope())
    return frame_->GetFrameScheduler()->GetTaskRunner(task_type);
  return worker_thread_->GetTaskRunner(task_type);
}

FrameOrWorkerScheduler* WorkletGlobalScope::GetScheduler() {
  DCHECK(IsContextThread());
  if (IsMainThreadWorkletGlobalScope())
    return frame_->GetFrameScheduler();
  return worker_thread_->GetScheduler();
}

LocalFrame* WorkletGlobalScope::GetFrame() const {
  DCHECK(IsMainThreadWorkletGlobalScope());
  return frame_.Get();
}

// Implementation of the first half of the "fetch and invoke a worklet script"
// algorithm:
// https://drafts.css-houdini.org/worklets/#fetch-and-invoke-a-worklet-script
void WorkletGlobalScope::FetchAndInvokeScript(
    const KURL& module_url_record,
    network::mojom::CredentialsMode credentials_mode,
    const FetchClientSettingsObjectSnapshot& outside_settings_object,
    WorkerResourceTimingNotifier& outside_resource_timing_notifier,
    scoped_refptr<base::SingleThreadTaskRunner> outside_settings_task_runner,
    WorkletPendingTasks* pending_tasks) {
  DCHECK(IsContextThread());

  // Step 1: "Let insideSettings be the workletGlobalScope's associated
  // environment settings object."
  // Step 2: "Let script by the result of fetch a worklet script given
  // moduleURLRecord, moduleResponsesMap, credentialOptions, outsideSettings,
  // and insideSettings when it asynchronously completes."

  // Step 3 to 5 are implemented in
  // WorkletModuleTreeClient::NotifyModuleTreeLoadFinished.
  auto* client = MakeGarbageCollected<WorkletModuleTreeClient>(
      ScriptController()->GetScriptState(),
      std::move(outside_settings_task_runner), pending_tasks);

  auto request_context_type = mojom::blink::RequestContextType::SCRIPT;
  FetchModuleScript(module_url_record, outside_settings_object,
                    outside_resource_timing_notifier, request_context_type,
                    GetDestination(), credentials_mode,
                    ModuleScriptCustomFetchType::kWorkletAddModule, client);
}

KURL WorkletGlobalScope::CompleteURL(const String& url) const {
  // Always return a null URL when passed a null string.
  // TODO(ikilpatrick): Should we change the KURL constructor to have this
  // behavior?
  if (url.IsNull())
    return KURL();
  // Always use UTF-8 in Worklets.
  return KURL(BaseURL(), url);
}

bool WorkletGlobalScope::CrossOriginIsolatedCapability() const {
  return parent_cross_origin_isolated_capability_;
}

bool WorkletGlobalScope::IsIsolatedContext() const {
  return parent_is_isolated_context_;
}

ukm::UkmRecorder* WorkletGlobalScope::UkmRecorder() {
  if (ukm_recorder_)
    return ukm_recorder_.get();

  mojo::Remote<ukm::mojom::UkmRecorderFactory> factory;
  GetBrowserInterfaceBroker().GetInterface(
      factory.BindNewPipeAndPassReceiver());
  ukm_recorder_ = ukm::MojoUkmRecorder::Create(*factory);

  return ukm_recorder_.get();
}

ukm::SourceId WorkletGlobalScope::UkmSourceID() const {
  return ukm::kInvalidSourceId;
}

mojo::PendingRemote<mojom::blink::BlobURLStore>
WorkletGlobalScope::TakeBlobUrlStorePendingRemote() {
  DCHECK(blob_url_store_pending_remote_.is_valid());
  return std::move(blob_url_store_pending_remote_);
}

void WorkletGlobalScope::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(browser_interface_broker_proxy_);
  WorkerOrWorkletGlobalScope::Trace(visitor);
}

bool WorkletGlobalScope::HasPendingActivity() const {
  return !ExecutionContext::IsContextDestroyed();
}

}  // namespace blink

"""

```