Response:
The user wants me to analyze the provided C++ code file `dedicated_worker_test.cc` from the Chromium Blink engine. I need to:

1. **List the functionalities** demonstrated in the code.
2. **Explain the relationship** between these functionalities and web technologies like JavaScript, HTML, and CSS, providing examples if applicable.
3. **Identify logical inferences** and provide examples of input and output.
4. **Point out common user or programming errors** that this code might help prevent or test for.
5. **Summarize the overall function** of this specific part of the code.

Based on the code, it seems to be a unit test file for the `DedicatedWorker` functionality in Blink. It focuses on testing the lifecycle, communication, and feature integration of dedicated workers.

Here's a breakdown of the key areas covered by the code:

*   **Worker Creation and Management:**  Setting up and tearing down dedicated worker instances.
*   **Message Passing:** Testing the `postMessage` API between the main thread and the worker. This includes scenarios for successful and failed deserialization of messages.
*   **Event Handling:** Testing the dispatch of `message` and `messageerror` events on both the worker object and the worker global scope.
*   **Use Counter Integration:** Verifying that API usage within the worker is correctly recorded by the browser's use counter mechanism.
*   **Task Runner Management:** Ensuring that tasks within the worker execute on the correct thread.
*   **Security Origin:**  Testing the proper propagation of security origins to worker contexts, especially for nested workers.
*   **Custom Events:** Demonstrating the ability to dispatch and handle custom events within the worker.
这是对 `blink/renderer/core/workers/dedicated_worker_test.cc` 文件第一部分的分析和功能归纳。

**功能列举:**

1. **DedicatedWorker 的创建和管理:**  这段代码定义了用于测试 `DedicatedWorker` 及其相关组件（如 `DedicatedWorkerThread`, `DedicatedWorkerGlobalScope`, `DedicatedWorkerMessagingProxy`, `DedicatedWorkerObjectProxy`）的测试类和辅助方法。它展示了如何创建 `DedicatedWorker` 实例，并模拟其启动和终止过程。
2. **消息传递测试:**  代码中包含了测试主线程和 DedicatedWorker 之间消息传递的机制。这包括测试 `postMessage` 方法，以及处理消息序列化和反序列化的场景。
3. **事件处理测试:**  这段代码测试了 DedicatedWorker 中事件的派发和处理，例如 `message` 和 `messageerror` 事件。它验证了这些事件能够在 Worker 对象和 Worker 全局作用域中被正确触发和捕获。
4. **UseCounter 集成测试:** 代码包含了测试 DedicatedWorker 中 API 使用情况如何被 UseCounter 记录的逻辑。UseCounter 是 Chromium 用来统计特定 Web API 使用频率的机制。
5. **任务调度测试:** 代码展示了如何测试 DedicatedWorker 内部的任务调度器，确保任务在正确的线程上执行。
6. **安全上下文测试:** 代码测试了 DedicatedWorker 的安全上下文，特别是顶级 frame 的安全 origin 如何被正确设置和传递，包括在嵌套 Worker 的场景中。
7. **自定义事件测试:**  代码定义了自定义事件 `CustomEventWithData` 及其工厂方法，用于测试 DedicatedWorker 如何处理和传递自定义事件。

**与 JavaScript, HTML, CSS 的关系及举例:**

1. **JavaScript:** DedicatedWorker 的核心功能是允许 JavaScript 代码在后台线程中运行。这段测试代码模拟了主线程向 DedicatedWorker 发送消息 (`postMessage`)，以及 DedicatedWorker 向主线程发送消息的场景。
    *   **举例:** 主线程可以发送一个包含 JSON 数据的字符串给 Worker：`worker.postMessage(JSON.stringify({action: 'processData', data: [1, 2, 3]}));`。测试代码会验证 Worker 是否收到了这条消息，并能正确反序列化 JSON 数据。
2. **HTML:**  HTML 可以通过 `<script>` 标签或 JavaScript 代码创建和启动 DedicatedWorker。测试代码模拟了这种启动过程，并通过 `KURL("http://fake.url/")` 等方式指定 Worker 脚本的 URL。
    *   **举例:**  HTML 中创建 DedicatedWorker 的代码可能是：`const worker = new Worker('worker.js');`。测试代码模拟了这种创建，并验证了 Worker 实例被正确创建。
3. **CSS:**  DedicatedWorker 本身不能直接操作 DOM 或 CSSOM。但是，DedicatedWorker 可以执行耗时的计算任务，避免阻塞主线程，从而提高页面渲染性能，间接地影响用户体验。测试代码通过模拟耗时操作或消息传递来验证 Worker 的隔离性和独立性。
    *   **举例:**  Worker 可以进行复杂的 CSS 动画计算，并将结果返回给主线程，由主线程更新 DOM。测试代码可以模拟这种计算过程和消息传递。

**逻辑推理及假设输入与输出:**

1. **假设输入:** 主线程向 DedicatedWorker 发送一个包含字符串 "hello" 的消息。
    *   **逻辑推理:** 测试代码会模拟消息的序列化、跨线程传递和反序列化。在 DedicatedWorker 内部，应该能够接收到这个字符串消息。
    *   **输出:** DedicatedWorker 的事件监听器应该接收到一个 `MessageEvent` 对象，其 `data` 属性值为 "hello"。
2. **假设输入:** 主线程尝试向 DedicatedWorker 发送一个无法被反序列化的对象（例如，包含循环引用的对象）。
    *   **逻辑推理:** 测试代码会设置反序列化失败的回调。DedicatedWorker 尝试反序列化消息时会失败。
    *   **输出:** DedicatedWorker 的 Worker 对象或全局作用域应该触发一个 `messageerror` 事件。

**用户或编程常见的使用错误举例:**

1. **忘记处理 `messageerror` 事件:**  如果主线程发送的消息无法被 Worker 反序列化，且 Worker 没有监听 `messageerror` 事件，那么错误可能会被忽略，导致程序行为异常。测试代码通过模拟反序列化失败并验证 `messageerror` 事件是否被触发，来确保这种错误能够被检测到。
2. **在 Worker 中直接操作 DOM:** DedicatedWorker 运行在独立的线程中，无法直接访问主线程的 DOM。如果开发者尝试在 Worker 中执行类似 `document.getElementById('foo')` 的操作，将会报错。测试代码不会直接测试这种错误，但它测试了 Worker 的独立性，暗示了这种操作的限制。
3. **跨域问题:** 如果 Worker 脚本的 URL 与主页面的 URL 不同源，可能会遇到跨域问题，导致 Worker 无法正常加载或通信。测试代码通过设置 `script_url_ = KURL("http://fake.url/")` 来模拟 Worker 脚本的 URL，可以用于测试跨域相关的逻辑（尽管这段代码本身没有直接测试跨域策略）。

**功能归纳:**

这部分 `dedicated_worker_test.cc` 文件的主要功能是为 Blink 引擎中的 `DedicatedWorker` 组件提供全面的单元测试。它涵盖了 Worker 的生命周期管理、消息传递机制、事件处理、UseCounter 集成、任务调度以及安全上下文等方面。通过这些测试，可以确保 `DedicatedWorker` 的核心功能正常运行，并且与其他 Blink 组件能够正确交互。此外，它还模拟了一些可能导致错误的场景，帮助开发者避免常见的 DedicatedWorker 使用错误。

### 提示词
```
这是目录为blink/renderer/core/workers/dedicated_worker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/workers/dedicated_worker_test.h"

#include <bitset>
#include <cstddef>
#include <memory>

#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/public/mojom/worker/dedicated_worker_host.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/sanitize_script_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/post_message_helper.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/unpacked_serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_message_port.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_post_message_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_worker_options.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/thread_debugger_common_impl.h"
#include "third_party/blink/renderer/core/messaging/blink_transferable_message.h"
#include "third_party/blink/renderer/core/messaging/message_channel.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/wait_for_event.h"
#include "third_party/blink/renderer/core/workers/custom_event_message.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker_messaging_proxy.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker_object_proxy.h"
#include "third_party/blink/renderer/core/workers/dedicated_worker_thread.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/parent_execution_context_task_runners.h"
#include "third_party/blink/renderer/core/workers/worker_backing_thread_startup_data.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/core/workers/worker_thread_test_helper.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "v8-value.h"

namespace blink {

namespace {

constexpr char kCustomEventName[] = "custom";
constexpr char kCustomErrorEventName[] = "customerror";

class CustomEventWithData final : public Event {
 public:
  explicit CustomEventWithData(const AtomicString& event_type)
      : Event(event_type, Bubbles::kNo, Cancelable::kNo) {}
  explicit CustomEventWithData(const AtomicString& event_type,
                               scoped_refptr<SerializedScriptValue> data)
      : CustomEventWithData(event_type, std::move(data), nullptr) {}

  explicit CustomEventWithData(const AtomicString& event_type,
                               scoped_refptr<SerializedScriptValue> data,
                               MessagePortArray* ports)
      : Event(event_type, Bubbles::kNo, Cancelable::kNo),
        data_as_serialized_script_value_(
            SerializedScriptValue::Unpack(std::move(data))),
        ports_(ports) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(data_as_serialized_script_value_);
    visitor->Trace(ports_);
    Event::Trace(visitor);
  }
  SerializedScriptValue* DataAsSerializedScriptValue() const {
    if (!data_as_serialized_script_value_) {
      return nullptr;
    }
    return data_as_serialized_script_value_->Value();
  }

  MessagePortArray* ports() { return ports_; }

 private:
  Member<UnpackedSerializedScriptValue> data_as_serialized_script_value_;
  Member<MessagePortArray> ports_;
};

ScriptValue CreateStringScriptValue(ScriptState* script_state,
                                    const String& str) {
  return ScriptValue(script_state->GetIsolate(),
                     V8String(script_state->GetIsolate(), str));
}

CrossThreadFunction<Event*(ScriptState*, CustomEventMessage)>
CustomEventFactoryCallback(base::RepeatingClosure quit_closure,
                           CustomEventWithData** out_event = nullptr) {
  return CrossThreadBindRepeating(base::BindLambdaForTesting(
      [quit_closure = std::move(quit_closure), out_event](
          ScriptState*, CustomEventMessage data) -> Event* {
        CustomEventWithData* result = MakeGarbageCollected<CustomEventWithData>(
            AtomicString::FromUTF8(kCustomEventName), std::move(data.message));
        if (out_event) {
          *out_event = result;
        }
        quit_closure.Run();
        return result;
      }));
}

CrossThreadFunction<Event*(ScriptState*)> CustomEventFactoryErrorCallback(
    base::RepeatingClosure quit_closure,
    Event** out_event = nullptr) {
  return CrossThreadBindRepeating(base::BindLambdaForTesting(
      [quit_closure = std::move(quit_closure), out_event](ScriptState*) {
        Event* result = MakeGarbageCollected<CustomEventWithData>(
            AtomicString::FromUTF8(kCustomErrorEventName));
        if (out_event) {
          *out_event = result;
        }
        quit_closure.Run();
        return result;
      }));
}

CrossThreadFunction<Event*(ScriptState*, CustomEventMessage)>
CustomEventWithPortsFactoryCallback(base::RepeatingClosure quit_closure,
                                    CustomEventWithData** out_event = nullptr) {
  return CrossThreadBindRepeating(base::BindLambdaForTesting(
      [quit_closure = std::move(quit_closure), out_event](
          ScriptState* script_state, CustomEventMessage message) -> Event* {
        MessagePortArray* ports = MessagePort::EntanglePorts(
            *ExecutionContext::From(script_state), std::move(message.ports));
        CustomEventWithData* result = MakeGarbageCollected<CustomEventWithData>(
            AtomicString::FromUTF8(kCustomEventName),
            std::move(message.message), ports);
        if (out_event) {
          *out_event = result;
        }
        quit_closure.Run();
        return result;
      }));
}

}  // namespace

class DedicatedWorkerThreadForTest final : public DedicatedWorkerThread {
 public:
  DedicatedWorkerThreadForTest(ExecutionContext* parent_execution_context,
                               DedicatedWorkerObjectProxy& worker_object_proxy)
      : DedicatedWorkerThread(
            parent_execution_context,
            worker_object_proxy,
            mojo::PendingRemote<mojom::blink::DedicatedWorkerHost>(),
            mojo::PendingRemote<
                mojom::blink::BackForwardCacheControllerHost>()) {
    worker_backing_thread_ = std::make_unique<WorkerBackingThread>(
        ThreadCreationParams(ThreadType::kTestThread));
  }

  WorkerOrWorkletGlobalScope* CreateWorkerGlobalScope(
      std::unique_ptr<GlobalScopeCreationParams> creation_params) override {
    // Needed to avoid calling into an uninitialized broker.
    if (!creation_params->browser_interface_broker) {
      (void)creation_params->browser_interface_broker
          .InitWithNewPipeAndPassReceiver();
    }
    auto* global_scope = DedicatedWorkerGlobalScope::Create(
        std::move(creation_params), this, time_origin_,
        mojo::PendingRemote<mojom::blink::DedicatedWorkerHost>(),
        mojo::PendingRemote<mojom::blink::BackForwardCacheControllerHost>());
    // Initializing a global scope with a dummy creation params may emit warning
    // messages (e.g., invalid CSP directives).
    return global_scope;
  }

  // Emulates API use on DedicatedWorkerGlobalScope.
  void CountFeature(WebFeature feature, CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    GlobalScope()->CountUse(feature);
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }
  void CountWebDXFeature(WebDXFeature feature,
                         CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    GlobalScope()->CountWebDXFeature(feature);
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  // Emulates deprecated API use on DedicatedWorkerGlobalScope.
  void CountDeprecation(WebFeature feature,
                        CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    Deprecation::CountDeprecation(GlobalScope(), feature);
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  void TestTaskRunner(CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        GlobalScope()->GetTaskRunner(TaskType::kInternalTest);
    EXPECT_TRUE(task_runner->RunsTasksInCurrentSequence());
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  void InitializeGlobalScope(KURL script_url) {
    EXPECT_TRUE(IsCurrentThread());
    To<DedicatedWorkerGlobalScope>(GlobalScope())
        ->Initialize(script_url, network::mojom::ReferrerPolicy::kDefault,
                     Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
                     nullptr /* response_origin_trial_tokens */);
  }
};

class DedicatedWorkerObjectProxyForTest final
    : public DedicatedWorkerObjectProxy {
 public:
  DedicatedWorkerObjectProxyForTest(
      DedicatedWorkerMessagingProxy* messaging_proxy,
      ParentExecutionContextTaskRunners* parent_execution_context_task_runners)
      : DedicatedWorkerObjectProxy(messaging_proxy,
                                   parent_execution_context_task_runners,
                                   DedicatedWorkerToken()) {}

  void CountFeature(WebFeature feature) override {
    // Any feature should be reported only one time.
    EXPECT_FALSE(reported_features_[static_cast<size_t>(feature)]);
    reported_features_.set(static_cast<size_t>(feature));
    DedicatedWorkerObjectProxy::CountFeature(feature);
  }

  void CountWebDXFeature(WebDXFeature feature) override {
    // Any feature should be reported only one time.
    EXPECT_FALSE(reported_webdx_features_[static_cast<size_t>(feature)]);
    reported_webdx_features_.set(static_cast<size_t>(feature));
    DedicatedWorkerObjectProxy::CountWebDXFeature(feature);
  }

 private:
  std::bitset<static_cast<size_t>(WebFeature::kMaxValue) + 1>
      reported_features_;
  std::bitset<static_cast<size_t>(WebDXFeature::kMaxValue) + 1>
      reported_webdx_features_;
};

class DedicatedWorkerMessagingProxyForTest
    : public DedicatedWorkerMessagingProxy {
 public:
  DedicatedWorkerMessagingProxyForTest(ExecutionContext* execution_context,
                                       DedicatedWorker* worker_object)
      : DedicatedWorkerMessagingProxy(
            execution_context,
            worker_object,
            [](DedicatedWorkerMessagingProxy* messaging_proxy,
               DedicatedWorker*,
               ParentExecutionContextTaskRunners* runners) {
              return std::make_unique<DedicatedWorkerObjectProxyForTest>(
                  messaging_proxy, runners);
            }) {
    script_url_ = KURL("http://fake.url/");
  }

  ~DedicatedWorkerMessagingProxyForTest() override = default;

  void StartWorker(
      std::unique_ptr<GlobalScopeCreationParams> params = nullptr) {
    scoped_refptr<const SecurityOrigin> security_origin =
        SecurityOrigin::Create(script_url_);
    auto worker_settings = std::make_unique<WorkerSettings>(
        To<LocalDOMWindow>(GetExecutionContext())->GetFrame()->GetSettings());
    if (!params) {
      params = std::make_unique<GlobalScopeCreationParams>(
          script_url_, mojom::blink::ScriptType::kClassic,
          "fake global scope name", "fake user agent", UserAgentMetadata(),
          nullptr /* web_worker_fetch_context */,
          Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
          Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
          network::mojom::ReferrerPolicy::kDefault, security_origin.get(),
          false /* starter_secure_context */,
          CalculateHttpsState(security_origin.get()),
          nullptr /* worker_clients */, nullptr /* content_settings_client */,
          nullptr /* inherited_trial_features */,
          base::UnguessableToken::Create(), std::move(worker_settings),
          mojom::blink::V8CacheOptions::kDefault,
          nullptr /* worklet_module_responses_map */);
    }
    params->parent_context_token =
        GetExecutionContext()->GetExecutionContextToken();
    InitializeWorkerThread(
        std::move(params),
        WorkerBackingThreadStartupData(
            WorkerBackingThreadStartupData::HeapLimitMode::kDefault,
            WorkerBackingThreadStartupData::AtomicsWaitMode::kAllow),
        WorkerObjectProxy().token());

    if (base::FeatureList::IsEnabled(features::kPlzDedicatedWorker)) {
      PostCrossThreadTask(
          *GetDedicatedWorkerThread()->GetTaskRunner(TaskType::kInternalTest),
          FROM_HERE,
          CrossThreadBindOnce(
              &DedicatedWorkerThreadForTest::InitializeGlobalScope,
              CrossThreadUnretained(GetDedicatedWorkerThread()), script_url_));
    }
  }

  void EvaluateClassicScript(const String& source) {
    GetWorkerThread()->EvaluateClassicScript(script_url_, source,
                                             nullptr /* cached_meta_data */,
                                             v8_inspector::V8StackTraceId());
  }

  DedicatedWorkerThreadForTest* GetDedicatedWorkerThread() {
    return static_cast<DedicatedWorkerThreadForTest*>(GetWorkerThread());
  }

  void Trace(Visitor* visitor) const override {
    DedicatedWorkerMessagingProxy::Trace(visitor);
  }

  const KURL& script_url() const { return script_url_; }

 private:
  std::unique_ptr<WorkerThread> CreateWorkerThread() override {
    return std::make_unique<DedicatedWorkerThreadForTest>(GetExecutionContext(),
                                                          WorkerObjectProxy());
  }

  KURL script_url_;
};

class FakeWebDedicatedWorkerHostFactoryClient
    : public WebDedicatedWorkerHostFactoryClient {
 public:
  // Implements WebDedicatedWorkerHostFactoryClient.
  void CreateWorkerHostDeprecated(
      const DedicatedWorkerToken& dedicated_worker_token,
      const WebURL& script_url,
      const WebSecurityOrigin& origin,
      CreateWorkerHostCallback callback) override {}
  void CreateWorkerHost(
      const DedicatedWorkerToken& dedicated_worker_token,
      const WebURL& script_url,
      network::mojom::CredentialsMode credentials_mode,
      const WebFetchClientSettingsObject& fetch_client_settings_object,
      CrossVariantMojoRemote<blink::mojom::BlobURLTokenInterfaceBase>
          blob_url_token,
      net::StorageAccessApiStatus storage_access_api_status) override {}
  scoped_refptr<blink::WebWorkerFetchContext> CloneWorkerFetchContext(
      WebWorkerFetchContext* web_worker_fetch_context,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    return nullptr;
  }
};

class FakeWebDedicatedWorkerHostFactoryClientPlatformSupport
    : public TestingPlatformSupport {
 public:
  std::unique_ptr<blink::WebDedicatedWorkerHostFactoryClient>
  CreateDedicatedWorkerHostFactoryClient(
      WebDedicatedWorker* worker,
      const BrowserInterfaceBrokerProxy& interface_broker) override {
    return std::make_unique<FakeWebDedicatedWorkerHostFactoryClient>();
  }
};

void DedicatedWorkerTest::SetUp() {
  PageTestBase::SetUp(gfx::Size());
  LocalDOMWindow* window = GetFrame().DomWindow();

  worker_object_ = MakeGarbageCollected<DedicatedWorker>(
      window, KURL("http://fake.url/"), WorkerOptions::Create(),
      [&](DedicatedWorker* worker) {
        auto* proxy =
            MakeGarbageCollected<DedicatedWorkerMessagingProxyForTest>(window,
                                                                       worker);
        worker_messaging_proxy_ = proxy;
        return proxy;
      });
  worker_object_->UpdateStateIfNeeded();
}

void DedicatedWorkerTest::TearDown() {
  GetWorkerThread()->TerminateForTesting();
  GetWorkerThread()->WaitForShutdownForTesting();
}

DedicatedWorkerMessagingProxyForTest*
DedicatedWorkerTest::WorkerMessagingProxy() {
  return worker_messaging_proxy_.Get();
}

DedicatedWorkerThreadForTest* DedicatedWorkerTest::GetWorkerThread() {
  return worker_messaging_proxy_->GetDedicatedWorkerThread();
}

void DedicatedWorkerTest::StartWorker(
    std::unique_ptr<GlobalScopeCreationParams> params) {
  WorkerMessagingProxy()->StartWorker(std::move(params));
}

void DedicatedWorkerTest::EvaluateClassicScript(const String& source_code) {
  WorkerMessagingProxy()->EvaluateClassicScript(source_code);
}

namespace {

void PostExitRunLoopTaskOnParent(WorkerThread* worker_thread,
                                 CrossThreadOnceClosure quit_closure) {
  PostCrossThreadTask(*worker_thread->GetParentTaskRunnerForTesting(),
                      FROM_HERE, CrossThreadBindOnce(std::move(quit_closure)));
}

}  // anonymous namespace

void DedicatedWorkerTest::WaitUntilWorkerIsRunning() {
  base::RunLoop loop;
  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(&PostExitRunLoopTaskOnParent,
                          CrossThreadUnretained(GetWorkerThread()),
                          CrossThreadBindOnce(loop.QuitClosure())));

  loop.Run();
}

TEST_F(DedicatedWorkerTest, PendingActivity_NoActivityAfterContextDestroyed) {
  StartWorker();

  EXPECT_TRUE(WorkerMessagingProxy()->HasPendingActivity());

  // Destroying the context should result in no pending activities.
  WorkerMessagingProxy()->TerminateGlobalScope();
  EXPECT_FALSE(WorkerMessagingProxy()->HasPendingActivity());
}

TEST_F(DedicatedWorkerTest, UseCounter) {
  Page::InsertOrdinaryPageForTesting(&GetPage());
  const String source_code = "// Do nothing";
  StartWorker();
  EvaluateClassicScript(source_code);

  // This feature is randomly selected.
  const WebFeature kFeature1 = WebFeature::kRequestFileSystem;
  const WebDXFeature kWebDXFeature1 = WebDXFeature::kCompressionStreams;

  // API use on the DedicatedWorkerGlobalScope should be recorded in UseCounter
  // on the Document.
  EXPECT_FALSE(GetDocument().IsUseCounted(kFeature1));
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&DedicatedWorkerThreadForTest::CountFeature,
                            CrossThreadUnretained(GetWorkerThread()), kFeature1,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }
  EXPECT_TRUE(GetDocument().IsUseCounted(kFeature1));

  EXPECT_FALSE(GetDocument().IsWebDXFeatureCounted(kWebDXFeature1));
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&DedicatedWorkerThreadForTest::CountWebDXFeature,
                            CrossThreadUnretained(GetWorkerThread()),
                            kWebDXFeature1,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }
  EXPECT_TRUE(GetDocument().IsWebDXFeatureCounted(kWebDXFeature1));

  // API use should be reported to the Document only one time. See comments in
  // DedicatedWorkerObjectProxyForTest::CountFeature.
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&DedicatedWorkerThreadForTest::CountFeature,
                            CrossThreadUnretained(GetWorkerThread()), kFeature1,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }

  // This feature is randomly selected from Deprecation::deprecationMessage().
  const WebFeature kFeature2 = WebFeature::kPaymentInstruments;

  // Deprecated API use on the DedicatedWorkerGlobalScope should be recorded in
  // UseCounter on the Document.
  EXPECT_FALSE(GetDocument().IsUseCounted(kFeature2));
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&DedicatedWorkerThreadForTest::CountDeprecation,
                            CrossThreadUnretained(GetWorkerThread()), kFeature2,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }
  EXPECT_TRUE(GetDocument().IsUseCounted(kFeature2));

  // API use should be reported to the Document only one time. See comments in
  // DedicatedWorkerObjectProxyForTest::CountDeprecation.
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&DedicatedWorkerThreadForTest::CountDeprecation,
                            CrossThreadUnretained(GetWorkerThread()), kFeature2,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }
}

TEST_F(DedicatedWorkerTest, TaskRunner) {
  base::RunLoop loop;
  StartWorker();

  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(&DedicatedWorkerThreadForTest::TestTaskRunner,
                          CrossThreadUnretained(GetWorkerThread()),
                          CrossThreadBindOnce(loop.QuitClosure())));
  loop.Run();
}

namespace {

BlinkTransferableMessage MakeTransferableMessage(
    base::UnguessableToken agent_cluster_id) {
  BlinkTransferableMessage message;
  message.message = SerializedScriptValue::NullValue();
  message.sender_agent_cluster_id = agent_cluster_id;
  return message;
}

}  // namespace

TEST_F(DedicatedWorkerTest, DispatchMessageEventOnWorkerObject) {
  StartWorker();

  base::RunLoop run_loop;
  auto* wait = MakeGarbageCollected<WaitForEvent>();
  wait->AddEventListener(WorkerObject(), event_type_names::kMessage);
  wait->AddEventListener(WorkerObject(), event_type_names::kMessageerror);
  wait->AddCompletionClosure(run_loop.QuitClosure());

  auto message = MakeTransferableMessage(
      GetDocument().GetExecutionContext()->GetAgentClusterID());
  WorkerMessagingProxy()->PostMessageToWorkerObject(std::move(message));
  run_loop.Run();

  EXPECT_EQ(wait->GetLastEvent()->type(), event_type_names::kMessage);
}

TEST_F(DedicatedWorkerTest,
       DispatchMessageEventOnWorkerObject_CannotDeserialize) {
  StartWorker();

  base::RunLoop run_loop;
  auto* wait = MakeGarbageCollected<WaitForEvent>();
  wait->AddEventListener(WorkerObject(), event_type_names::kMessage);
  wait->AddEventListener(WorkerObject(), event_type_names::kMessageerror);
  wait->AddCompletionClosure(run_loop.QuitClosure());

  SerializedScriptValue::ScopedOverrideCanDeserializeInForTesting
      override_can_deserialize_in(base::BindLambdaForTesting(
          [&](const SerializedScriptValue&, ExecutionContext* execution_context,
              bool can_deserialize) {
            EXPECT_EQ(execution_context, GetFrame().DomWindow());
            EXPECT_TRUE(can_deserialize);
            return false;
          }));
  auto message = MakeTransferableMessage(
      GetDocument().GetExecutionContext()->GetAgentClusterID());
  WorkerMessagingProxy()->PostMessageToWorkerObject(std::move(message));
  run_loop.Run();

  EXPECT_EQ(wait->GetLastEvent()->type(), event_type_names::kMessageerror);
}

TEST_F(DedicatedWorkerTest, DispatchMessageEventOnWorkerGlobalScope) {
  // Script must run for the worker global scope to dispatch messages.
  const String source_code = "// Do nothing";
  StartWorker();
  EvaluateClassicScript(source_code);

  AtomicString event_type;
  base::RunLoop run_loop_1;
  base::RunLoop run_loop_2;

  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(
          [](DedicatedWorkerThreadForTest* worker_thread,
             AtomicString* event_type, WTF::CrossThreadOnceClosure quit_1,
             WTF::CrossThreadOnceClosure quit_2) {
            auto* global_scope = worker_thread->GlobalScope();
            auto* wait = MakeGarbageCollected<WaitForEvent>();
            wait->AddEventListener(global_scope, event_type_names::kMessage);
            wait->AddEventListener(global_scope,
                                   event_type_names::kMessageerror);
            wait->AddCompletionClosure(WTF::BindOnce(
                [](WaitForEvent* wait, AtomicString* event_type,
                   WTF::CrossThreadOnceClosure quit_closure) {
                  *event_type = wait->GetLastEvent()->type();
                  std::move(quit_closure).Run();
                },
                WrapPersistent(wait), WTF::Unretained(event_type),
                std::move(quit_2)));
            std::move(quit_1).Run();
          },
          CrossThreadUnretained(GetWorkerThread()),
          CrossThreadUnretained(&event_type),
          WTF::CrossThreadOnceClosure(run_loop_1.QuitClosure()),
          WTF::CrossThreadOnceClosure(run_loop_2.QuitClosure())));

  // Wait for the first run loop to quit, which signals that the event listeners
  // are registered. Then post the message and wait to be notified of the
  // result. Each run loop can only be used once.
  run_loop_1.Run();
  auto message = MakeTransferableMessage(
      GetDocument().GetExecutionContext()->GetAgentClusterID());
  WorkerMessagingProxy()->PostMessageToWorkerGlobalScope(std::move(message));
  run_loop_2.Run();

  EXPECT_EQ(event_type, event_type_names::kMessage);
}

TEST_F(DedicatedWorkerTest, TopLevelFrameSecurityOrigin) {
  ScopedTestingPlatformSupport<
      FakeWebDedicatedWorkerHostFactoryClientPlatformSupport>
      platform;
  const auto& script_url = WorkerMessagingProxy()->script_url();
  scoped_refptr<SecurityOrigin> security_origin =
      SecurityOrigin::Create(script_url);
  WorkerObject()
      ->GetExecutionContext()
      ->GetSecurityContext()
      .SetSecurityOriginForTesting(security_origin);
  StartWorker(WorkerObject()->CreateGlobalScopeCreationParams(
      script_url, network::mojom::ReferrerPolicy::kDefault,
      Vector<network::mojom::blink::ContentSecurityPolicyPtr>()));
  base::RunLoop run_loop;

  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(
          [](DedicatedWorkerThreadForTest* worker_thread,
             WTF::CrossThreadOnceClosure quit,
             const SecurityOrigin* security_origin, const KURL& script_url) {
            // Check the worker's top level frame security origin.
            auto* worker_global_scope =
                static_cast<WorkerGlobalScope*>(worker_thread->GlobalScope());
            ASSERT_TRUE(worker_global_scope->top_level_frame_security_origin());
            EXPECT_TRUE(worker_global_scope->top_level_frame_security_origin()
                            ->IsSameOriginDomainWith(security_origin));

            // Create a nested worker and check the top level frame security
            // origin of the GlobalScopeCreationParams.
            {
              auto* nested_worker_object =
                  MakeGarbageCollected<DedicatedWorker>(
                      worker_global_scope, script_url, WorkerOptions::Create());
              nested_worker_object->UpdateStateIfNeeded();

              auto nested_worker_params =
                  nested_worker_object->CreateGlobalScopeCreationParams(
                      script_url, network::mojom::ReferrerPolicy::kDefault,
                      Vector<
                          network::mojom::blink::ContentSecurityPolicyPtr>());
              ASSERT_TRUE(
                  nested_worker_params->top_level_frame_security_origin);
              EXPECT_TRUE(nested_worker_params->top_level_frame_security_origin
                              ->IsSameOriginDomainWith(security_origin));
            }
            std::move(quit).Run();
          },
          CrossThreadUnretained(GetWorkerThread()),
          WTF::CrossThreadOnceClosure(run_loop.QuitClosure()),
          CrossThreadUnretained(WorkerObject()
                                    ->GetExecutionContext()
                                    ->GetSecurityContext()
                                    .GetSecurityOrigin()),
          script_url));
  run_loop.Run();
}

TEST_F(DedicatedWorkerTest,
       DispatchMessageEventOnWorkerGlobalScope_CannotDeserialize) {
  // Script must run for the worker global scope to dispatch messages.
  const String source_code = "// Do nothing";
  StartWorker();
  EvaluateClassicScript(source_code);

  AtomicString event_type;
  base::RunLoop run_loop_1;
  base::RunLoop run_loop_2;

  auto* worker_thread = GetWorkerThread();
  SerializedScriptValue::ScopedOverrideCanDeserializeInForTesting
      override_can_deserialize_in(base::BindLambdaForTesting(
          [&](const SerializedScriptValue&, ExecutionContext* execution_context,
              bool can_deserialize) {
            EXPECT_EQ(execution_context, worker_thread->GlobalScope());
            EXPECT_TRUE(can_deserialize);
            return false;
          }));

  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(
          [](DedicatedWorkerThreadForTest* worker_thread,
             AtomicString* event_type, WTF::CrossThreadOnceClosure quit_1,
             WTF::CrossThreadOnceClosure quit_2) {
            auto* global_scope = worker_thread->GlobalScope();
            auto* wait = MakeGarbageCollected<WaitForEvent>();
            wait->AddEventListener(global_scope, event_type_names::kMessage);
            wait->AddEventListener(global_scope,
                                   event_type_names::kMessageerror);
            wait->AddCompletionClosure(WTF::BindOnce(
                [](WaitForEvent* wait, AtomicString* event_type,
                   WTF::CrossThreadOnceClosure quit_closure) {
                  *event_type = wait->GetLastEvent()->type();
                  std::move(quit_closure).Run();
                },
                WrapPersistent(wait), WTF::Unretained(event_type),
                std::move(quit_2)));
            std::move(quit_1).Run();
          },
          CrossThreadUnretained(worker_thread),
          CrossThreadUnretained(&event_type),
          WTF::CrossThreadOnceClosure(run_loop_1.QuitClosure()),
          WTF::CrossThreadOnceClosure(run_loop_2.QuitClosure())));

  // Wait for the first run loop to quit, which signals that the event listeners
  // are registered. Then post the message and wait to be notified of the
  // result. Each run loop can only be used once.
  run_loop_1.Run();
  auto message = MakeTransferableMessage(
      GetDocument().GetExecutionContext()->GetAgentClusterID());
  WorkerMessagingProxy()->PostMessageToWorkerGlobalScope(std::move(message));
  run_loop_2.Run();

  EXPECT_EQ(event_type, event_type_names::kMessageerror);
}

TEST_F(DedicatedWorkerTest, PostCustomEventWithString) {
  V8
```