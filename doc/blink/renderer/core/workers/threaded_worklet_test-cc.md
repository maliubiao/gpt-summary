Response:
Let's break down the thought process to analyze this C++ test file.

1. **Understand the Goal:** The core request is to understand the *functionality* of the `threaded_worklet_test.cc` file. Since it's a `_test.cc` file, the primary purpose is to *test* something. The name "threaded_worklet" strongly suggests it's testing the functionality of threaded worklets in Blink.

2. **Identify Key Classes/Components:**  The code includes several custom classes and uses existing Blink infrastructure. It's important to identify the major players:
    * `ThreadedWorkletObjectProxyForTest`:  A test-specific version of `ThreadedWorkletObjectProxy`. The name suggests it's responsible for communication *from* the worklet *to* the main thread. The "ForTest" suffix is a strong indicator of a testing helper.
    * `ThreadedWorkletThreadForTest`: A test-specific `WorkerThread` subclass. This clearly represents the thread where the worklet runs. Again, "ForTest" signals a test helper.
    * `ThreadedWorkletMessagingProxyForTest`: A test-specific `ThreadedWorkletMessagingProxy`. This is likely responsible for setting up and managing the communication between the main thread and the worklet thread.
    * `ThreadedWorkletTest`: The main test fixture using Google Test (`TEST_F`). This contains the individual test cases.
    * Standard Blink components: `WorkerThread`, `WorkletGlobalScope`, `ContentSecurityPolicy`, `SecurityOrigin`, `Document`, `Page`, task runners, etc.

3. **Analyze Test Cases (the `TEST_F` blocks):** These are the most direct indicators of what's being tested. Each `TEST_F` focuses on a specific aspect:
    * `SecurityOrigin`:  Tests the security origin of the worklet.
    * `AgentCluster`: Tests that the worklet belongs to the correct agent cluster.
    * `ContentSecurityPolicy`: Tests CSP inheritance and enforcement within the worklet.
    * `InvalidContentSecurityPolicy`: Tests how the worklet handles invalid CSPs (specifically, no crashing).
    * `UseCounter`: Tests that API usage and deprecations within the worklet are correctly tracked via the UseCounter mechanism on the main document.
    * `TaskRunner`: Tests that the worklet can obtain and use its own task runner.
    * `NestedRunLoopTermination`: Tests the robustness of worklet termination, especially in scenarios with nested worklets and event loops.

4. **Examine Helper Classes (especially `ForTest` classes):** These classes often reveal details about the tested functionality.
    * `ThreadedWorkletObjectProxyForTest`: The `CountFeature` override is significant. It checks that `WebFeature` counts are reported only once. This directly relates to the `UseCounter` test.
    * `ThreadedWorkletThreadForTest`: The methods like `TestSecurityOrigin`, `TestAgentCluster`, `TestContentSecurityPolicy`, etc., clearly correspond to the test cases. These methods execute *on the worklet thread* and verify specific conditions. The `CreateWorkerGlobalScope` method confirms it's creating a `FakeWorkletGlobalScope`.
    * `ThreadedWorkletMessagingProxyForTest`: The `Start` method shows how the worklet thread is initialized, including setting up the `GlobalScopeCreationParams` with CSP, security origin, etc. The `CreateWorkerThread` method confirms the creation of the test-specific worker thread.

5. **Connect to Web Standards (JavaScript, HTML, CSS):**  Consider how worklets relate to web development:
    * **JavaScript:** Worklets execute JavaScript code. The tests involve running code within the worklet (`TestSecurityOrigin`, etc.).
    * **HTML:** Worklets are often initiated from HTML documents. The test setup creates a dummy page.
    * **CSS:** While this specific test doesn't directly manipulate CSS, worklets *can* be used in CSS (e.g., CSS Paint API). The tests involving CSP are relevant because CSP affects the execution of JavaScript, which could be part of a CSS worklet.

6. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when working with worklets:
    * Assuming the worklet has the same security context as the main document. The `SecurityOrigin` test addresses this.
    * Expecting API usage within the worklet to be tracked automatically without understanding UseCounter. The `UseCounter` test is relevant here.
    * Issues with incorrect CSP configurations affecting worklet execution. The CSP tests highlight this.
    * Problems with terminating worklets correctly, potentially leading to resource leaks or unexpected behavior. The `NestedRunLoopTermination` test touches on this.

7. **Infer Logic and Provide Examples:** Based on the code and test cases, deduce the input and output for specific scenarios. For example, the `ContentSecurityPolicy` test sets up a specific CSP and then verifies whether the worklet respects those rules when attempting to load scripts.

8. **Structure the Answer:** Organize the findings into logical categories: functionality, relation to web standards, logic/examples, and common errors. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this is just testing basic worklet creation.
* **Correction:** The specific test cases (CSP, SecurityOrigin, UseCounter) indicate it's going deeper, testing the *environment* and *capabilities* of the threaded worklet.
* **Initial thought:** Focus only on the `ThreadedWorkletTest` class.
* **Correction:**  Realize the helper classes (`ForTest` variants) are crucial for understanding the setup and verification logic.
* **Initial thought:**  Only list the classes present.
* **Correction:** Explain the *role* of each significant class in the testing process.

By following these steps and iteratively refining the analysis, we can arrive at a comprehensive understanding of the `threaded_worklet_test.cc` file's purpose and functionality.
这个文件 `blink/renderer/core/workers/threaded_worklet_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `ThreadedWorklet` 相关的核心功能**。

更具体地说，它测试了在独立的线程上运行的 Worklet（一种轻量级的 Web Worker）的各种特性和行为。

以下是该文件测试的主要功能以及它们与 JavaScript、HTML 和 CSS 的关系：

**核心功能测试:**

1. **Worklet 的创建和销毁:**
   - 测试 `ThreadedWorkletMessagingProxy` 如何创建和管理 `WorkerThread` 来运行 Worklet。
   - 测试 Worklet 线程的正常终止和资源清理。
   - **与 JavaScript 的关系:** Worklet 执行 JavaScript 代码。这个测试确保了 Worklet 能够正确启动和停止 JavaScript 执行环境。

2. **Worklet 的安全上下文 (Security Origin):**
   - 测试 Worklet 拥有一个 **唯一的、不透明的安全源 (opaque origin)**。
   - 测试 Worklet 的安全源与拥有它的文档的安全源不同。
   - **与 JavaScript 和 HTML 的关系:** 安全源是浏览器安全模型的基础，它决定了哪些脚本可以访问哪些资源。这个测试确保了 Worklet 遵循了正确的安全隔离原则。

3. **代理集群 (Agent Cluster):**
   - 测试 Worklet 属于创建它的文档所在的代理集群。
   - **与 JavaScript 和 HTML 的关系:** 代理集群是浏览器隔离机制的一部分，用于隔离不同源的页面，提高稳定性和安全性。这个测试确保了 Worklet 被正确地放置在相应的隔离域中。

4. **内容安全策略 (Content Security Policy - CSP):**
   - 测试 Worklet **继承了创建它的文档的 CSP**。
   - 测试 Worklet 能够正确执行 CSP 策略，例如允许或禁止加载特定来源的脚本。
   - 测试即使存在 **无效的 CSP 策略**，Worklet 也不会崩溃。
   - **与 JavaScript 和 HTML 的关系:** CSP 是一种重要的安全机制，允许网站控制浏览器可以加载哪些资源，从而减少跨站脚本攻击 (XSS) 的风险。这个测试确保了 Worklet 正确地应用了父文档的 CSP 策略。
   - **举例说明:**
     - **假设输入:** HTML 文档的 CSP 设置为 `script-src 'self' https://allowed.example.com`。
     - **预期输出:** Worklet 内部尝试加载来自 `https://allowed.example.com` 的脚本应该成功，而加载来自其他域（例如 `https://disallowed.example.com`）的脚本应该失败。

5. **功能计数器 (Use Counter):**
   - 测试在 Worklet 中使用特定 Web 功能时，会正确地在拥有该 Worklet 的文档上记录使用情况。
   - 测试同一个功能只会被报告一次。
   - 测试 **已弃用的 API** 的使用也会被正确记录。
   - **与 JavaScript、HTML 和 CSS 的关系:** 浏览器使用功能计数器来跟踪 Web 功能的使用情况，以便了解哪些功能被广泛使用，哪些功能可以被安全地移除或更改。这可以帮助浏览器开发人员做出决策。Worklet 也可以使用各种 Web API，例如文件系统 API、支付 API 等。
   - **举例说明:**
     - **假设输入:** Worklet 代码中调用了 `navigator.requestFileSystem` (假设这是一个被跟踪的功能)。
     - **预期输出:** 在拥有该 Worklet 的文档的 Use Counter 中，`kRequestFileSystem` 功能会被标记为已使用。

6. **任务运行器 (Task Runner):**
   - 测试 Worklet 能够获取并使用其自身的任务运行器来执行任务。
   - **与 JavaScript 的关系:** JavaScript 代码的执行通常由事件循环和任务队列驱动。每个线程都有一个或多个任务运行器来管理待执行的任务。这个测试确保了 Worklet 拥有独立执行任务的能力。

7. **嵌套事件循环的终止:**
   - 测试在存在嵌套的 Worklet 和事件循环的情况下，能够正确地终止 Worklet，避免崩溃。
   - **与 JavaScript 的关系:** Worklet 内部可能会有自己的事件循环，或者在某些情况下会创建新的 Worklet，形成嵌套结构。这个测试确保了在这种复杂场景下的稳定性。

**代码结构和辅助类:**

- `ThreadedWorkletObjectProxyForTest`:  用于测试目的的 `ThreadedWorkletObjectProxy` 子类，用于验证功能计数器是否正确报告。
- `ThreadedWorkletThreadForTest`:  用于测试目的的 `WorkerThread` 子类，提供了一些用于在 Worklet 线程上执行特定测试逻辑的方法。
- `ThreadedWorkletMessagingProxyForTest`: 用于测试目的的 `ThreadedWorkletMessagingProxy` 子类，负责 Worklet 线程的创建和管理。

**用户或编程常见的使用错误示例:**

1. **错误地假设 Worklet 与主线程共享安全源:**  开发者可能会错误地认为 Worklet 可以直接访问主线程的某些受安全源限制的资源，而实际上 Worklet 拥有独立的安全源，需要遵循跨域访问策略。
2. **忽视 Worklet 的 CSP 继承:** 开发者可能在 Worklet 中尝试加载被父文档 CSP 阻止的资源，导致加载失败。
3. **不理解 Use Counter 机制:** 开发者可能不清楚浏览器如何跟踪功能使用情况，或者在调试某些功能是否启用时感到困惑。
4. **在复杂的 Worklet 嵌套场景中管理生命周期不当:**  开发者可能在创建和销毁嵌套 Worklet 时出现错误，导致资源泄漏或程序崩溃。

**总结:**

`threaded_worklet_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎中 `ThreadedWorklet` 机制的正确性和稳定性。它覆盖了 Worklet 的创建、安全上下文、CSP、功能计数以及任务管理等核心方面，并间接地与 JavaScript、HTML 和 CSS 的相关规范和行为联系起来。通过这些测试，Chromium 能够保证 Worklet 功能在各种场景下的可靠运行，并帮助开发者避免一些常见的使用错误。

### 提示词
```
这是目录为blink/renderer/core/workers/threaded_worklet_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <bitset>

#include "base/gtest_prod_util.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/thread_debugger_common_impl.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/threaded_worklet_messaging_proxy.h"
#include "third_party/blink/renderer/core/workers/threaded_worklet_object_proxy.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/core/workers/worker_thread_test_helper.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope.h"
#include "third_party/blink/renderer/core/workers/worklet_global_scope_test_helper.h"
#include "third_party/blink/renderer/core/workers/worklet_module_responses_map.h"
#include "third_party/blink/renderer/core/workers/worklet_thread_holder.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

class ThreadedWorkletObjectProxyForTest final
    : public ThreadedWorkletObjectProxy {
 public:
  ThreadedWorkletObjectProxyForTest(
      ThreadedWorkletMessagingProxy* messaging_proxy,
      ParentExecutionContextTaskRunners* parent_execution_context_task_runners)
      : ThreadedWorkletObjectProxy(messaging_proxy,
                                   parent_execution_context_task_runners,
                                   /*parent_agent_group_task_runner=*/nullptr) {
  }

 protected:
  void CountFeature(WebFeature feature) override {
    // Any feature should be reported only one time.
    EXPECT_FALSE(reported_features_[static_cast<size_t>(feature)]);
    reported_features_.set(static_cast<size_t>(feature));
    ThreadedWorkletObjectProxy::CountFeature(feature);
  }

 private:
  std::bitset<static_cast<size_t>(WebFeature::kMaxValue) + 1>
      reported_features_;
};

class ThreadedWorkletThreadForTest : public WorkerThread {
 public:
  explicit ThreadedWorkletThreadForTest(
      WorkerReportingProxy& worker_reporting_proxy)
      : WorkerThread(worker_reporting_proxy) {}
  ~ThreadedWorkletThreadForTest() override = default;

  WorkerBackingThread& GetWorkerBackingThread() override {
    auto* worklet_thread_holder =
        WorkletThreadHolder<ThreadedWorkletThreadForTest>::GetInstance();
    DCHECK(worklet_thread_holder);
    return *worklet_thread_holder->GetThread();
  }

  static void EnsureSharedBackingThread() {
    DCHECK(IsMainThread());
    WorkletThreadHolder<ThreadedWorkletThreadForTest>::EnsureInstance(
        ThreadCreationParams(ThreadType::kTestThread)
            .SetThreadNameForTest("ThreadedWorkletThreadForTest"));
  }

  static void ClearSharedBackingThread() {
    DCHECK(IsMainThread());
    WorkletThreadHolder<ThreadedWorkletThreadForTest>::ClearInstance();
  }

  void TestSecurityOrigin(WTF::CrossThreadOnceClosure quit_closure) {
    WorkletGlobalScope* global_scope = To<WorkletGlobalScope>(GlobalScope());
    // The SecurityOrigin for a worklet should be a unique opaque origin, while
    // the owner Document's SecurityOrigin shouldn't.
    EXPECT_TRUE(global_scope->GetSecurityOrigin()->IsOpaque());
    EXPECT_FALSE(global_scope->DocumentSecurityOrigin()->IsOpaque());
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  void TestAgentCluster(base::UnguessableToken owner_agent_cluster_id,
                        WTF::CrossThreadOnceClosure quit_closure) {
    ASSERT_TRUE(owner_agent_cluster_id);
    EXPECT_EQ(GlobalScope()->GetAgentClusterID(), owner_agent_cluster_id);
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  void TestContentSecurityPolicy(WTF::CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    ContentSecurityPolicy* csp = GlobalScope()->GetContentSecurityPolicy();
    KURL main_document_url = KURL("https://example.com/script.js");

    // The "script-src 'self'" directive allows |main_document_url| since it is
    // same-origin with the main document.
    EXPECT_TRUE(csp->AllowScriptFromSource(
        main_document_url, String(), IntegrityMetadataSet(), kParserInserted,
        main_document_url, RedirectStatus::kNoRedirect));

    // The "script-src https://allowed.example.com" should allow this.
    EXPECT_TRUE(csp->AllowScriptFromSource(
        KURL("https://allowed.example.com"), String(), IntegrityMetadataSet(),
        kParserInserted, KURL("https://allowed.example.com"),
        RedirectStatus::kNoRedirect));

    EXPECT_FALSE(csp->AllowScriptFromSource(
        KURL("https://disallowed.example.com"), String(),
        IntegrityMetadataSet(), kParserInserted,
        KURL("https://disallowed.example.com"), RedirectStatus::kNoRedirect));

    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  // Test that having an invalid CSP does not result in an exception.
  // See bugs: 844383,844317
  void TestInvalidContentSecurityPolicy(
      WTF::CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());

    // At this point check that the CSP that was set is indeed invalid.
    const Vector<network::mojom::blink::ContentSecurityPolicyPtr>& csp =
        GlobalScope()->GetContentSecurityPolicy()->GetParsedPolicies();
    EXPECT_EQ(1ul, csp.size());
    EXPECT_EQ("invalid-csp", csp[0]->header->header_value);
    EXPECT_EQ(network::mojom::ContentSecurityPolicyType::kEnforce,
              csp[0]->header->type);

    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  // Emulates API use on threaded WorkletGlobalScope.
  void CountFeature(WebFeature feature,
                    WTF::CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    GlobalScope()->CountUse(feature);
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  // Emulates deprecated API use on threaded WorkletGlobalScope.
  void CountDeprecation(WebFeature feature,
                        WTF::CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    Deprecation::CountDeprecation(GlobalScope(), feature);
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

  void TestTaskRunner(WTF::CrossThreadOnceClosure quit_closure) {
    EXPECT_TRUE(IsCurrentThread());
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        GlobalScope()->GetTaskRunner(TaskType::kInternalTest);
    EXPECT_TRUE(task_runner->RunsTasksInCurrentSequence());
    PostCrossThreadTask(*GetParentTaskRunnerForTesting(), FROM_HERE,
                        CrossThreadBindOnce(std::move(quit_closure)));
  }

 private:
  WorkerOrWorkletGlobalScope* CreateWorkerGlobalScope(
      std::unique_ptr<GlobalScopeCreationParams> creation_params) final {
    auto* global_scope = MakeGarbageCollected<FakeWorkletGlobalScope>(
        std::move(creation_params), GetWorkerReportingProxy(), this);
    EXPECT_FALSE(global_scope->IsMainThreadWorkletGlobalScope());
    EXPECT_TRUE(global_scope->IsThreadedWorkletGlobalScope());
    return global_scope;
  }

  bool IsOwningBackingThread() const final { return false; }

  ThreadType GetThreadType() const override {
    return ThreadType::kUnspecifiedWorkerThread;
  }
};

class ThreadedWorkletMessagingProxyForTest
    : public ThreadedWorkletMessagingProxy {
 public:
  explicit ThreadedWorkletMessagingProxyForTest(
      ExecutionContext* execution_context)
      : ThreadedWorkletMessagingProxy(execution_context) {
    worklet_object_proxy_ = std::make_unique<ThreadedWorkletObjectProxyForTest>(
        this, GetParentExecutionContextTaskRunners());
  }

  ~ThreadedWorkletMessagingProxyForTest() override = default;

  void Start() {
    std::unique_ptr<Vector<char>> cached_meta_data;
    WorkerClients* worker_clients = nullptr;
    std::unique_ptr<WorkerSettings> worker_settings;
    LocalFrame* frame = To<LocalDOMWindow>(GetExecutionContext())->GetFrame();
    InitializeWorkerThread(
        std::make_unique<GlobalScopeCreationParams>(
            GetExecutionContext()->Url(), mojom::blink::ScriptType::kModule,
            "threaded_worklet", GetExecutionContext()->UserAgent(),
            frame->Loader().UserAgentMetadata(),
            nullptr /* web_worker_fetch_context */,
            mojo::Clone(GetExecutionContext()
                            ->GetContentSecurityPolicy()
                            ->GetParsedPolicies()),
            Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
            GetExecutionContext()->GetReferrerPolicy(),
            GetExecutionContext()->GetSecurityOrigin(),
            GetExecutionContext()->IsSecureContext(),
            GetExecutionContext()->GetHttpsState(), worker_clients,
            nullptr /* content_settings_client */,
            OriginTrialContext::GetInheritedTrialFeatures(GetExecutionContext())
                .get(),
            base::UnguessableToken::Create(), std::move(worker_settings),
            mojom::blink::V8CacheOptions::kDefault,
            MakeGarbageCollected<WorkletModuleResponsesMap>(),
            mojo::NullRemote() /* browser_interface_broker */,
            frame->Loader().CreateWorkerCodeCacheHost(),
            frame->GetBlobUrlStorePendingRemote(), BeginFrameProviderParams(),
            nullptr /* parent_permissions_policy */,
            GetExecutionContext()->GetAgentClusterID(), ukm::kInvalidSourceId,
            GetExecutionContext()->GetExecutionContextToken()),
        std::nullopt, std::nullopt);
  }

 private:
  friend class ThreadedWorkletTest;
  FRIEND_TEST_ALL_PREFIXES(ThreadedWorkletTest, NestedRunLoopTermination);

  std::unique_ptr<WorkerThread> CreateWorkerThread() final {
    return std::make_unique<ThreadedWorkletThreadForTest>(WorkletObjectProxy());
  }
};

class ThreadedWorkletTest : public testing::Test {
 public:
  void SetUp() override {
    page_ = std::make_unique<DummyPageHolder>();
    KURL url("https://example.com/");
    page_->GetFrame().Loader().CommitNavigation(
        WebNavigationParams::CreateWithEmptyHTMLForTesting(url),
        nullptr /* extra_data */);
    blink::test::RunPendingTasks();
    ASSERT_EQ(url.GetString(), GetDocument().Url().GetString());

    messaging_proxy_ =
        MakeGarbageCollected<ThreadedWorkletMessagingProxyForTest>(
            page_->GetFrame().DomWindow());
    ThreadedWorkletThreadForTest::EnsureSharedBackingThread();
  }

  void TearDown() override {
    GetWorkerThread()->Terminate();
    GetWorkerThread()->WaitForShutdownForTesting();
    test::RunPendingTasks();
    ThreadedWorkletThreadForTest::ClearSharedBackingThread();
    messaging_proxy_ = nullptr;
  }

  ThreadedWorkletMessagingProxyForTest* MessagingProxy() {
    return messaging_proxy_.Get();
  }

  ThreadedWorkletThreadForTest* GetWorkerThread() {
    return static_cast<ThreadedWorkletThreadForTest*>(
        messaging_proxy_->GetWorkerThread());
  }

  ExecutionContext* GetExecutionContext() {
    return page_->GetFrame().DomWindow();
  }
  Document& GetDocument() { return page_->GetDocument(); }

  void WaitForReady(WorkerThread* worker_thread) {
    base::WaitableEvent child_waitable;
    PostCrossThreadTask(
        *worker_thread->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&base::WaitableEvent::Signal,
                            CrossThreadUnretained(&child_waitable)));

    child_waitable.Wait();
  }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_;
  Persistent<ThreadedWorkletMessagingProxyForTest> messaging_proxy_;
};

TEST_F(ThreadedWorkletTest, SecurityOrigin) {
  base::RunLoop loop;
  MessagingProxy()->Start();

  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(&ThreadedWorkletThreadForTest::TestSecurityOrigin,
                          CrossThreadUnretained(GetWorkerThread()),
                          CrossThreadBindOnce(loop.QuitClosure())));
  loop.Run();
}

TEST_F(ThreadedWorkletTest, AgentCluster) {
  base::RunLoop loop;
  MessagingProxy()->Start();

  // The worklet should be in the owner window's agent cluster.
  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(&ThreadedWorkletThreadForTest::TestAgentCluster,
                          CrossThreadUnretained(GetWorkerThread()),
                          GetExecutionContext()->GetAgentClusterID(),
                          CrossThreadBindOnce(loop.QuitClosure())));
  loop.Run();
}

TEST_F(ThreadedWorkletTest, ContentSecurityPolicy) {
  base::RunLoop loop;
  // Set up the CSP for Document before starting ThreadedWorklet because
  // ThreadedWorklet inherits the owner Document's CSP.
  auto* csp = MakeGarbageCollected<ContentSecurityPolicy>();
  csp->AddPolicies(ParseContentSecurityPolicies(
      "script-src 'self' https://allowed.example.com",
      network::mojom::ContentSecurityPolicyType::kEnforce,
      network::mojom::ContentSecurityPolicySource::kHTTP,
      *(GetExecutionContext()->GetSecurityOrigin())));
  GetExecutionContext()->SetContentSecurityPolicy(csp);

  MessagingProxy()->Start();

  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(
          &ThreadedWorkletThreadForTest::TestContentSecurityPolicy,
          CrossThreadUnretained(GetWorkerThread()),
          CrossThreadBindOnce(loop.QuitClosure())));
  loop.Run();
}

TEST_F(ThreadedWorkletTest, InvalidContentSecurityPolicy) {
  base::RunLoop loop;
  auto* csp = MakeGarbageCollected<ContentSecurityPolicy>();
  csp->AddPolicies(ParseContentSecurityPolicies(
      "invalid-csp", network::mojom::ContentSecurityPolicyType::kEnforce,
      network::mojom::ContentSecurityPolicySource::kHTTP,
      *(GetExecutionContext()->GetSecurityOrigin())));
  GetExecutionContext()->SetContentSecurityPolicy(csp);

  MessagingProxy()->Start();

  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(
          &ThreadedWorkletThreadForTest::TestInvalidContentSecurityPolicy,
          CrossThreadUnretained(GetWorkerThread()),
          CrossThreadBindOnce(loop.QuitClosure())));
  loop.Run();
}

TEST_F(ThreadedWorkletTest, UseCounter) {
  Page::InsertOrdinaryPageForTesting(GetDocument().GetPage());
  MessagingProxy()->Start();

  // This feature is randomly selected.
  const WebFeature kFeature1 = WebFeature::kRequestFileSystem;

  // API use on the threaded WorkletGlobalScope should be recorded in UseCounter
  // on the Document.
  EXPECT_FALSE(GetDocument().IsUseCounted(kFeature1));
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&ThreadedWorkletThreadForTest::CountFeature,
                            CrossThreadUnretained(GetWorkerThread()), kFeature1,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }
  EXPECT_TRUE(GetDocument().IsUseCounted(kFeature1));

  // API use should be reported to the Document only one time. See comments in
  // ThreadedWorkletObjectProxyForTest::CountFeature.
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&ThreadedWorkletThreadForTest::CountFeature,
                            CrossThreadUnretained(GetWorkerThread()), kFeature1,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }

  // This feature is randomly selected from Deprecation::deprecationMessage().
  const WebFeature kFeature2 = WebFeature::kPaymentInstruments;

  // Deprecated API use on the threaded WorkletGlobalScope should be recorded in
  // UseCounter on the Document.
  EXPECT_FALSE(GetDocument().IsUseCounted(kFeature2));
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&ThreadedWorkletThreadForTest::CountDeprecation,
                            CrossThreadUnretained(GetWorkerThread()), kFeature2,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }
  EXPECT_TRUE(GetDocument().IsUseCounted(kFeature2));

  // API use should be reported to the Document only one time. See comments in
  // ThreadedWorkletObjectProxyForTest::CountDeprecation.
  {
    base::RunLoop loop;
    PostCrossThreadTask(
        *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(&ThreadedWorkletThreadForTest::CountDeprecation,
                            CrossThreadUnretained(GetWorkerThread()), kFeature2,
                            CrossThreadBindOnce(loop.QuitClosure())));
    loop.Run();
  }
}

TEST_F(ThreadedWorkletTest, TaskRunner) {
  MessagingProxy()->Start();

  base::RunLoop loop;
  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(&ThreadedWorkletThreadForTest::TestTaskRunner,
                          CrossThreadUnretained(GetWorkerThread()),
                          CrossThreadBindOnce(loop.QuitClosure())));
  loop.Run();
}

TEST_F(ThreadedWorkletTest, NestedRunLoopTermination) {
  base::RunLoop loop;
  MessagingProxy()->Start();

  ThreadedWorkletMessagingProxyForTest* second_messaging_proxy =
      MakeGarbageCollected<ThreadedWorkletMessagingProxyForTest>(
          GetExecutionContext());

  // Get a nested event loop where the first one is on the stack
  // and the second is still alive.
  second_messaging_proxy->Start();

  // Wait until the workers are setup and ready to accept work before we
  // pause them.
  WaitForReady(GetWorkerThread());
  WaitForReady(second_messaging_proxy->GetWorkerThread());

  // Pause the second worker, then the first.
  second_messaging_proxy->GetWorkerThread()->Pause();
  GetWorkerThread()->Pause();

  // Resume then terminate the second worker.
  second_messaging_proxy->GetWorkerThread()->Resume();
  second_messaging_proxy->GetWorkerThread()->Terminate();
  second_messaging_proxy = nullptr;

  // Now resume the first worker.
  GetWorkerThread()->Resume();

  // Make sure execution still works without crashing.
  PostCrossThreadTask(
      *GetWorkerThread()->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(&ThreadedWorkletThreadForTest::TestTaskRunner,
                          CrossThreadUnretained(GetWorkerThread()),
                          CrossThreadBindOnce(loop.QuitClosure())));
  loop.Run();
}

}  // namespace blink
```