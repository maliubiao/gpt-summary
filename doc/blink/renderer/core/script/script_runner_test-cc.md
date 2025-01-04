Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The core request is to analyze `script_runner_test.cc` and explain its functionality, its relation to web technologies, its logic, potential errors, and debugging steps.

2. **Identify the Core Component:** The filename itself, `script_runner_test.cc`, strongly suggests the file is a unit test for a component named `ScriptRunner`. The inclusion of `#include "third_party/blink/renderer/core/script/script_runner.h"` confirms this.

3. **Examine Imports (Headers):**  The included headers provide crucial context:
    * `script_runner.h`:  The header of the class being tested.
    * `base/test/null_task_runner.h`, `base/time/time.h`:  Indicates the use of testing utilities and time manipulation.
    * `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  Confirms this is a Google Test based unit test.
    * `mojom/frame/lifecycle.mojom-blink.h`:  Suggests interaction with the frame lifecycle, a core concept in browser rendering.
    * `platform/platform.h`:  Points to platform-specific abstractions.
    * `core/frame/local_dom_window.h`:  Indicates interaction with the DOM window object.
    * `core/script/mock_script_element_base.h`, `core/script/pending_script.h`, `core/script/script.h`:  Highlights the file's focus on script execution, specifically dealing with pending scripts and their associated elements.
    * `core/testing/dummy_page_holder.h`:  Shows the use of a test fixture simulating a web page.
    * `platform/bindings/runtime_call_stats.h`: Suggests tracking performance-related information.
    * `platform/heap/...`: Implies memory management considerations.
    * `platform/scheduler/...`: Points to interaction with the browser's task scheduling mechanisms.
    * `platform/testing/...`:  Confirms the use of Blink-specific testing utilities.

4. **Analyze the Test Fixture (`ScriptRunnerTest`):**
    * It inherits from `testing::Test`, a standard Google Test practice.
    * It creates a `DummyPageHolder` and a `Document`, setting up a minimal DOM environment.
    * It instantiates the `ScriptRunner` being tested.
    * `SetUp()` and `TearDown()` manage the lifecycle of the `ScriptRunner` and potentially related resources.
    * The helper functions `NotifyScriptReady` and `QueueScriptForExecution` reveal the core interaction patterns with the `ScriptRunner`. `NotifyScriptReady` signals that a script is ready to be executed, and `QueueScriptForExecution` adds a script to the execution queue.

5. **Examine Individual Test Cases:**  Each `TEST_F` function focuses on testing specific scenarios:
    * **Basic Queuing and Execution:**  Tests like `QueueSingleScript_Async`, `QueueSingleScript_InOrder`, and `QueueMultipleScripts_InOrder` verify the fundamental ability to queue and execute scripts, both asynchronously and in order.
    * **Mixed Script Types:** `QueueMixedScripts` tests the interaction between in-order and asynchronous scripts.
    * **Reentrancy:**  `QueueReentrantScript_Async`, `QueueReentrantScript_InOrder`, and `QueueReentrantScript_ManyAsyncScripts` explore how the `ScriptRunner` handles scenarios where script execution triggers the queuing of more scripts.
    * **Lifecycle Management:** `ResumeAndSuspend_InOrder` and `ResumeAndSuspend_Async` test how the `ScriptRunner` behaves when the frame's lifecycle state changes (e.g., pausing and resuming).
    * **Late Notifications:** `LateNotifications` checks how the system handles notifications about script readiness after the script has already been processed.
    * **Resource Management:** `TasksWithDeadScriptRunner` ensures the code doesn't crash when the `ScriptRunner` is destroyed while tasks are still pending.
    * **Streaming (Indirectly):** `TryStreamWhenEnqueingScript` suggests interaction with a streaming mechanism, though not deeply explored in this test.
    * **Delay Reasons:** `DelayReasons` delves into how the `ScriptRunner` handles scripts that are waiting for certain conditions to be met before execution.
    * **Low-Priority Tasks:** The `PostTaskWithLowPriorityUntilTimeoutTest` fixture and its tests examine a utility function for scheduling tasks with lower priority until a timeout. This is likely related to performance optimization.

6. **Identify Connections to Web Technologies:**
    * **JavaScript:** The core functionality revolves around executing scripts, which are predominantly JavaScript in web browsers. The concepts of asynchronous and synchronous script execution directly relate to how JavaScript code is loaded and run in web pages.
    * **HTML:** The `<script>` tag in HTML is the primary way to embed JavaScript. The `PendingScript` likely represents an instance of a `<script>` tag encountered during HTML parsing. The `ScriptSchedulingType` (in-order, async) directly maps to the `async` and `defer` attributes of the `<script>` tag.
    * **CSS (Indirectly):** While not directly manipulating CSS, JavaScript often interacts with the DOM to change styles. The execution of JavaScript triggered by HTML and the resulting DOM manipulation have a strong connection to CSS rendering.

7. **Infer Logical Reasoning and Examples:** For each test case, think about the preconditions, the actions performed, and the expected outcomes. For instance, in `QueueMultipleScripts_InOrder`, the assumption is that in-order scripts will execute sequentially. The `EXPECT_THAT(order_, ElementsAre(1, 2, 3));` line confirms this expectation. Hypothetical inputs are the queued scripts, and the output is the order of their execution.

8. **Consider User/Programming Errors:**  Think about common mistakes when working with scripts in web development:
    * **Forgetting `async` or `defer`:** Leads to blocking rendering. The tests for in-order vs. async scripts implicitly touch on this.
    * **Script errors:** While not explicitly tested here, the framework for handling script execution is being tested, and error handling would be a related concern.
    * **Race conditions:**  Asynchronous script execution can lead to unexpected ordering. The tests involving reentrancy and mixed scripts touch on scenarios where the order of execution needs careful management.

9. **Trace User Operations (Debugging Clues):**  Imagine a user browsing a website. How does the browser end up executing scripts?
    * **Page Load:** The browser parses HTML, encounters `<script>` tags.
    * **Script Loading:** External scripts are fetched.
    * **Script Execution:** The `ScriptRunner` is responsible for managing the execution of these scripts, respecting their `async`/`defer` attributes and the overall frame lifecycle. The tests simulate these different scenarios. A bug in the `ScriptRunner` could manifest as scripts not executing in the expected order, causing errors or unexpected behavior on the webpage.

10. **Structure the Explanation:** Organize the findings into logical sections (Functionality, Relationship to Web Technologies, Logic/Examples, Errors, Debugging). Use clear and concise language. Provide concrete examples wherever possible.

By following this structured approach, you can systematically analyze a complex piece of code and extract the necessary information to answer the prompt effectively.
这个文件 `blink/renderer/core/script/script_runner_test.cc` 是 Chromium Blink 引擎中用于测试 `ScriptRunner` 类的单元测试文件。 `ScriptRunner` 负责管理和执行 JavaScript 代码。因此，这个测试文件的主要功能是验证 `ScriptRunner` 的各种行为是否符合预期。

以下是该文件功能的详细列举，以及与 JavaScript、HTML、CSS 的关系、逻辑推理、用户/编程错误和调试线索：

**功能列举:**

1. **测试脚本的排队和执行:** 测试 `ScriptRunner` 如何将待执行的脚本（`PendingScript`）加入队列并按计划执行。
2. **测试同步和异步脚本的执行顺序:** 验证 `ScriptRunner` 是否能正确处理同步（"in-order"）和异步脚本，确保同步脚本按添加顺序执行，异步脚本可以在准备好时立即执行。
3. **测试脚本执行的重入:** 验证在脚本执行过程中，如果又添加了新的脚本，`ScriptRunner` 是否能正确处理这种情况，避免死锁或错误。
4. **测试帧生命周期对脚本执行的影响:** 验证当帧的生命周期状态改变（例如，从活动到暂停，再到恢复）时，`ScriptRunner` 是否能暂停和恢复脚本的执行。
5. **测试脚本准备就绪后的通知机制:** 验证 `ScriptRunner` 在收到脚本已准备好执行的通知后，是否能正确地启动执行。
6. **测试 `ScriptRunner` 对象被销毁后的行为:** 验证当 `ScriptRunner` 对象被销毁后，待执行的任务是否能安全地处理，避免访问已释放的内存。
7. **测试延迟执行的原因:** 验证 `ScriptRunner` 如何处理由于各种原因（例如，加载中）而需要延迟执行的脚本。
8. **测试低优先级任务的执行:** 验证 `PostTaskWithLowPriorityUntilTimeoutForTesting` 函数，该函数用于在较低优先级下执行任务，直到超时。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关系到 **JavaScript** 的执行。 `ScriptRunner` 的核心职责就是执行 JavaScript 代码。

* **JavaScript 执行顺序:**  测试用例 `QueueSingleScript_Async`, `QueueSingleScript_InOrder`, `QueueMultipleScripts_InOrder`, `QueueMixedScripts` 等直接测试了 JavaScript 代码的执行顺序。例如，HTML 中 `<script>` 标签可以有 `async` 或 `defer` 属性，这影响了脚本的加载和执行方式。`ScriptRunner` 需要正确处理这些情况。
    * **例子 (假设输入与输出):**
        * **假设输入:** HTML 中有两个 `<script>` 标签，第一个没有 `async` 或 `defer`，第二个有 `async`。
        * **预期输出:**  第一个脚本（同步脚本）会先执行完毕，然后再执行第二个脚本（异步脚本，可能在第一个脚本完成前后任何时间执行）。测试用例 `QueueMixedScripts` 模拟了这种场景。

* **HTML `<script>` 标签:**  `PendingScript` 对象通常与 HTML 中的 `<script>` 元素相关联。测试文件中的 `MockPendingScript` 模拟了这种关联，并测试了 `ScriptRunner` 如何处理来自不同 `<script>` 标签的脚本。

* **CSS (间接关系):** 虽然这个测试文件本身不直接测试 CSS，但 JavaScript 经常用于操作 CSS 样式。`ScriptRunner` 负责执行这些 JavaScript 代码，从而间接地影响了页面的样式。如果 `ScriptRunner` 的行为不正确，可能会导致 JavaScript 代码无法正确执行，从而影响 CSS 样式的应用。

**逻辑推理 (假设输入与输出):**

* **测试用例: `QueueMultipleScripts_InOrder`**
    * **假设输入:**  三个标记为 "in-order" 的 `MockPendingScript` 对象被添加到 `ScriptRunner` 的执行队列。每个 `MockPendingScript` 的 `ExecuteScriptBlock` 方法都会记录一个数字到 `order_` 向量中。
    * **预期输出:**  `order_` 向量会包含 `1, 2, 3`，表示这三个脚本按照添加的顺序依次执行。

* **测试用例: `QueueMixedScripts`**
    * **假设输入:**  五个 `MockPendingScript` 对象被添加到执行队列，其中前三个是 "in-order"，后两个是 "async"。前三个 "in-order" 脚本的 `NotifyScriptReady` 顺序与添加顺序不同。
    * **预期输出:**  异步脚本在准备好时可以先执行，而 "in-order" 脚本需要等待之前的 "in-order" 脚本执行完毕。最终的执行顺序会反映这种规则，例如 `ElementsAre(1, 5, 2, 3, 4)`，表示第一个同步脚本先执行，然后第三个异步脚本执行，接着是第二个同步脚本，依此类推。

**用户或编程常见的使用错误:**

* **忘记 `async` 或 `defer` 属性导致阻塞:** 用户在 HTML 中添加 `<script>` 标签时，如果没有使用 `async` 或 `defer` 属性，脚本会阻塞 HTML 的解析，影响页面加载速度。 `ScriptRunner` 的测试确保了在没有这些属性的情况下，脚本会按顺序执行。
* **脚本执行顺序依赖错误:** 开发者可能会错误地假设异步脚本的执行顺序，导致代码出现问题。测试用例 `QueueMixedScripts` 帮助验证 `ScriptRunner` 是否按照规范处理异步脚本的执行。
* **在脚本执行过程中修改 DOM 结构导致意外行为:**  虽然不是 `ScriptRunner` 直接负责，但其执行的 JavaScript 代码可能会这样做。如果脚本的执行顺序不确定，可能会导致依赖特定 DOM 结构的代码出错。
* **在脚本执行过程中无限循环或执行耗时操作:** 这会导致页面无响应。虽然测试用例不直接模拟这种情况，但 `ScriptRunner` 的正确性对于防止这种情况造成的损害至关重要。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中浏览网页时，以下步骤可能会导致 `ScriptRunner` 被调用和执行：

1. **用户输入 URL 或点击链接:** 浏览器开始加载网页。
2. **HTML 解析器解析 HTML 文档:** 当解析器遇到 `<script>` 标签时，会创建相应的 `PendingScript` 对象。
3. **脚本加载:** 如果是外部脚本，浏览器会发起网络请求下载脚本内容。
4. **`ScriptRunner` 排队脚本:**  `PendingScript` 对象被添加到 `ScriptRunner` 的执行队列中。脚本的类型（同步或异步）会影响其在队列中的位置和执行时机。
5. **脚本准备就绪通知:** 当脚本加载完成或者是一个内联脚本时，会通知 `ScriptRunner` 该脚本已准备好执行。
6. **`ScriptRunner` 执行脚本:**  `ScriptRunner` 根据脚本的类型和当前的状态，选择合适的时机执行脚本代码。这涉及到调用 JavaScript 引擎来执行代码。

**作为调试线索:**

* **页面加载缓慢或卡顿:** 如果用户遇到页面加载缓慢或卡顿的情况，可能是由于 JavaScript 执行时间过长或脚本加载被阻塞。调试时可以关注 `ScriptRunner` 的行为，查看是否有大量的同步脚本阻塞了页面渲染。
* **JavaScript 错误或异常:** 用户可能会看到 JavaScript 错误信息。调试时需要查看哪个脚本导致了错误，以及 `ScriptRunner` 是否按照预期的顺序执行了脚本。
* **页面交互异常:** 如果用户在与网页交互时遇到异常行为，例如按钮点击没有反应，可能是由于 JavaScript 代码没有正确执行。调试时需要检查 `ScriptRunner` 是否正确地执行了相关的事件处理脚本。
* **使用开发者工具:**  浏览器的开发者工具 (如 Chrome DevTools) 提供了 "Sources" 或 "Debugger" 面板，可以帮助开发者查看脚本的加载和执行顺序，设置断点，单步调试 JavaScript 代码，从而深入了解 `ScriptRunner` 的工作流程。

总而言之，`blink/renderer/core/script/script_runner_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎中负责 JavaScript 执行的 `ScriptRunner` 类的功能正确可靠，这对于用户流畅地浏览网页和执行网页上的交互操作至关重要。

Prompt: 
```
这是目录为blink/renderer/core/script/script_runner_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/script/script_runner.h"

#include "base/test/null_task_runner.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/script/mock_script_element_base.h"
#include "third_party/blink/renderer/core/script/pending_script.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"

using testing::InvokeWithoutArgs;
using testing::ElementsAre;
using testing::Return;
using testing::WhenSorted;
using testing::ElementsAreArray;
using testing::_;

namespace blink {

class MockPendingScript : public PendingScript {
 public:
  static MockPendingScript* CreateInOrder(Document* document) {
    return Create(document, ScriptSchedulingType::kInOrder);
  }

  static MockPendingScript* CreateAsync(Document* document) {
    return Create(document, ScriptSchedulingType::kAsync);
  }

  MockPendingScript(ScriptElementBase* element,
                    ScriptSchedulingType scheduling_type)
      : PendingScript(element,
                      TextPosition::MinimumPosition(),
                      /*parent_task=*/nullptr) {
    SetSchedulingType(scheduling_type);
  }
  ~MockPendingScript() override {}

  MOCK_CONST_METHOD0(GetScriptType, mojom::blink::ScriptType());
  MOCK_CONST_METHOD1(CheckMIMETypeBeforeRunScript, bool(Document*));
  MOCK_CONST_METHOD0(GetSource, Script*());
  MOCK_CONST_METHOD0(IsExternal, bool());
  MOCK_CONST_METHOD0(WasCanceled, bool());
  MOCK_CONST_METHOD0(UrlForTracing, KURL());
  MOCK_METHOD0(RemoveFromMemoryCache, void());
  MOCK_METHOD0(ExecuteScriptBlock, void());

  bool IsReady() const override { return is_ready_; }
  void SetIsReady(bool is_ready) { is_ready_ = is_ready; }

 protected:
  MOCK_METHOD0(DisposeInternal, void());
  MOCK_CONST_METHOD0(CheckState, void());

 private:
  static MockPendingScript* Create(Document* document,
                                   ScriptSchedulingType scheduling_type) {
    MockScriptElementBase* element = MockScriptElementBase::Create();
    EXPECT_CALL(*element, GetDocument())
        .WillRepeatedly(testing::ReturnRef(*document));
    EXPECT_CALL(*element, GetExecutionContext())
        .WillRepeatedly(testing::Return(document->GetExecutionContext()));
    MockPendingScript* pending_script =
        MakeGarbageCollected<MockPendingScript>(element, scheduling_type);
    EXPECT_CALL(*pending_script, IsExternal()).WillRepeatedly(Return(true));
    return pending_script;
  }

  bool is_ready_ = false;
  base::OnceClosure streaming_finished_callback_;
};

class ScriptRunnerTest : public testing::Test {
 public:
  ScriptRunnerTest()
      : page_holder_(std::make_unique<DummyPageHolder>()),
        document_(&page_holder_->GetDocument()) {}

  void SetUp() override {
    script_runner_ = MakeGarbageCollected<ScriptRunner>(document_.Get());
    // Give ScriptRunner a task runner that platform_ will pump in
    // RunUntilIdle()/RunSingleTask().
    script_runner_->SetTaskRunnerForTesting(
        platform_->GetMainThreadScheduler()->DefaultTaskRunner().get());
    RuntimeCallStats::SetRuntimeCallStatsForTesting();
  }
  void TearDown() override {
    script_runner_.Release();
    RuntimeCallStats::ClearRuntimeCallStatsForTesting();
  }

 protected:
  void NotifyScriptReady(MockPendingScript* pending_script) {
    pending_script->SetIsReady(true);
    script_runner_->PendingScriptFinished(pending_script);
  }

  void QueueScriptForExecution(MockPendingScript* pending_script) {
    script_runner_->QueueScriptForExecution(
        pending_script, static_cast<ScriptRunner::DelayReasons>(
                            ScriptRunner::DelayReason::kLoad));
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
  Persistent<Document> document_;
  Persistent<ScriptRunner> script_runner_;
  WTF::Vector<int> order_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;
};

TEST_F(ScriptRunnerTest, QueueSingleScript_Async) {
  auto* pending_script = MockPendingScript::CreateAsync(document_);

  QueueScriptForExecution(pending_script);
  NotifyScriptReady(pending_script);

  EXPECT_CALL(*pending_script, ExecuteScriptBlock());
  platform_->RunUntilIdle();
}

TEST_F(ScriptRunnerTest, QueueSingleScript_InOrder) {
  auto* pending_script = MockPendingScript::CreateInOrder(document_);
  QueueScriptForExecution(pending_script);

  EXPECT_CALL(*pending_script, ExecuteScriptBlock());

  NotifyScriptReady(pending_script);

  platform_->RunUntilIdle();
}

TEST_F(ScriptRunnerTest, QueueMultipleScripts_InOrder) {
  auto* pending_script1 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script2 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script3 = MockPendingScript::CreateInOrder(document_);

  HeapVector<Member<MockPendingScript>> pending_scripts;
  pending_scripts.push_back(pending_script1);
  pending_scripts.push_back(pending_script2);
  pending_scripts.push_back(pending_script3);

  for (MockPendingScript* pending_script : pending_scripts) {
    QueueScriptForExecution(pending_script);
  }

  for (wtf_size_t i = 0; i < pending_scripts.size(); ++i) {
    EXPECT_CALL(*pending_scripts[i], ExecuteScriptBlock())
        .WillOnce(InvokeWithoutArgs([this, i] { order_.push_back(i + 1); }));
  }

  for (int i = 2; i >= 0; i--) {
    NotifyScriptReady(pending_scripts[i]);
    platform_->RunUntilIdle();
  }

  // But ensure the scripts were run in the expected order.
  EXPECT_THAT(order_, ElementsAre(1, 2, 3));
}

TEST_F(ScriptRunnerTest, QueueMixedScripts) {
  auto* pending_script1 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script2 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script3 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script4 = MockPendingScript::CreateAsync(document_);
  auto* pending_script5 = MockPendingScript::CreateAsync(document_);

  QueueScriptForExecution(pending_script1);
  QueueScriptForExecution(pending_script2);
  QueueScriptForExecution(pending_script3);
  QueueScriptForExecution(pending_script4);
  QueueScriptForExecution(pending_script5);

  NotifyScriptReady(pending_script1);
  NotifyScriptReady(pending_script3);
  NotifyScriptReady(pending_script5);

  EXPECT_CALL(*pending_script1, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(1); }));
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(2); }));
  EXPECT_CALL(*pending_script3, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(3); }));
  EXPECT_CALL(*pending_script4, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(4); }));
  EXPECT_CALL(*pending_script5, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(5); }));

  platform_->RunSingleTask();
  document_->domWindow()->SetLifecycleState(
      mojom::FrameLifecycleState::kPaused);
  document_->domWindow()->SetLifecycleState(
      mojom::FrameLifecycleState::kRunning);
  platform_->RunUntilIdle();

  // In-order script 3 cannot run, since in-order script 2 just scheduled before
  // is not yet ready.
  // Async scripts that are ready can skip the previously queued other async
  // scripts, so 5 runs.
  EXPECT_THAT(order_, ElementsAre(1, 5));

  NotifyScriptReady(pending_script2);
  NotifyScriptReady(pending_script4);
  platform_->RunUntilIdle();

  // In-order script 3 can now run.
  EXPECT_THAT(order_, ElementsAre(1, 5, 2, 3, 4));
}

TEST_F(ScriptRunnerTest, QueueReentrantScript_Async) {
  auto* pending_script1 = MockPendingScript::CreateAsync(document_);
  auto* pending_script2 = MockPendingScript::CreateAsync(document_);
  auto* pending_script3 = MockPendingScript::CreateAsync(document_);

  QueueScriptForExecution(pending_script1);
  QueueScriptForExecution(pending_script2);
  QueueScriptForExecution(pending_script3);
  NotifyScriptReady(pending_script1);

  auto* pending_script = pending_script2;
  EXPECT_CALL(*pending_script1, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([pending_script, this] {
        order_.push_back(1);
        NotifyScriptReady(pending_script);
      }));

  pending_script = pending_script3;
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([pending_script, this] {
        order_.push_back(2);
        NotifyScriptReady(pending_script);
      }));

  EXPECT_CALL(*pending_script3, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(3); }));

  // Make sure that re-entrant calls to notifyScriptReady don't cause
  // ScriptRunner::execute to do more work than expected.
  platform_->RunSingleTask();
  EXPECT_THAT(order_, ElementsAre(1));

  platform_->RunSingleTask();
  EXPECT_THAT(order_, ElementsAre(1, 2));

  platform_->RunSingleTask();
  EXPECT_THAT(order_, ElementsAre(1, 2, 3));
}

TEST_F(ScriptRunnerTest, QueueReentrantScript_InOrder) {
  auto* pending_script1 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script2 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script3 = MockPendingScript::CreateInOrder(document_);

  QueueScriptForExecution(pending_script1);
  NotifyScriptReady(pending_script1);

  MockPendingScript* pending_script = pending_script2;
  EXPECT_CALL(*pending_script1, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([pending_script, &pending_script2, this] {
        order_.push_back(1);
        QueueScriptForExecution(pending_script);
        NotifyScriptReady(pending_script2);
      }));

  pending_script = pending_script3;
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([pending_script, &pending_script3, this] {
        order_.push_back(2);
        QueueScriptForExecution(pending_script);
        NotifyScriptReady(pending_script3);
      }));

  EXPECT_CALL(*pending_script3, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(3); }));

  // Make sure that re-entrant calls to queueScriptForExecution don't cause
  // ScriptRunner::execute to do more work than expected.
  platform_->RunSingleTask();
  EXPECT_THAT(order_, ElementsAre(1));

  platform_->RunSingleTask();
  EXPECT_THAT(order_, ElementsAre(1, 2));

  platform_->RunSingleTask();
  EXPECT_THAT(order_, ElementsAre(1, 2, 3));
}

TEST_F(ScriptRunnerTest, QueueReentrantScript_ManyAsyncScripts) {
  MockPendingScript* pending_scripts[20];
  for (int i = 0; i < 20; i++)
    pending_scripts[i] = nullptr;

  for (int i = 0; i < 20; i++) {
    pending_scripts[i] = MockPendingScript::CreateAsync(document_);

    QueueScriptForExecution(pending_scripts[i]);

    if (i > 0) {
      EXPECT_CALL(*pending_scripts[i], ExecuteScriptBlock())
          .WillOnce(InvokeWithoutArgs([this, i] { order_.push_back(i); }));
    }
  }

  NotifyScriptReady(pending_scripts[0]);
  NotifyScriptReady(pending_scripts[1]);

  EXPECT_CALL(*pending_scripts[0], ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([&pending_scripts, this] {
        for (int i = 2; i < 20; i++) {
          NotifyScriptReady(pending_scripts[i]);
        }
        order_.push_back(0);
      }));

  platform_->RunUntilIdle();

  int expected[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                    10, 11, 12, 13, 14, 15, 16, 17, 18, 19};

  EXPECT_THAT(order_, testing::ElementsAreArray(expected));
}

TEST_F(ScriptRunnerTest, ResumeAndSuspend_InOrder) {
  auto* pending_script1 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script2 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script3 = MockPendingScript::CreateInOrder(document_);

  QueueScriptForExecution(pending_script1);
  QueueScriptForExecution(pending_script2);
  QueueScriptForExecution(pending_script3);

  EXPECT_CALL(*pending_script1, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(1); }));
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(2); }));
  EXPECT_CALL(*pending_script3, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(3); }));

  NotifyScriptReady(pending_script1);
  NotifyScriptReady(pending_script2);
  NotifyScriptReady(pending_script3);

  document_->domWindow()->SetLifecycleState(
      mojom::FrameLifecycleState::kPaused);
  document_->domWindow()->SetLifecycleState(
      mojom::FrameLifecycleState::kRunning);
  platform_->RunUntilIdle();

  // Make sure elements are correct and in right order.
  EXPECT_THAT(order_, ElementsAre(1, 2, 3));
}

TEST_F(ScriptRunnerTest, ResumeAndSuspend_Async) {
  auto* pending_script1 = MockPendingScript::CreateAsync(document_);
  auto* pending_script2 = MockPendingScript::CreateAsync(document_);
  auto* pending_script3 = MockPendingScript::CreateAsync(document_);

  QueueScriptForExecution(pending_script1);
  QueueScriptForExecution(pending_script2);
  QueueScriptForExecution(pending_script3);

  NotifyScriptReady(pending_script1);
  NotifyScriptReady(pending_script2);
  NotifyScriptReady(pending_script3);

  EXPECT_CALL(*pending_script1, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(1); }));
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(2); }));
  EXPECT_CALL(*pending_script3, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(3); }));

  document_->domWindow()->SetLifecycleState(
      mojom::FrameLifecycleState::kPaused);
  document_->domWindow()->SetLifecycleState(
      mojom::FrameLifecycleState::kRunning);
  platform_->RunUntilIdle();

  // Make sure elements are correct.
  EXPECT_THAT(order_, WhenSorted(ElementsAre(1, 2, 3)));
}

TEST_F(ScriptRunnerTest, LateNotifications) {
  auto* pending_script1 = MockPendingScript::CreateInOrder(document_);
  auto* pending_script2 = MockPendingScript::CreateInOrder(document_);

  QueueScriptForExecution(pending_script1);
  QueueScriptForExecution(pending_script2);

  EXPECT_CALL(*pending_script1, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(1); }));
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock())
      .WillOnce(InvokeWithoutArgs([this] { order_.push_back(2); }));

  NotifyScriptReady(pending_script1);
  platform_->RunUntilIdle();

  // At this moment all tasks can be already executed. Make sure that we do not
  // crash here.
  NotifyScriptReady(pending_script2);
  platform_->RunUntilIdle();

  EXPECT_THAT(order_, ElementsAre(1, 2));
}

TEST_F(ScriptRunnerTest, TasksWithDeadScriptRunner) {
  Persistent<MockPendingScript> pending_script1 =
      MockPendingScript::CreateAsync(document_);
  Persistent<MockPendingScript> pending_script2 =
      MockPendingScript::CreateAsync(document_);

  QueueScriptForExecution(pending_script1);
  QueueScriptForExecution(pending_script2);

  NotifyScriptReady(pending_script1);
  NotifyScriptReady(pending_script2);

  script_runner_.Release();

  ThreadState::Current()->CollectAllGarbageForTesting();

  // m_scriptRunner is gone. We need to make sure that ScriptRunner::Task do not
  // access dead object.
  EXPECT_CALL(*pending_script1, ExecuteScriptBlock()).Times(0);
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock()).Times(0);

  platform_->RunUntilIdle();
}

TEST_F(ScriptRunnerTest, TryStreamWhenEnqueingScript) {
  auto* pending_script1 = MockPendingScript::CreateAsync(document_);
  pending_script1->SetIsReady(true);
  QueueScriptForExecution(pending_script1);
}

TEST_F(ScriptRunnerTest, DelayReasons) {
  // Script waiting only for loading.
  MockPendingScript* pending_script1 =
      MockPendingScript::CreateAsync(document_);

  // Script waiting for one additional delay reason.
  MockPendingScript* pending_script2 =
      MockPendingScript::CreateAsync(document_);

  // Script waiting for two additional delay reason.
  MockPendingScript* pending_script3 =
      MockPendingScript::CreateAsync(document_);

  // Script waiting for an additional delay reason that is removed before load
  // completion.
  MockPendingScript* pending_script4 =
      MockPendingScript::CreateAsync(document_);

  using Checkpoint = testing::StrictMock<testing::MockFunction<void(int)>>;
  Checkpoint checkpoint;
  ::testing::InSequence s;

  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*pending_script1, ExecuteScriptBlock());
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*pending_script2, ExecuteScriptBlock());
  EXPECT_CALL(checkpoint, Call(4));
  EXPECT_CALL(checkpoint, Call(5));
  EXPECT_CALL(*pending_script3, ExecuteScriptBlock());
  EXPECT_CALL(checkpoint, Call(6));
  EXPECT_CALL(checkpoint, Call(7));
  EXPECT_CALL(*pending_script4, ExecuteScriptBlock());
  EXPECT_CALL(checkpoint, Call(8));
  EXPECT_CALL(checkpoint, Call(9));

  auto* delayer1 = MakeGarbageCollected<ScriptRunnerDelayer>(
      script_runner_, ScriptRunner::DelayReason::kTest1);
  auto* delayer2 = MakeGarbageCollected<ScriptRunnerDelayer>(
      script_runner_, ScriptRunner::DelayReason::kTest2);
  delayer1->Activate();
  delayer1->Activate();
  delayer2->Activate();

  script_runner_->QueueScriptForExecution(
      pending_script1, static_cast<int>(ScriptRunner::DelayReason::kLoad));
  script_runner_->QueueScriptForExecution(
      pending_script2, static_cast<int>(ScriptRunner::DelayReason::kLoad) |
                           static_cast<int>(ScriptRunner::DelayReason::kTest1));
  script_runner_->QueueScriptForExecution(
      pending_script3, static_cast<int>(ScriptRunner::DelayReason::kLoad) |
                           static_cast<int>(ScriptRunner::DelayReason::kTest1) |
                           static_cast<int>(ScriptRunner::DelayReason::kTest2));
  script_runner_->QueueScriptForExecution(
      pending_script4, static_cast<int>(ScriptRunner::DelayReason::kLoad) |
                           static_cast<int>(ScriptRunner::DelayReason::kTest1));

  NotifyScriptReady(pending_script1);
  NotifyScriptReady(pending_script2);
  NotifyScriptReady(pending_script3);

  checkpoint.Call(1);
  platform_->RunUntilIdle();
  checkpoint.Call(2);
  delayer1->Deactivate();
  checkpoint.Call(3);
  platform_->RunUntilIdle();

  checkpoint.Call(4);
  delayer2->Deactivate();
  checkpoint.Call(5);
  platform_->RunUntilIdle();

  checkpoint.Call(6);
  NotifyScriptReady(pending_script4);
  checkpoint.Call(7);
  platform_->RunUntilIdle();

  checkpoint.Call(8);
  delayer2->Deactivate();
  checkpoint.Call(9);
  platform_->RunUntilIdle();
}

class PostTaskWithLowPriorityUntilTimeoutTest : public testing::Test {
 public:
  PostTaskWithLowPriorityUntilTimeoutTest()
      : task_runner_(platform_->test_task_runner()),
        null_task_runner_(base::MakeRefCounted<base::NullTaskRunner>()) {}

 protected:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner_;
  scoped_refptr<base::NullTaskRunner> null_task_runner_;
};

TEST_F(PostTaskWithLowPriorityUntilTimeoutTest, RunTaskOnce) {
  int counter = 0;
  base::OnceClosure task = WTF::BindOnce([](int* counter) { (*counter)++; },
                                         WTF::Unretained(&counter));

  PostTaskWithLowPriorityUntilTimeoutForTesting(
      FROM_HERE, std::move(task), base::Seconds(1),
      /*lower_priority_task_runner=*/task_runner_,
      /*normal_priority_task_runner=*/task_runner_);

  EXPECT_EQ(0, counter);
  EXPECT_EQ(2u, task_runner_->GetPendingTaskCount());
  platform_->SetAutoAdvanceNowToPendingTasks(true);
  platform_->RunUntilIdle();
  EXPECT_EQ(1, counter);
  EXPECT_EQ(0u, task_runner_->GetPendingTaskCount());
}

TEST_F(PostTaskWithLowPriorityUntilTimeoutTest, RunOnLowerPriorityTaskRunner) {
  int counter = 0;
  base::OnceClosure task = WTF::BindOnce([](int* counter) { (*counter)++; },
                                         WTF::Unretained(&counter));

  PostTaskWithLowPriorityUntilTimeoutForTesting(
      FROM_HERE, std::move(task), base::Seconds(1),
      /*lower_priority_task_runner=*/task_runner_,
      /*normal_priority_task_runner=*/null_task_runner_);

  EXPECT_EQ(0, counter);
  EXPECT_EQ(1u, task_runner_->GetPendingTaskCount());
  platform_->RunSingleTask();
  EXPECT_EQ(1, counter);
  EXPECT_EQ(0u, task_runner_->GetPendingTaskCount());
}

TEST_F(PostTaskWithLowPriorityUntilTimeoutTest, RunOnNormalPriorityTaskRunner) {
  int counter = 0;
  base::OnceClosure task = WTF::BindOnce([](int* counter) { (*counter)++; },
                                         WTF::Unretained(&counter));

  PostTaskWithLowPriorityUntilTimeoutForTesting(
      FROM_HERE, std::move(task), base::Seconds(1),
      /*lower_priority_task_runner=*/null_task_runner_,
      /*normal_priority_task_runner=*/task_runner_);

  EXPECT_EQ(0, counter);
  EXPECT_EQ(1u, task_runner_->GetPendingTaskCount());
  platform_->RunSingleTask();
  EXPECT_EQ(1, counter);
  EXPECT_EQ(0u, task_runner_->GetPendingTaskCount());
}

}  // namespace blink

"""

```