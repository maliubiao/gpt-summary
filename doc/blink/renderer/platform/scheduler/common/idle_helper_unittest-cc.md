Response: Let's break down the thought process to analyze the provided C++ unittest file.

1. **Understand the Goal:** The request asks for a summary of the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors. The file name strongly suggests it's testing `IdleHelper`.

2. **Initial Skim and Identification of Key Components:**  Read through the code quickly, identifying major sections and classes. Keywords like `TEST_F`, `EXPECT_EQ`, `PostIdleTask`, `StartIdlePeriod`, `EnableLongIdlePeriod`, and the presence of mock objects (`MOCK_METHOD`) immediately stand out. The included headers also provide clues: `base/test/test_mock_time_task_runner.h` strongly indicates time-based testing.

3. **Focus on the Core Class Under Test:** The name of the file, `idle_helper_unittest.cc`, and the inclusion of `#include "third_party/blink/renderer/platform/scheduler/common/idle_helper.h"` clearly indicate that the `IdleHelper` class is the central subject.

4. **Analyze the Test Structure:** Observe the use of Google Test framework (`TEST_F`, `EXPECT_*`). Notice the different test fixture classes: `BaseIdleHelperTest`, `IdleHelperTest`, `IdleHelperTestWithIdlePeriodObserver`, `IdleHelperWithQuiescencePeriodTest`, and `MultiThreadedIdleHelperTest`. This suggests different aspects of `IdleHelper` are being tested in isolation.

5. **Infer Functionality from Test Names and Assertions:** Examine the individual test case names (e.g., `TestPostIdleTask`, `TestLongIdlePeriod`, `TestIdleTaskExceedsDeadline`). These names are very descriptive and provide a good overview of the features being tested. Look at the `EXPECT_*` calls within each test to understand the expected behavior. For instance, `EXPECT_EQ(1, run_count)` after calling `StartIdlePeriod` suggests that an idle task should have been executed.

6. **Identify Key `IdleHelper` Methods Being Tested:**  Based on the test cases, compile a list of the major methods of `IdleHelper` that are being exercised:
    * `PostIdleTask` and `PostDelayedIdleTask`:  Scheduling idle tasks.
    * `StartIdlePeriod`: Manually triggering a short idle period.
    * `EnableLongIdlePeriod`: Triggering a long idle period.
    * `EndIdlePeriod`: Manually ending an idle period.
    * `Shutdown`: Shutting down the `IdleHelper`.
    * `CanExceedIdleDeadlineIfRequired`: Checking if an idle task can exceed its deadline.
    * (Implicitly) The various states of the idle period.

7. **Consider the Role of Mock Objects:**  Note the `IdleHelperForTest` class and its mocked methods: `CanEnterLongIdlePeriod`, `IsNotQuiescent`, `OnIdlePeriodStarted`, `OnIdlePeriodEnded`, `OnPendingTasksChanged`. This indicates the tests are verifying the interactions between `IdleHelper` and its delegate.

8. **Relate to Web Technologies (JavaScript, HTML, CSS):** This requires understanding *why* an `IdleHelper` would exist in a browser engine. Think about browser performance and how to defer less critical tasks. Idle tasks are ideal for things like:
    * **JavaScript:** Running non-critical JavaScript code when the browser is not busy with user interactions or rendering. Examples: analytics, pre-caching, background updates.
    * **HTML/DOM:**  Performing non-urgent DOM manipulations or layout adjustments.
    * **CSS:**  Potentially related to applying complex CSS styles or animations that are not time-critical.

9. **Logical Reasoning Examples:**  Identify tests that demonstrate conditional behavior or cause-and-effect relationships. For instance, the `TestIdleTaskExceedsDeadline` test shows that if an idle task consumes the entire idle period, subsequent idle tasks won't run until the next idle period. Formulate these as "If [input/scenario], then [output/behavior]".

10. **Common Usage Errors:**  Think about how a developer using `IdleHelper` might misuse it. Consider scenarios like:
    * Forgetting to start the idle period.
    * Posting too many long-running idle tasks that block other important work.
    * Incorrectly assuming idle tasks will run immediately.
    * Not handling the possibility that idle tasks might not run at all if the browser is constantly busy.

11. **Refine and Organize:** Structure the analysis logically with clear headings and bullet points. Provide specific code examples where relevant (even if paraphrased for brevity). Ensure the language is clear and easy to understand for someone not intimately familiar with the Chromium codebase.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps the `IdleHelper` directly interacts with the rendering pipeline. **Correction:** While related to browser performance, the tests focus on task scheduling, suggesting it's a lower-level utility.
* **Initial thought:** The connection to web technologies might be very direct (e.g., a test involving specific DOM APIs). **Correction:** The connection is more conceptual. The tests demonstrate scheduling behavior that *enables* deferring web-related tasks.
* **Review of Test Names:** Realizing the test names are a goldmine of information and using them to structure the functional summary.

By following these steps, analyzing the code structure, test cases, and considering the context of a browser engine, a comprehensive understanding of the `IdleHelper` and the functionality of the unittest file can be achieved.
这个文件 `idle_helper_unittest.cc` 是 Chromium Blink 引擎中 `IdleHelper` 类的单元测试。`IdleHelper` 的主要功能是管理和调度在浏览器空闲时执行的任务，目的是在不影响用户体验的前提下利用空闲时间执行一些低优先级的任务。

以下是 `idle_helper_unittest.cc` 文件测试的主要功能点，并说明了它与 JavaScript, HTML, CSS 功能的关系，以及逻辑推理、常见使用错误等：

**主要功能测试点：**

1. **空闲任务的发布和执行 (`TestPostIdleTask`, `TestPostDelayedIdleTask`):**
   - 测试 `PostIdleTask` 和 `PostDelayedIdleTask` 方法是否能正确地将任务添加到空闲队列中。
   - 测试空闲任务是否在进入空闲期后被执行。
   - 测试延迟的空闲任务是否在指定的延迟后才被加入队列并执行。

   **与 JavaScript, HTML, CSS 的关系举例：**
   - **JavaScript:**  可以利用 `IdleHelper` 在浏览器空闲时执行一些非关键的 JavaScript 代码，例如：
     -  发送分析数据：`idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce([](){ SendAnalyticsData(); }));`
     -  预编译或缓存数据：`idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce([](){ PrecacheExpensiveData(); }));`
   - **HTML/DOM:**  在空闲时进行一些非阻塞的 DOM 操作，例如：
     -  懒加载图片：当视口没有压力时，加载剩余的图片。
     -  更新不重要的 UI 元素。
   - **CSS:**  可以用于应用一些非关键的 CSS 样式或进行一些 CSS 相关的计算，但这种情况相对较少，因为 CSS 的应用通常与渲染过程紧密相关。

   **逻辑推理（假设输入与输出）：**
   - **假设输入:** 发布一个空闲任务，然后启动一个短空闲期。
   - **预期输出:**  在空闲期内，该空闲任务会被执行。

2. **空闲期的启动和结束 (`TestEnterAndExitIdlePeriod`, `TestLongIdlePeriod`):**
   - 测试 `StartIdlePeriod` 和 `EndIdlePeriod` 方法是否能正确地控制空闲期的开始和结束。
   - 测试长空闲期 (`EnableLongIdlePeriod`) 的工作机制，包括是否会在没有待处理任务时进入长空闲期。
   - 测试长空闲期在有延迟任务时的行为，例如是否会等待延迟任务执行完毕。

   **与 JavaScript, HTML, CSS 的关系举例：**
   - 浏览器内部会根据用户的交互和页面的状态来判断是否应该进入空闲期。`IdleHelper` 帮助管理这个过程。

   **逻辑推理：**
   - **假设输入:** 启用长空闲期，且没有其他高优先级任务。
   - **预期输出:**  `IdleHelper` 会启动一个长空闲期，并在该期间执行已发布的空闲任务。

3. **空闲任务执行的截止时间 (`TestIdleTaskExceedsDeadline`):**
   - 测试空闲任务是否会受到截止时间的限制，如果在截止时间前未能完成，是否会暂停执行。

   **与 JavaScript, HTML, CSS 的关系举例：**
   - 确保空闲任务不会占用过多时间，影响后续的渲染或其他更重要的任务，从而保证用户体验的流畅性。

   **逻辑推理：**
   - **假设输入:** 发布两个空闲任务，启动一个非常短的空闲期，该空闲期不足以执行完两个任务。
   - **预期输出:** 第一个空闲任务可能会执行一部分或全部，但第二个任务不会在当前的空闲期内执行。

4. **重新发布空闲任务 (`TestRepostingIdleTask`):**
   - 测试空闲任务执行后是否可以重新发布自身，以便在后续的空闲期继续执行。

   **与 JavaScript, HTML, CSS 的关系举例：**
   - 一些需要分阶段执行的空闲任务可能会用到这种机制。

   **逻辑推理：**
   - **假设输入:** 发布一个会重新发布自身的空闲任务，启动多个短空闲期。
   - **预期输出:** 该空闲任务会在每个空闲期执行一次，直到达到设定的重新发布次数。

5. **长空闲期的条件 (`TestLongIdlePeriodWhenNotCanEnterLongIdlePeriod`, `LongIdlePeriodStartsImmediatelyIfQuiescent`):**
   - 测试进入长空闲期需要满足的条件，例如系统是否处于静止状态（quiescent）。
   - 测试 `CanEnterLongIdlePeriod` 委托方法的作用。

   **与 JavaScript, HTML, CSS 的关系举例：**
   - 浏览器需要判断当前是否适合进入长空闲期，例如在用户正在交互或页面正在进行重要渲染时不应进入。

   **逻辑推理：**
   - **假设输入:** 启用长空闲期，但 `CanEnterLongIdlePeriod` 返回 false。
   - **预期输出:**  `IdleHelper` 不会立即进入长空闲期，而是会等待条件满足。

6. **与延迟任务的交互 (`TestLongIdlePeriodWithPendingDelayedTask`, `TestLongIdlePeriodWithLatePendingDelayedTask`):**
   - 测试长空闲期与普通延迟任务之间的交互，例如长空闲期的截止时间是否会受到延迟任务的影响。

   **与 JavaScript, HTML, CSS 的关系举例：**
   - 需要协调不同优先级的任务，确保高优先级的延迟任务能够及时执行。

   **逻辑推理：**
   - **假设输入:** 启用长空闲期，同时存在一个即将到期的延迟任务。
   - **预期输出:** 长空闲期的截止时间会被设置为延迟任务的执行时间。

7. **在非主线程发布空闲任务 (`IdleTasksFromNonMainThreads`):**
   - 测试是否可以从非主线程发布空闲任务。

   **与 JavaScript, HTML, CSS 的关系举例：**
   - 某些需要在后台线程执行的辅助操作，可以在空闲时利用 `IdleHelper` 进行调度。

8. **`OnPendingTasksChanged` 回调 (`OnPendingTasksChanged`):**
   - 测试当空闲队列中的任务状态发生变化时，是否会调用 `OnPendingTasksChanged` 回调。

   **与 JavaScript, HTML, CSS 的关系举例：**
   -  `IdleHelper` 的使用者可以通过这个回调来了解空闲队列的状态，并根据需要做出相应的处理。

**常见的使用错误举例：**

1. **忘记启动空闲期：**  如果发布了空闲任务，但没有调用 `StartIdlePeriod` 或 `EnableLongIdlePeriod`，那么这些空闲任务将不会被执行。
   ```c++
   idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce([](){ /* 一些操作 */ }));
   // 错误：忘记调用 idle_helper_->StartIdlePeriod(...) 或 idle_helper_->EnableLongIdlePeriod();
   ```
   **后果:** 空闲任务永远不会执行。

2. **在不合适的时机启用长空闲期：** 如果在浏览器繁忙时启用长空闲期，可能会导致一些低优先级的任务在不恰当的时间执行，影响性能。
   ```c++
   // 假设此时浏览器正在处理用户交互
   idle_helper_->EnableLongIdlePeriod(); // 可能不是最佳时机
   ```
   **后果:**  可能会导致卡顿或响应延迟。

3. **假设空闲任务会立即执行：**  空闲任务只有在浏览器进入空闲状态后才会被执行，不能假设它们会像普通任务一样立即运行。
   ```c++
   idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce([](){ 
       // 错误假设：这段代码会立即运行
   }));
   // 后续代码依赖于空闲任务的执行结果，可能会出错
   ```
   **后果:**  可能导致程序逻辑错误或数据不一致。

4. **发布耗时过长的空闲任务：** 如果空闲任务执行时间过长，可能会占用后续的空闲期，甚至影响到用户交互。
   ```c++
   idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce([](){ 
       // 执行一个非常耗时的操作，例如大数据计算
   }));
   ```
   **后果:**  可能会导致后续的空闲任务无法及时执行，甚至影响用户体验。

5. **在 `Shutdown` 后尝试发布空闲任务：** 一旦 `IdleHelper` 被 `Shutdown`，就不能再发布新的空闲任务。
   ```c++
   idle_helper_->Shutdown();
   idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce([](){ /* ... */ })); // 错误：Shutdown 后不应发布
   ```
   **后果:**  发布操作可能被忽略或导致未定义的行为。

总而言之，`idle_helper_unittest.cc` 文件全面地测试了 `IdleHelper` 类的各种功能和边界情况，确保它能够正确地管理和调度浏览器的空闲任务，从而在不影响用户体验的前提下，有效地利用空闲时间执行一些后台操作。理解这些测试用例有助于开发者正确地使用 `IdleHelper`，并在涉及 JavaScript、HTML 和 CSS 的异步操作时做出更合理的调度决策。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/common/idle_helper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/common/idle_helper.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/run_loop.h"
#include "base/task/common/lazy_now.h"
#include "base/task/sequence_manager/sequence_manager.h"
#include "base/task/sequence_manager/task_queue.h"
#include "base/task/sequence_manager/test/sequence_manager_for_test.h"
#include "base/task/sequence_manager/time_domain.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/scheduler/common/scheduler_helper.h"
#include "third_party/blink/renderer/platform/scheduler/common/single_thread_idle_task_runner.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/worker/non_main_thread_scheduler_helper.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using testing::_;
using testing::AnyNumber;
using testing::AtLeast;
using testing::Exactly;
using testing::Invoke;
using testing::Return;

namespace blink {
namespace scheduler {
// To avoid symbol collisions in jumbo builds.
namespace idle_helper_unittest {

using base::sequence_manager::SequenceManager;
using base::sequence_manager::TaskQueue;

void AppendToVectorTestTask(Vector<String>* vector, String value) {
  vector->push_back(value);
}

void AppendToVectorIdleTestTask(Vector<String>* vector,
                                String value,
                                base::TimeTicks deadline) {
  AppendToVectorTestTask(vector, value);
}

void NullTask() {}

void NullIdleTask(base::TimeTicks deadline) {}

void AppendToVectorReentrantTask(base::SingleThreadTaskRunner* task_runner,
                                 Vector<int>* vector,
                                 int* reentrant_count,
                                 int max_reentrant_count) {
  vector->push_back((*reentrant_count)++);
  if (*reentrant_count < max_reentrant_count) {
    task_runner->PostTask(FROM_HERE,
                          base::BindOnce(AppendToVectorReentrantTask,
                                         base::Unretained(task_runner), vector,
                                         reentrant_count, max_reentrant_count));
  }
}

void IdleTestTask(int* run_count,
                  base::TimeTicks* deadline_out,
                  base::TimeTicks deadline) {
  (*run_count)++;
  if (deadline_out) {
    *deadline_out = deadline;
  }
}

int g_max_idle_task_reposts = 2;

void RepostingIdleTestTask(SingleThreadIdleTaskRunner* idle_task_runner,
                           int* run_count,
                           base::TimeTicks* deadline_out,
                           base::TimeTicks deadline) {
  if ((*run_count + 1) < g_max_idle_task_reposts) {
    idle_task_runner->PostIdleTask(
        FROM_HERE, base::BindOnce(&RepostingIdleTestTask,
                                  base::Unretained(idle_task_runner), run_count,
                                  deadline_out));
  }
  *deadline_out = deadline;
  (*run_count)++;
}

void RepostingUpdateClockIdleTestTask(
    SingleThreadIdleTaskRunner* idle_task_runner,
    int* run_count,
    scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner,
    base::TimeDelta advance_time,
    Vector<base::TimeTicks>* deadlines,
    base::TimeTicks deadline) {
  if ((*run_count + 1) < g_max_idle_task_reposts) {
    idle_task_runner->PostIdleTask(
        FROM_HERE, base::BindOnce(&RepostingUpdateClockIdleTestTask,
                                  base::Unretained(idle_task_runner), run_count,
                                  test_task_runner, advance_time, deadlines));
  }
  deadlines->push_back(deadline);
  (*run_count)++;
  test_task_runner->AdvanceMockTickClock(advance_time);
}

void RepeatingTask(base::SingleThreadTaskRunner* task_runner,
                   int num_repeats,
                   base::TimeDelta delay) {
  if (num_repeats > 1) {
    task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&RepeatingTask, base::Unretained(task_runner),
                       num_repeats - 1, delay),
        delay);
  }
}

void UpdateClockIdleTestTask(
    scoped_refptr<base::TestMockTimeTaskRunner> task_runner,
    int* run_count,
    base::TimeTicks set_time,
    base::TimeTicks deadline) {
  task_runner->AdvanceMockTickClock(set_time - task_runner->NowTicks());
  (*run_count)++;
}

void UpdateClockToDeadlineIdleTestTask(
    scoped_refptr<base::TestMockTimeTaskRunner> task_runner,
    int* run_count,
    base::TimeTicks deadline) {
  UpdateClockIdleTestTask(task_runner, run_count, deadline, deadline);
}

void EndIdlePeriodIdleTask(IdleHelper* idle_helper, base::TimeTicks deadline) {
  idle_helper->EndIdlePeriod();
}

void ShutdownIdleTask(IdleHelper* helper,
                      bool* shutdown_task_run,
                      base::TimeTicks deadline) {
  *shutdown_task_run = true;
  helper->Shutdown();
}

class IdleHelperForTest : public IdleHelper, public IdleHelper::Delegate {
 public:
  explicit IdleHelperForTest(
      SchedulerHelper* scheduler_helper,
      base::TimeDelta required_quiescence_duration_before_long_idle_period,
      TaskQueue* idle_task_queue)
      : IdleHelper(scheduler_helper,
                   this,
                   "TestSchedulerIdlePeriod",
                   required_quiescence_duration_before_long_idle_period,
                   idle_task_queue) {}

  ~IdleHelperForTest() override = default;

  // IdleHelper::Delegate implementation:
  MOCK_METHOD2(CanEnterLongIdlePeriod,
               bool(base::TimeTicks now,
                    base::TimeDelta* next_long_idle_period_delay_out));

  MOCK_METHOD0(IsNotQuiescent, void());
  MOCK_METHOD0(OnIdlePeriodStarted, void());
  MOCK_METHOD0(OnIdlePeriodEnded, void());
  MOCK_METHOD1(OnPendingTasksChanged, void(bool has_tasks));
};

class BaseIdleHelperTest : public testing::Test {
 public:
  explicit BaseIdleHelperTest(
      base::TimeDelta required_quiescence_duration_before_long_idle_period)
      : test_task_runner_(base::MakeRefCounted<base::TestMockTimeTaskRunner>(
            base::TestMockTimeTaskRunner::Type::kStandalone)) {
    auto settings = base::sequence_manager::SequenceManager::Settings::Builder()
                        .SetPrioritySettings(CreatePrioritySettings())
                        .Build();
    sequence_manager_ = base::sequence_manager::SequenceManagerForTest::Create(
        nullptr, test_task_runner_, test_task_runner_->GetMockTickClock(),
        std::move(settings));
    scheduler_helper_ = std::make_unique<NonMainThreadSchedulerHelper>(
        sequence_manager_.get(), nullptr, TaskType::kInternalTest);
    scheduler_helper_->AttachToCurrentThread();
    idle_helper_queue_ = scheduler_helper_->NewTaskQueue(
        TaskQueue::Spec(base::sequence_manager::QueueName::IDLE_TQ));
    idle_helper_ = std::make_unique<IdleHelperForTest>(
        scheduler_helper_.get(),
        required_quiescence_duration_before_long_idle_period,
        idle_helper_queue_->GetTaskQueue());
    default_task_queue_ = scheduler_helper_->DefaultNonMainThreadTaskQueue();
    default_task_runner_ =
        default_task_queue_->GetTaskRunnerWithDefaultTaskType();
    idle_task_runner_ = idle_helper_->IdleTaskRunner();
    test_task_runner_->AdvanceMockTickClock(base::Microseconds(5000));
  }

  BaseIdleHelperTest(const BaseIdleHelperTest&) = delete;
  BaseIdleHelperTest& operator=(const BaseIdleHelperTest&) = delete;
  ~BaseIdleHelperTest() override = default;

  void SetUp() override {
    EXPECT_CALL(*idle_helper_, OnIdlePeriodStarted()).Times(AnyNumber());
    EXPECT_CALL(*idle_helper_, OnIdlePeriodEnded()).Times(AnyNumber());
    EXPECT_CALL(*idle_helper_, CanEnterLongIdlePeriod(_, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(_)).Times(AnyNumber());
  }

  void TearDown() override {
    EXPECT_CALL(*idle_helper_, OnIdlePeriodEnded()).Times(AnyNumber());
    idle_helper_->Shutdown();
    idle_helper_queue_->ShutdownTaskQueue();
    test_task_runner_->FastForwardUntilNoTasksRemain();
  }

  SequenceManager* sequence_manager() const { return sequence_manager_.get(); }

  template <typename E>
  static void CallForEachEnumValue(E first,
                                   E last,
                                   const char* (*function)(E)) {
    for (E val = first; val < last;
         val = static_cast<E>(static_cast<int>(val) + 1)) {
      (*function)(val);
    }
  }

  static void CheckAllTaskQueueIdToString() {
    CallForEachEnumValue<IdleHelper::IdlePeriodState>(
        IdleHelper::IdlePeriodState::kFirstIdlePeriodState,
        IdleHelper::IdlePeriodState::kIdlePeriodStateCount,
        &IdleHelper::IdlePeriodStateToString);
  }

  bool IsInIdlePeriod() const {
    return idle_helper_->IsInIdlePeriod(
        idle_helper_->SchedulerIdlePeriodState());
  }

 protected:
  static base::TimeDelta maximum_idle_period_duration() {
    return IdleHelper::kMaximumIdlePeriod;
  }

  static base::TimeDelta retry_enable_long_idle_period_delay() {
    return base::Milliseconds(
        IdleHelper::kRetryEnableLongIdlePeriodDelayMillis);
  }

  static base::TimeDelta minimum_idle_period_duration() {
    return base::Milliseconds(IdleHelper::kMinimumIdlePeriodDurationMillis);
  }

  base::TimeTicks CurrentIdleTaskDeadline() {
    return idle_helper_->CurrentIdleTaskDeadline();
  }

  void CheckIdlePeriodStateIs(const char* expected) {
    EXPECT_STREQ(expected, IdleHelper::IdlePeriodStateToString(
                               idle_helper_->SchedulerIdlePeriodState()));
  }

  const TaskQueue* idle_queue() const { return idle_helper_->idle_queue_; }

  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;
  std::unique_ptr<SequenceManager> sequence_manager_;
  std::unique_ptr<NonMainThreadSchedulerHelper> scheduler_helper_;
  scoped_refptr<NonMainThreadTaskQueue> idle_helper_queue_;
  std::unique_ptr<IdleHelperForTest> idle_helper_;
  scoped_refptr<NonMainThreadTaskQueue> default_task_queue_;
  scoped_refptr<base::SingleThreadTaskRunner> default_task_runner_;
  scoped_refptr<SingleThreadIdleTaskRunner> idle_task_runner_;
};

class IdleHelperTest : public BaseIdleHelperTest {
 public:
  IdleHelperTest() : BaseIdleHelperTest(base::TimeDelta()) {}
  IdleHelperTest(const IdleHelperTest&) = delete;
  IdleHelperTest& operator=(const IdleHelperTest&) = delete;

  ~IdleHelperTest() override = default;
};

TEST_F(IdleHelperTest, TestPostIdleTask) {
  int run_count = 0;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(IdleHelperTest, TestPostIdleTask_EndIdlePeriod) {
  int run_count = 0;
  base::TimeTicks deadline_in_task;

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  idle_helper_->EndIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);
}

TEST_F(IdleHelperTest, TestRepostingIdleTask) {
  base::TimeTicks actual_deadline;
  int run_count = 0;

  g_max_idle_task_reposts = 2;
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&RepostingIdleTestTask,
                                base::RetainedRef(idle_task_runner_),
                                &run_count, &actual_deadline));
  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);

  // Reposted tasks shouldn't run until next idle period.
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(2, run_count);
}

TEST_F(IdleHelperTest, TestIdleTaskExceedsDeadline) {
  int run_count = 0;

  // Post two UpdateClockToDeadlineIdleTestTask tasks.
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&UpdateClockToDeadlineIdleTestTask,
                                test_task_runner_, &run_count));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&UpdateClockToDeadlineIdleTestTask,
                                test_task_runner_, &run_count));

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  test_task_runner_->RunUntilIdle();
  // Only the first idle task should execute since it's used up the deadline.
  EXPECT_EQ(1, run_count);

  idle_helper_->EndIdlePeriod();
  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  test_task_runner_->RunUntilIdle();
  // Second task should be run on the next idle period.
  EXPECT_EQ(2, run_count);
}

class IdleHelperTestWithIdlePeriodObserver : public BaseIdleHelperTest {
 public:
  IdleHelperTestWithIdlePeriodObserver()
      : BaseIdleHelperTest(base::TimeDelta()) {}
  IdleHelperTestWithIdlePeriodObserver(
      const IdleHelperTestWithIdlePeriodObserver&) = delete;
  IdleHelperTestWithIdlePeriodObserver& operator=(
      const IdleHelperTestWithIdlePeriodObserver&) = delete;

  ~IdleHelperTestWithIdlePeriodObserver() override = default;

  void SetUp() override {
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(_)).Times(AnyNumber());
  }

  void ExpectIdlePeriodStartsButNeverEnds() {
    EXPECT_CALL(*idle_helper_, OnIdlePeriodStarted()).Times(1);
    EXPECT_CALL(*idle_helper_, OnIdlePeriodEnded()).Times(0);
  }

  void ExpectIdlePeriodStartsAndEnds(const testing::Cardinality& cardinality) {
    EXPECT_CALL(*idle_helper_, OnIdlePeriodStarted()).Times(cardinality);
    EXPECT_CALL(*idle_helper_, OnIdlePeriodEnded()).Times(cardinality);
  }
};

TEST_F(IdleHelperTestWithIdlePeriodObserver, TestEnterButNotExitIdlePeriod) {
  ExpectIdlePeriodStartsButNeverEnds();

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
}

TEST_F(IdleHelperTestWithIdlePeriodObserver, TestEnterAndExitIdlePeriod) {
  BaseIdleHelperTest* fixture = this;
  ON_CALL(*idle_helper_, OnIdlePeriodStarted())
      .WillByDefault(
          Invoke([fixture]() { EXPECT_TRUE(fixture->IsInIdlePeriod()); }));
  ON_CALL(*idle_helper_, OnIdlePeriodEnded()).WillByDefault(Invoke([fixture]() {
    EXPECT_FALSE(fixture->IsInIdlePeriod());
  }));

  ExpectIdlePeriodStartsAndEnds(Exactly(1));

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  idle_helper_->EndIdlePeriod();
}

TEST_F(IdleHelperTestWithIdlePeriodObserver, TestLongIdlePeriod) {
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + maximum_idle_period_duration();
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  EXPECT_CALL(*idle_helper_, CanEnterLongIdlePeriod(_, _))
      .Times(1)
      .WillRepeatedly(Return(true));
  ExpectIdlePeriodStartsButNeverEnds();

  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);  // Shouldn't run yet as no idle period.

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);  // Should have run in a long idle time.
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(IdleHelperTest, TestLongIdlePeriodWithPendingDelayedTask) {
  base::TimeDelta pending_task_delay = base::Milliseconds(30);
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + pending_task_delay;
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        pending_task_delay);

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);  // Should have run in a long idle time.
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(IdleHelperTest, TestLongIdlePeriodWithLatePendingDelayedTask) {
  base::TimeDelta pending_task_delay = base::Milliseconds(10);
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        pending_task_delay);

  // Advance clock until after delayed task was meant to be run.
  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(20));

  // Post an idle task and then EnableLongIdlePeriod. Since there is a late
  // pending delayed task this shouldn't actually start an idle period.
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  // After the delayed task has been run we should trigger an idle period.
  test_task_runner_->AdvanceMockTickClock(maximum_idle_period_duration());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
}

TEST_F(IdleHelperTestWithIdlePeriodObserver, TestLongIdlePeriodRepeating) {
  Vector<base::TimeTicks> actual_deadlines;
  int run_count = 0;

  EXPECT_CALL(*idle_helper_, CanEnterLongIdlePeriod(_, _))
      .Times(4)
      .WillRepeatedly(Return(true));
  ExpectIdlePeriodStartsAndEnds(AtLeast(2));

  g_max_idle_task_reposts = 3;
  base::TimeTicks clock_before(test_task_runner_->NowTicks());
  base::TimeDelta idle_task_runtime(base::Milliseconds(10));
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingUpdateClockIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count,
                     test_task_runner_, idle_task_runtime, &actual_deadlines));

  // Check each idle task runs in their own idle period.
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(3, run_count);
  EXPECT_THAT(
      actual_deadlines,
      testing::ElementsAre(clock_before + maximum_idle_period_duration(),
                           clock_before + 2 * maximum_idle_period_duration(),
                           clock_before + 3 * maximum_idle_period_duration()));

  g_max_idle_task_reposts = 5;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingUpdateClockIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count,
                     test_task_runner_, idle_task_runtime, &actual_deadlines));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&EndIdlePeriodIdleTask,
                                base::Unretained(idle_helper_.get())));

  // Ensure that reposting tasks stop after EndIdlePeriod is called.
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(4, run_count);
}

TEST_F(IdleHelperTestWithIdlePeriodObserver,
       TestLongIdlePeriodWhenNotCanEnterLongIdlePeriod) {
  base::TimeDelta delay = base::Milliseconds(1000);
  base::TimeDelta half_delay = base::Milliseconds(500);
  base::TimeTicks delay_over = test_task_runner_->NowTicks() + delay;
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  ON_CALL(*idle_helper_, CanEnterLongIdlePeriod(_, _))
      .WillByDefault(
          Invoke([delay, delay_over](
                     base::TimeTicks now,
                     base::TimeDelta* next_long_idle_period_delay_out) {
            if (now >= delay_over)
              return true;
            *next_long_idle_period_delay_out = delay;
            return false;
          }));

  EXPECT_CALL(*idle_helper_, CanEnterLongIdlePeriod(_, _)).Times(2);
  EXPECT_CALL(*idle_helper_, OnIdlePeriodStarted()).Times(AnyNumber());

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  // Make sure Idle tasks don't run until the delay has occurred.
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  test_task_runner_->AdvanceMockTickClock(half_delay);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  // Delay is finished, idle task should run.
  test_task_runner_->AdvanceMockTickClock(half_delay);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
}

TEST_F(IdleHelperTest,
       TestLongIdlePeriodDoesNotImmediatelyRestartIfMaxDeadline) {
  Vector<base::TimeTicks> actual_deadlines;
  int run_count = 0;

  base::TimeTicks clock_before(test_task_runner_->NowTicks());
  base::TimeDelta idle_task_runtime(base::Milliseconds(10));

  // The second idle period should happen immediately after the first the
  // they have max deadlines.
  g_max_idle_task_reposts = 2;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingUpdateClockIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count,
                     test_task_runner_, idle_task_runtime, &actual_deadlines));

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(2, run_count);
  EXPECT_THAT(
      actual_deadlines,
      testing::ElementsAre(clock_before + maximum_idle_period_duration(),
                           clock_before + 2 * maximum_idle_period_duration()));
}

TEST_F(IdleHelperTest, TestLongIdlePeriodRestartWaitsIfNotMaxDeadline) {
  base::TimeTicks actual_deadline;
  int run_count = 0;

  base::TimeDelta pending_task_delay(base::Milliseconds(20));
  base::TimeDelta idle_task_duration(base::Milliseconds(10));
  base::TimeTicks expected_deadline(
      test_task_runner_->NowTicks() + pending_task_delay +
      maximum_idle_period_duration() + retry_enable_long_idle_period_delay());

  // Post delayed task to ensure idle period doesn't have a max deadline.
  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        pending_task_delay);

  g_max_idle_task_reposts = 2;
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&RepostingIdleTestTask,
                                base::RetainedRef(idle_task_runner_),
                                &run_count, &actual_deadline));
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
  test_task_runner_->AdvanceMockTickClock(idle_task_duration);

  // Next idle period shouldn't happen until the pending task has been run.
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);

  // Once the pending task is run the new idle period should start.
  test_task_runner_->AdvanceMockTickClock(pending_task_delay -
                                          idle_task_duration);

  // Since the idle period tried to start before the pending task ran we have to
  // wait for the idle helper to retry starting the long idle period.
  test_task_runner_->AdvanceMockTickClock(
      retry_enable_long_idle_period_delay());
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(2, run_count);
  EXPECT_EQ(expected_deadline, actual_deadline);
}

TEST_F(IdleHelperTest, TestLongIdlePeriodPaused) {
  Vector<base::TimeTicks> actual_deadlines;
  int run_count = 0;

  // If there are no idle tasks posted we should start in the paused state.
  idle_helper_->EnableLongIdlePeriod();
  CheckIdlePeriodStateIs("in_long_idle_period_paused");
  // There shouldn't be any delayed tasks posted by the idle helper when paused.
  base::LazyNow lazy_now_1(test_task_runner_->GetMockTickClock());
  EXPECT_FALSE(scheduler_helper_->GetNextWakeUp());

  // Posting a task should transition us to the an active state.
  g_max_idle_task_reposts = 2;
  base::TimeTicks clock_before(test_task_runner_->NowTicks());
  base::TimeDelta idle_task_runtime(base::Milliseconds(10));
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingUpdateClockIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count,
                     test_task_runner_, idle_task_runtime, &actual_deadlines));
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(2, run_count);
  EXPECT_THAT(
      actual_deadlines,
      testing::ElementsAre(clock_before + maximum_idle_period_duration(),
                           clock_before + 2 * maximum_idle_period_duration()));

  // Once all task have been run we should go back to the paused state.
  CheckIdlePeriodStateIs("in_long_idle_period_paused");
  base::LazyNow lazy_now_2(test_task_runner_->GetMockTickClock());
  EXPECT_FALSE(scheduler_helper_->GetNextWakeUp());

  idle_helper_->EndIdlePeriod();
  CheckIdlePeriodStateIs("not_in_idle_period");
}

TEST_F(IdleHelperTest, TestLongIdlePeriodWhenShutdown) {
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  idle_helper_->Shutdown();

  // We shouldn't be able to enter a long idle period when shutdown
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  CheckIdlePeriodStateIs("not_in_idle_period");
  EXPECT_EQ(0, run_count);
}

void TestCanExceedIdleDeadlineIfRequiredTask(IdleHelperForTest* idle_helper,
                                             bool* can_exceed_idle_deadline_out,
                                             int* run_count,
                                             base::TimeTicks deadline) {
  *can_exceed_idle_deadline_out =
      idle_helper->CanExceedIdleDeadlineIfRequired();
  (*run_count)++;
}

TEST_F(IdleHelperTest, CanExceedIdleDeadlineIfRequired) {
  int run_count = 0;
  bool can_exceed_idle_deadline = false;

  // Should return false if not in an idle period.
  EXPECT_FALSE(idle_helper_->CanExceedIdleDeadlineIfRequired());

  // Should return false for short idle periods.
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&TestCanExceedIdleDeadlineIfRequiredTask,
                                idle_helper_.get(), &can_exceed_idle_deadline,
                                &run_count));
  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
  EXPECT_FALSE(can_exceed_idle_deadline);

  // Should return false for a long idle period which is shortened due to a
  // pending delayed task.
  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        base::Milliseconds(10));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&TestCanExceedIdleDeadlineIfRequiredTask,
                                idle_helper_.get(), &can_exceed_idle_deadline,
                                &run_count));
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(2, run_count);
  EXPECT_FALSE(can_exceed_idle_deadline);

  // Next long idle period will be for the maximum time, so
  // CanExceedIdleDeadlineIfRequired should return true.
  test_task_runner_->AdvanceMockTickClock(maximum_idle_period_duration());
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&TestCanExceedIdleDeadlineIfRequiredTask,
                                idle_helper_.get(), &can_exceed_idle_deadline,
                                &run_count));
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(3, run_count);
  EXPECT_TRUE(can_exceed_idle_deadline);
}

class IdleHelperWithQuiescencePeriodTest : public BaseIdleHelperTest {
 public:
  IdleHelperWithQuiescencePeriodTest(
      const IdleHelperWithQuiescencePeriodTest&) = delete;
  IdleHelperWithQuiescencePeriodTest& operator=(
      const IdleHelperWithQuiescencePeriodTest&) = delete;
  enum {
    kQuiescenceDelayMs = 100,
    kLongIdlePeriodMs = 50,
  };

  IdleHelperWithQuiescencePeriodTest()
      : BaseIdleHelperTest(base::Milliseconds(kQuiescenceDelayMs)) {}

  ~IdleHelperWithQuiescencePeriodTest() override = default;

  void SetUp() override {
    EXPECT_CALL(*idle_helper_, OnIdlePeriodStarted()).Times(AnyNumber());
    EXPECT_CALL(*idle_helper_, OnIdlePeriodEnded()).Times(AnyNumber());
    EXPECT_CALL(*idle_helper_, CanEnterLongIdlePeriod(_, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*idle_helper_, IsNotQuiescent()).Times(AnyNumber());
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(_)).Times(AnyNumber());
  }

  void MakeNonQuiescent() {
    // Run an arbitrary task so we're deemed to be not quiescent.
    default_task_runner_->PostTask(FROM_HERE, base::BindOnce(NullTask));
    test_task_runner_->RunUntilIdle();
  }

 private:
};

class IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver
    : public IdleHelperWithQuiescencePeriodTest {
 public:
  IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver()
      : IdleHelperWithQuiescencePeriodTest() {}

  IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver(
      const IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver&) = delete;
  IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver& operator=(
      const IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver&) = delete;

  ~IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver() override =
      default;

  void SetUp() override {
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(_)).Times(AnyNumber());
  }
};

TEST_F(IdleHelperWithQuiescencePeriodTest,
       LongIdlePeriodStartsImmediatelyIfQuiescent) {
  base::TimeTicks actual_deadline;
  int run_count = 0;
  g_max_idle_task_reposts = 1;
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&RepostingIdleTestTask,
                                base::RetainedRef(idle_task_runner_),
                                &run_count, &actual_deadline));

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(1, run_count);
}

TEST_F(IdleHelperWithQuiescencePeriodTestWithIdlePeriodObserver,
       LongIdlePeriodDoesNotStartsImmediatelyIfBusy) {
  MakeNonQuiescent();
  EXPECT_CALL(*idle_helper_, OnIdlePeriodStarted()).Times(0);
  EXPECT_CALL(*idle_helper_, OnIdlePeriodEnded()).Times(0);
  EXPECT_CALL(*idle_helper_, CanEnterLongIdlePeriod(_, _)).Times(0);
  EXPECT_CALL(*idle_helper_, IsNotQuiescent()).Times(AtLeast(1));

  base::TimeTicks actual_deadline;
  int run_count = 0;
  g_max_idle_task_reposts = 1;
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&RepostingIdleTestTask,
                                base::RetainedRef(idle_task_runner_),
                                &run_count, &actual_deadline));

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(0, run_count);
}

TEST_F(IdleHelperWithQuiescencePeriodTest,
       LongIdlePeriodStartsAfterQuiescence) {
  MakeNonQuiescent();

  // Run a repeating task so we're deemed to be busy for the next 400ms.
  default_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&RepeatingTask,
                                base::Unretained(default_task_runner_.get()),
                                10, base::Milliseconds(40)));

  int run_count = 0;
  // In this scenario EnableLongIdlePeriod deems us not to be quiescent 5x in
  // a row.
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() +
      base::Milliseconds(5 * kQuiescenceDelayMs + kLongIdlePeriodMs);
  base::TimeTicks deadline_in_task;
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(IdleHelperWithQuiescencePeriodTest,
       QuescienceCheckedForAfterLongIdlePeriodEnds) {
  idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce(&NullIdleTask));
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();

  // Post a normal task to make the scheduler non-quiescent.
  default_task_runner_->PostTask(FROM_HERE, base::BindOnce(&NullTask));
  test_task_runner_->RunUntilIdle();

  // Post an idle task. The idle task won't run initially because the system is
  // not judged to be quiescent, but should be run after the quiescence delay.
  int run_count = 0;
  base::TimeTicks deadline_in_task;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() +
      base::Milliseconds(kQuiescenceDelayMs + kLongIdlePeriodMs);
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(IdleHelperTest, NoShortIdlePeriodWhenDeadlineTooClose) {
  int run_count = 0;
  base::TimeTicks deadline_in_task;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  base::TimeDelta half_a_ms(base::Microseconds(50));
  base::TimeTicks less_than_min_deadline(test_task_runner_->NowTicks() +
                                         minimum_idle_period_duration() -
                                         half_a_ms);
  base::TimeTicks more_than_min_deadline(test_task_runner_->NowTicks() +
                                         minimum_idle_period_duration() +
                                         half_a_ms);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                less_than_min_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                more_than_min_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
}

TEST_F(IdleHelperTest, NoLongIdlePeriodWhenDeadlineTooClose) {
  int run_count = 0;
  base::TimeTicks deadline_in_task;

  base::TimeDelta half_a_ms(base::Microseconds(50));
  base::TimeDelta less_than_min_deadline_duration(
      minimum_idle_period_duration() - half_a_ms);
  base::TimeDelta more_than_min_deadline_duration(
      minimum_idle_period_duration() + half_a_ms);

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        less_than_min_deadline_duration);

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->EndIdlePeriod();
  test_task_runner_->AdvanceMockTickClock(maximum_idle_period_duration());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        more_than_min_deadline_duration);
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
}

TEST_F(IdleHelperWithQuiescencePeriodTest,
       PendingEnableLongIdlePeriodNotRunAfterShutdown) {
  MakeNonQuiescent();

  bool shutdown_task_run = false;
  int run_count = 0;
  base::TimeTicks deadline_in_task;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&ShutdownIdleTask, base::Unretained(idle_helper_.get()),
                     &shutdown_task_run));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  // Delayed call to IdleHelper::EnableLongIdlePeriod enables idle tasks.
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->AdvanceMockTickClock(maximum_idle_period_duration() * 2.0);
  test_task_runner_->RunUntilIdle();
  EXPECT_TRUE(shutdown_task_run);
  EXPECT_EQ(0, run_count);

  // Shutdown immediately after idle period started should prevent the idle
  // task from running.
  idle_helper_->Shutdown();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);
}

TEST_F(IdleHelperTest, TestPostDelayedIdleTask) {
  int run_count = 0;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  // Posting a delayed idle task should not post anything on the underlying
  // task queue until the delay is up.
  idle_task_runner_->PostDelayedIdleTask(
      FROM_HERE, base::Milliseconds(200),
      base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  EXPECT_EQ(0u, idle_queue()->GetNumberOfPendingTasks());

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));

  // It shouldn't run until the delay is over even though we went idle.
  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  EXPECT_EQ(0u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  EXPECT_EQ(1u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

// Tests that the OnPendingTasksChanged callback is called once when the idle
// queue becomes non-empty and again when it becomes empty.
TEST_F(IdleHelperTest, OnPendingTasksChanged) {
  int run_count = 0;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  {
    testing::InSequence dummy;
    // This will be called once. I.e when the one and only task is posted.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(true)).Times(1);
    // This will be called once. I.e when the one and only task completes.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(false)).Times(1);
  }

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

// Tests that the OnPendingTasksChanged callback is still only called once
// with false despite there being two idle tasks posted.
TEST_F(IdleHelperTest, OnPendingTasksChanged_TwoTasksAtTheSameTime) {
  int run_count = 0;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  {
    testing::InSequence dummy;
    // This will be called 3 times. I.e when T1 and T2 are posted and when T1
    // completes.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(true)).Times(3);
    // This will be called once. I.e when T2 completes.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(false)).Times(1);
  }

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(2, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

class MultiThreadedIdleHelperTest : public IdleHelperTest {
 public:
  void PostIdleTaskFromNewThread(int* run_count) {
    PostDelayedIdleTaskFromNewThread(base::TimeDelta(), run_count);
  }

  void PostDelayedIdleTaskFromNewThread(base::TimeDelta delay, int* run_count) {
    std::unique_ptr<NonMainThread> thread = NonMainThread::CreateThread(
        ThreadCreationParams(ThreadType::kTestThread)
            .SetThreadNameForTest("TestBackgroundThread"));
    PostCrossThreadTask(
        *thread->GetTaskRunner(), FROM_HERE,
        CrossThreadBindOnce(&PostIdleTaskFromBackgroundThread,
                            idle_task_runner_, delay,
                            WTF::CrossThreadUnretained(run_count)));
    thread.reset();
  }

 protected:
  static void PostIdleTaskFromBackgroundThread(
      scoped_refptr<SingleThreadIdleTaskRunner> idle_task_runner,
      base::TimeDelta delay,
      int* run_count) {
    auto callback = ConvertToBaseOnceCallback(CrossThreadBindOnce(
        &IdleTestTask, WTF::CrossThreadUnretained(run_count), nullptr));
    if (delay.is_zero()) {
      idle_task_runner->PostIdleTask(FROM_HERE, std::move(callback));
    } else {
      idle_task_runner->PostDelayedIdleTask(FROM_HERE, delay,
                                            std::move(callback));
    }
  }
};

TEST_F(MultiThreadedIdleHelperTest, IdleTasksFromNonMainThreads) {
  int run_count = 0;

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));

  PostIdleTaskFromNewThread(&run_count);
  PostIdleTaskFromNewThread(&run_count);
  PostIdleTaskFromNewThread(&run_count);

  EXPECT_EQ(3u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(3, run_count);
}

TEST_F(MultiThreadedIdleHelperTest, DelayedIdleTasksFromNonMainThreads) {
  int run_count = 0;

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));

  PostDelayedIdleTaskFromNewThread(base::Milliseconds(200), &run_count);
  PostDelayedIdleTaskFromNewThread(base::Milliseconds(250), &run_count);
  PostDelayedIdleTaskFromNewThread(base::Milliseconds(300), &run_count);

  // Delayed idle tasks are not queued until a new idle period starts.
  EXPECT_EQ(0u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(300));
  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  EXPECT_EQ(3u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(3, run_count);
}

TEST_F(MultiThreadedIdleHelperTest,
       DelayedAndNonDelayedIdleTasksFromMultipleThreads) {
  int run_count = 0;

  PostIdleTaskFromNewThread(&run_count);

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, nullptr));

  PostDelayedIdleTaskFromNewThread(base::Milliseconds(200), &run_count);

  idle_task_runner_->PostDelayedIdleTask(
      FROM_HERE, base::Milliseconds(250),
      base::BindOnce(&IdleTestTask, &run_count, nullptr));

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(250));

  EXPECT_EQ(2u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  EXPECT_EQ(4u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(4, run_count);
}

}  // namespace idle_helper_unittest
}  // namespace scheduler
}  // namespace blink
```