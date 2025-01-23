Response:
Let's break down the thought process to analyze the provided C++ code for `prioritized_dispatcher_unittest.cc`.

1. **Understand the Core Purpose:** The filename immediately suggests this is a unit test file. The `_unittest.cc` suffix is a strong convention in many C++ projects, including Chromium. The name `PrioritizedDispatcher` gives the main subject being tested. So, the primary function is to test the behavior of a class called `PrioritizedDispatcher`.

2. **Examine Includes:** The `#include` directives reveal the dependencies and context:
    * `"net/base/prioritized_dispatcher.h"`: This is the header file for the class being tested. We know the test file interacts directly with this class.
    * `<memory>`, `<string>`: Standard C++ library headers for memory management and string manipulation, likely used within the test setup and assertions.
    * `"base/check.h"`: A Chromium base library for assertions and preconditions (like `CHECK`).
    * `"base/compiler_specific.h"`:  Deals with compiler-specific attributes, probably not crucial for understanding the core logic.
    * `"base/memory/raw_ptr.h"`: A Chromium construct for raw pointers with specific ownership semantics, important to note when dealing with object lifetimes.
    * `"base/test/gtest_util.h"`: Provides Chromium-specific extensions for Google Test.
    * `"net/base/request_priority.h"`: Defines the priority levels used by the dispatcher.
    * `"testing/gtest/include/gtest/gtest.h"`: The core Google Test framework.

3. **Identify the Test Fixture:** The `PrioritizedDispatcherTest` class inheriting from `testing::Test` is the standard setup for Google Test. This class holds the test cases and helper methods.

4. **Analyze Helper Classes/Types:**
    * `Priority`: A type alias for `PrioritizedDispatcher::Priority`, indicating the dispatcher works with request priorities.
    * `TestJob`:  A crucial inner class that simulates a "job" being managed by the `PrioritizedDispatcher`. Key aspects of `TestJob`:
        * It inherits from `PrioritizedDispatcher::Job`.
        * It has a `tag_` (a char) to identify the job.
        * It has a `priority_`.
        * It manipulates a `log_` string to record execution order.
        * It uses `PrioritizedDispatcher::Handle` to interact with the dispatcher.
        * It has methods like `Add`, `ChangePriority`, `Cancel`, `Finish`, and `Start` which directly call corresponding methods on the `PrioritizedDispatcher`. This is the core interaction point.

5. **Understand Test Cases (Individual `TEST_F` functions):** Each `TEST_F` function focuses on testing a specific aspect of the `PrioritizedDispatcher`:
    * `GetLimits`: Tests retrieving and setting limits on the dispatcher (e.g., total number of jobs, reserved slots for priorities).
    * `AddAFIFO`: Tests basic FIFO (First-In, First-Out) behavior for jobs with the same priority.
    * `AddPriority`: Tests that higher priority jobs run before lower priority jobs.
    * `AddAtHead`: Tests adding jobs to the front of the queue for a given priority.
    * `EnforceLimits`: Tests that the dispatcher respects the configured limits on concurrent jobs and reserved slots for priorities.
    * `ChangePriority`: Tests dynamically changing the priority of a queued job.
    * `Cancel`: Tests removing a queued job.
    * `Evict`: Tests explicitly removing the oldest lowest-priority job.
    * `EvictFromEmpty`: Tests the behavior of `EvictOldestLowest` when the queue is empty.
    * `AddWhileZeroLimits`: Tests adding jobs when the dispatcher's limits are set to zero and then restoring the limits.
    * `ReduceLimitsWhileJobQueued`: Tests reducing the limits while jobs are queued and running.
    * `ZeroLimitsThenCancel`: Tests cancelling a job when the limits are zero.
    * `ZeroLimitsThenIncreasePriority`: Tests increasing a job's priority to HIGHEST when limits are zero.
    * `CancelNull`, `CancelMissing`:  *(With `GTEST_HAS_DEATH_TEST`)* Test that the `Cancel` method behaves correctly (and potentially crashes with a `DCHECK`) when given invalid handles.

6. **Identify Key Methods and Behaviors Being Tested:**  The tests cover the following core functionalities of the `PrioritizedDispatcher`:
    * Adding jobs (both at the end and the head of the queue).
    * Managing job priorities.
    * Enforcing concurrency limits.
    * Dynamically changing job priorities.
    * Cancelling jobs.
    * Evicting jobs.
    * Handling scenarios with zero limits.

7. **Look for Potential Links to JavaScript (if any):**  At this level of C++ code, there's no *direct* connection to JavaScript. However, consider these points:
    * **Network Requests:**  The `net` namespace strongly suggests this dispatcher is involved in managing network requests. In a browser, JavaScript often initiates network requests. Therefore, this `PrioritizedDispatcher` *could* be a component deep within the browser's network stack that handles the scheduling of those requests. The priorities might map to how the browser prioritizes different types of network requests (e.g., user-initiated vs. background updates).
    * **Task Scheduling:** The concept of a "dispatcher" is common in asynchronous programming. While this is C++, the underlying principle of managing and executing tasks with priorities is relevant to JavaScript's event loop and task queues.

8. **Consider Error Scenarios:** The tests themselves highlight potential errors:
    * Trying to cancel a null or invalid handle (tested with `DCHECK_DEATH`).
    * Incorrect limit configurations leading to unexpected job execution order.

9. **Think About User Interaction and Debugging:** How might a user action lead to this code being executed?
    * A user clicking a link or submitting a form could trigger network requests that are then managed by the `PrioritizedDispatcher`.
    * A web page might initiate background requests (e.g., for prefetching or analytics) with different priorities.
    * Browser extensions might also initiate network requests.

    For debugging, setting breakpoints in the `Add`, `Start`, `Finish`, `Cancel`, or `ChangePriority` methods of `PrioritizedDispatcher` and `TestJob` would be useful to trace the flow of jobs and understand why they are being executed in a particular order or why limits are being enforced in a certain way.

By following these steps, you can systematically analyze the C++ code and understand its purpose, functionality, and potential connections to other parts of a system (like the browser's interaction with JavaScript).
这个C++源代码文件 `prioritized_dispatcher_unittest.cc` 是 Chromium 网络栈中 `net/base/prioritized_dispatcher.h` 头的**单元测试文件**。它的主要功能是 **验证 `PrioritizedDispatcher` 类的正确性和各种边界情况**。

以下是该文件的详细功能分解：

**1. 验证 `PrioritizedDispatcher` 的核心功能：**

* **添加任务 (Add/AddAtHead):** 测试以不同的优先级添加任务到调度器，并验证任务是否按照优先级顺序执行。`AddAtHead` 特别测试了将任务添加到队列头部的情况。
* **执行任务 (Start/Finish):**  通过模拟任务的启动和完成，测试调度器是否正确地启动任务，并在任务完成后释放资源，允许其他任务执行。
* **优先级管理 (ChangePriority):**  测试动态改变队列中任务的优先级，验证调度器是否能够根据新的优先级重新安排任务的执行顺序。
* **取消任务 (Cancel):** 测试从调度器中移除已排队但尚未执行的任务。
* **限制 (Limits):**
    * **设置和获取限制 (GetLimits):** 测试设置调度器允许的最大并发任务数量，以及为不同优先级预留的槽位数量。
    * **强制限制 (EnforceLimits):**  验证调度器是否严格遵守设置的限制，例如，高优先级的任务是否能够抢占低优先级的任务的执行机会，以及预留槽位是否按预期工作。
    * **零限制 (SetLimitsToZero):** 测试在调度器限制设置为零的情况下添加任务的行为，以及之后恢复限制时的行为。
* **驱逐任务 (EvictOldestLowest):** 测试显式移除队列中最老的、优先级最低的任务的功能。

**2. 使用 `TestJob` 模拟任务：**

* 文件中定义了一个名为 `TestJob` 的内部类，它继承自 `PrioritizedDispatcher::Job`。
* `TestJob` 的主要作用是模拟需要被调度器执行的“任务”。
* 它包含一个字符 `tag_` 用于标识任务，一个 `priority_` 表示任务的优先级，以及一个指向 `std::string log_` 的指针，用于记录任务的执行顺序。
* `TestJob` 的 `Start()` 方法会在 `log_` 中追加它的 `tag_`，`Finish()` 方法会在 `log_` 中追加 `.`。 这使得测试能够清晰地追踪任务的执行顺序。

**3. 使用 Google Test 框架进行测试：**

* 文件使用了 Google Test 框架来组织和执行测试用例。
* 每个以 `TEST_F` 开头的函数都是一个独立的测试用例，用于验证 `PrioritizedDispatcher` 的特定功能。
* `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE` 等断言宏用于判断测试结果是否符合预期。

**与 JavaScript 功能的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但其背后的 `PrioritizedDispatcher` 类在 Chromium 浏览器中可能被用于管理与网络请求相关的任务。JavaScript 代码可以通过浏览器提供的 API (例如 `fetch`, `XMLHttpRequest`) 发起网络请求。  `PrioritizedDispatcher` 可能在幕后负责调度这些请求，根据它们的优先级（例如用户发起的请求可能比预加载请求优先级更高）来决定哪个请求应该先被处理。

**举例说明：**

假设一个网页同时发起以下网络请求：

1. **用户点击一个链接 (高优先级):**  这个请求需要尽快完成，以提升用户体验。
2. **一个用于收集分析数据的后台请求 (低优先级):**  这个请求可以稍后执行，不会立即影响用户体验。
3. **一个用于预加载下一个页面的请求 (中等优先级):**  这个请求可以在用户交互不繁忙的时候执行。

在 Chromium 的内部，当 JavaScript 发起这些请求时，它们可能会被添加到 `PrioritizedDispatcher` 中，并带有相应的优先级信息。调度器会根据优先级顺序来处理这些请求。用户点击链接的请求会因为优先级最高而被优先处理，然后是预加载请求，最后是分析数据请求。

**逻辑推理 - 假设输入与输出：**

考虑 `TEST_F(PrioritizedDispatcherTest, AddPriority)` 测试用例：

* **假设输入:**
    * 调度器限制为一次只能运行一个任务。
    * 按顺序添加了以下任务，优先级分别为：
        * 'a' (IDLE)
        * 'b' (MEDIUM)
        * 'c' (HIGHEST)
        * 'd' (HIGHEST)
        * 'e' (MEDIUM)
* **预期输出:**  日志字符串 "a.c.d.b.e."

**推理过程:**

1. 任务 'a' 首先被添加，并且由于调度器空闲，它立即开始执行，`log_` 变为 "a"。完成后追加 "."，变为 "a."。
2. 任务 'b' 被添加，但由于调度器正忙，它进入队列。
3. 任务 'c' 被添加，由于优先级高于 'b'，它会被放在 'b' 的前面。
4. 任务 'd' 被添加，优先级与 'c' 相同，通常会按照添加顺序排在 'c' 之后。
5. 任务 'a' 完成，调度器开始执行队列中的下一个任务，由于 'c' 的优先级最高，所以 'c' 开始执行，`log_` 变为 "a.c"。完成后追加 "."，变为 "a.c."。
6. 任务 'c' 完成，调度器执行下一个最高优先级的任务，即 'd'，`log_` 变为 "a.c.d"。完成后追加 "."，变为 "a.c.d."。
7. 任务 'd' 完成，调度器执行 'b'，`log_` 变为 "a.c.d.b"。完成后追加 "."，变为 "a.c.d.b."。
8. 任务 'b' 完成，调度器执行 'e'，`log_` 变为 "a.c.d.b.e"。完成后追加 "."，变为 "a.c.d.b.e."。

**用户或编程常见的使用错误：**

* **忘记调用 `Finish()`:** 如果一个 `TestJob` 的 `Start()` 被调用，但 `Finish()` 没有被调用，调度器会认为该任务还在运行，可能会阻止其他任务的执行。这在实际编程中对应于网络请求完成后没有正确释放资源或通知调度器。
* **错误的优先级设置:** 为不重要的任务设置过高的优先级可能会导致重要的任务被延迟执行，影响用户体验。
* **超出限制添加任务:** 虽然调度器会管理这种情况，但如果程序不加控制地添加大量高优先级任务，可能会导致系统资源耗尽。
* **在任务未添加到调度器时尝试操作 (例如 `Cancel`, `ChangePriority`):**  `TestJob` 的 `Add()` 方法会返回一个 `Handle`，后续的操作需要基于这个有效的 `Handle`。如果直接操作未添加的任务，会导致程序错误。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中执行某个操作，触发了一个网络请求。** 例如，点击一个链接、提交一个表单、加载一个图片等。
2. **浏览器的渲染进程或网络进程会创建一个表示该网络请求的对象。** 这个对象会包含请求的 URL、方法、头部信息等。
3. **该网络请求会被提交到 Chromium 的网络栈进行处理。**
4. **网络栈中的某个组件 (可能是一个更高层次的请求队列或管理器) 决定该请求的优先级。**  例如，用户发起的导航请求通常具有较高的优先级。
5. **该网络请求 (或者一个与之关联的任务对象) 会被添加到 `PrioritizedDispatcher` 中。** `PrioritizedDispatcher` 负责根据优先级和当前资源限制来调度该请求的执行。
6. **当调度器认为该请求可以执行时 (例如，有可用的槽位且优先级足够高)，会调用与该请求关联的任务的 `Start()` 方法。**
7. **该任务执行实际的网络操作 (例如，建立连接、发送请求、接收数据)。**
8. **网络操作完成后，任务会调用其自身的 `Finish()` 方法，通知 `PrioritizedDispatcher` 该任务已完成。**

在调试网络请求调度相关问题时，开发者可能会在 `PrioritizedDispatcher` 的 `Add()`, `Start()`, `Finish()`, `ChangePriority()` 等方法中设置断点，以观察请求的添加、执行顺序和优先级变化，从而理解为什么某些请求被延迟或以特定的顺序执行。

总而言之，`prioritized_dispatcher_unittest.cc` 是一个至关重要的测试文件，它确保了 Chromium 网络栈中任务调度核心组件的正确性和健壮性，这直接影响着用户浏览网页时的体验和效率。

### 提示词
```
这是目录为net/base/prioritized_dispatcher_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/prioritized_dispatcher.h"

#include <memory>
#include <string>

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/memory/raw_ptr.h"
#include "base/test/gtest_util.h"
#include "net/base/request_priority.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// We rely on the priority enum values being sequential having starting at 0,
// and increasing for higher priorities.
static_assert(MINIMUM_PRIORITY == 0u && MINIMUM_PRIORITY == THROTTLED &&
                  THROTTLED < IDLE &&
                  IDLE < LOWEST &&
                  LOWEST < HIGHEST &&
                  HIGHEST <= MAXIMUM_PRIORITY,
              "priority indexes incompatible");

class PrioritizedDispatcherTest : public testing::Test {
 public:
  typedef PrioritizedDispatcher::Priority Priority;
  // A job that appends |tag| to |log| when started and '.' when finished.
  // This is intended to confirm the execution order of a sequence of jobs added
  // to the dispatcher. Note that finishing order of jobs does not matter.
  class TestJob : public PrioritizedDispatcher::Job {
   public:
    TestJob(PrioritizedDispatcher* dispatcher,
            char tag,
            Priority priority,
            std::string* log)
        : dispatcher_(dispatcher), tag_(tag), priority_(priority), log_(log) {}

    bool running() const {
      return running_;
    }

    const PrioritizedDispatcher::Handle handle() const {
      return handle_;
    }

    void Add(bool at_head) {
      CHECK(handle_.is_null());
      CHECK(!running_);
      size_t num_queued = dispatcher_->num_queued_jobs();
      size_t num_running = dispatcher_->num_running_jobs();

      if (!at_head) {
        handle_ = dispatcher_->Add(this, priority_);
      } else {
        handle_ = dispatcher_->AddAtHead(this, priority_);
      }

      if (handle_.is_null()) {
        EXPECT_EQ(num_queued, dispatcher_->num_queued_jobs());
        EXPECT_TRUE(running_);
        EXPECT_EQ(num_running + 1, dispatcher_->num_running_jobs());
      } else {
        EXPECT_FALSE(running_);
        EXPECT_EQ(priority_, handle_.priority());
        EXPECT_EQ(tag_, reinterpret_cast<TestJob*>(handle_.value())->tag_);
        EXPECT_EQ(num_running, dispatcher_->num_running_jobs());
      }
    }

    void ChangePriority(Priority priority) {
      CHECK(!handle_.is_null());
      CHECK(!running_);
      size_t num_queued = dispatcher_->num_queued_jobs();
      size_t num_running = dispatcher_->num_running_jobs();

      handle_ = dispatcher_->ChangePriority(handle_, priority);

      if (handle_.is_null()) {
        EXPECT_TRUE(running_);
        EXPECT_EQ(num_queued - 1, dispatcher_->num_queued_jobs());
        EXPECT_EQ(num_running + 1, dispatcher_->num_running_jobs());
      } else {
        EXPECT_FALSE(running_);
        EXPECT_EQ(priority, handle_.priority());
        EXPECT_EQ(tag_, reinterpret_cast<TestJob*>(handle_.value())->tag_);
        EXPECT_EQ(num_queued, dispatcher_->num_queued_jobs());
        EXPECT_EQ(num_running, dispatcher_->num_running_jobs());
      }
    }

    void Cancel() {
      CHECK(!handle_.is_null());
      CHECK(!running_);
      size_t num_queued = dispatcher_->num_queued_jobs();

      dispatcher_->Cancel(handle_);

      EXPECT_EQ(num_queued - 1, dispatcher_->num_queued_jobs());
      handle_ = PrioritizedDispatcher::Handle();
    }

    void Finish() {
      CHECK(running_);
      running_ = false;
      log_->append(1u, '.');

      dispatcher_->OnJobFinished();
    }

    // PrioritizedDispatcher::Job interface
    void Start() override {
      EXPECT_FALSE(running_);
      handle_ = PrioritizedDispatcher::Handle();
      running_ = true;
      log_->append(1u, tag_);
    }

   private:
    raw_ptr<PrioritizedDispatcher> dispatcher_;

    char tag_;
    Priority priority_;

    PrioritizedDispatcher::Handle handle_;
    bool running_ = false;

    raw_ptr<std::string> log_;
  };

 protected:
  void Prepare(const PrioritizedDispatcher::Limits& limits) {
    dispatcher_ = std::make_unique<PrioritizedDispatcher>(limits);
  }

  std::unique_ptr<TestJob> AddJob(char data, Priority priority) {
    auto job =
        std::make_unique<TestJob>(dispatcher_.get(), data, priority, &log_);
    job->Add(false);
    return job;
  }

  std::unique_ptr<TestJob> AddJobAtHead(char data, Priority priority) {
    auto job =
        std::make_unique<TestJob>(dispatcher_.get(), data, priority, &log_);
    job->Add(true);
    return job;
  }

  void Expect(const std::string& log) {
    EXPECT_EQ(0u, dispatcher_->num_queued_jobs());
    EXPECT_EQ(0u, dispatcher_->num_running_jobs());
    EXPECT_EQ(log, log_);
    log_.clear();
  }

  std::string log_;
  std::unique_ptr<PrioritizedDispatcher> dispatcher_;
};

TEST_F(PrioritizedDispatcherTest, GetLimits) {
  // Set non-trivial initial limits.
  PrioritizedDispatcher::Limits original_limits(NUM_PRIORITIES, 5);
  original_limits.reserved_slots[HIGHEST] = 1;
  original_limits.reserved_slots[LOW] = 2;
  Prepare(original_limits);

  // Get current limits, make sure the original limits are returned.
  PrioritizedDispatcher::Limits retrieved_limits = dispatcher_->GetLimits();
  ASSERT_EQ(original_limits.total_jobs, retrieved_limits.total_jobs);
  ASSERT_EQ(static_cast<size_t>(NUM_PRIORITIES),
            retrieved_limits.reserved_slots.size());
  for (size_t priority = MINIMUM_PRIORITY; priority <= MAXIMUM_PRIORITY;
       ++priority) {
    EXPECT_EQ(original_limits.reserved_slots[priority],
              retrieved_limits.reserved_slots[priority]);
  }

  // Set new limits.
  PrioritizedDispatcher::Limits new_limits(NUM_PRIORITIES, 6);
  new_limits.reserved_slots[MEDIUM] = 3;
  new_limits.reserved_slots[LOWEST] = 1;
  Prepare(new_limits);

  // Get current limits, make sure the new limits are returned.
  retrieved_limits = dispatcher_->GetLimits();
  ASSERT_EQ(new_limits.total_jobs, retrieved_limits.total_jobs);
  ASSERT_EQ(static_cast<size_t>(NUM_PRIORITIES),
            retrieved_limits.reserved_slots.size());
  for (size_t priority = MINIMUM_PRIORITY; priority <= MAXIMUM_PRIORITY;
       ++priority) {
    EXPECT_EQ(new_limits.reserved_slots[priority],
              retrieved_limits.reserved_slots[priority]);
  }
}

TEST_F(PrioritizedDispatcherTest, AddAFIFO) {
  // Allow only one running job.
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', IDLE);
  std::unique_ptr<TestJob> job_c = AddJob('c', IDLE);
  std::unique_ptr<TestJob> job_d = AddJob('d', IDLE);

  ASSERT_TRUE(job_a->running());
  job_a->Finish();
  ASSERT_TRUE(job_b->running());
  job_b->Finish();
  ASSERT_TRUE(job_c->running());
  job_c->Finish();
  ASSERT_TRUE(job_d->running());
  job_d->Finish();

  Expect("a.b.c.d.");
}

TEST_F(PrioritizedDispatcherTest, AddPriority) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', MEDIUM);
  std::unique_ptr<TestJob> job_c = AddJob('c', HIGHEST);
  std::unique_ptr<TestJob> job_d = AddJob('d', HIGHEST);
  std::unique_ptr<TestJob> job_e = AddJob('e', MEDIUM);

  ASSERT_TRUE(job_a->running());
  job_a->Finish();
  ASSERT_TRUE(job_c->running());
  job_c->Finish();
  ASSERT_TRUE(job_d->running());
  job_d->Finish();
  ASSERT_TRUE(job_b->running());
  job_b->Finish();
  ASSERT_TRUE(job_e->running());
  job_e->Finish();

  Expect("a.c.d.b.e.");
}

TEST_F(PrioritizedDispatcherTest, AddAtHead) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', MEDIUM);
  std::unique_ptr<TestJob> job_b = AddJobAtHead('b', MEDIUM);
  std::unique_ptr<TestJob> job_c = AddJobAtHead('c', HIGHEST);
  std::unique_ptr<TestJob> job_d = AddJobAtHead('d', HIGHEST);
  std::unique_ptr<TestJob> job_e = AddJobAtHead('e', MEDIUM);
  std::unique_ptr<TestJob> job_f = AddJob('f', MEDIUM);

  ASSERT_TRUE(job_a->running());
  job_a->Finish();
  ASSERT_TRUE(job_d->running());
  job_d->Finish();
  ASSERT_TRUE(job_c->running());
  job_c->Finish();
  ASSERT_TRUE(job_e->running());
  job_e->Finish();
  ASSERT_TRUE(job_b->running());
  job_b->Finish();
  ASSERT_TRUE(job_f->running());
  job_f->Finish();

  Expect("a.d.c.e.b.f.");
}

TEST_F(PrioritizedDispatcherTest, EnforceLimits) {
  // Reserve 2 for HIGHEST and 1 for LOW or higher.
  // This leaves 2 for LOWEST or lower.
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 5);
  limits.reserved_slots[HIGHEST] = 2;
  limits.reserved_slots[LOW] = 1;
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);  // Uses unreserved slot.
  std::unique_ptr<TestJob> job_b = AddJob('b', IDLE);  // Uses unreserved slot.
  std::unique_ptr<TestJob> job_c = AddJob('c', LOWEST);   // Must wait.
  std::unique_ptr<TestJob> job_d = AddJob('d', LOW);      // Uses reserved slot.
  std::unique_ptr<TestJob> job_e = AddJob('e', MEDIUM);   // Must wait.
  std::unique_ptr<TestJob> job_f = AddJob('f', HIGHEST);  // Uses reserved slot.
  std::unique_ptr<TestJob> job_g = AddJob('g', HIGHEST);  // Uses reserved slot.
  std::unique_ptr<TestJob> job_h = AddJob('h', HIGHEST);  // Must wait.

  EXPECT_EQ(5u, dispatcher_->num_running_jobs());
  EXPECT_EQ(3u, dispatcher_->num_queued_jobs());

  ASSERT_TRUE(job_a->running());
  ASSERT_TRUE(job_b->running());
  ASSERT_TRUE(job_d->running());
  ASSERT_TRUE(job_f->running());
  ASSERT_TRUE(job_g->running());
  // a, b, d, f, g are running. Finish them in any order.
  job_b->Finish();  // Releases h.
  job_f->Finish();
  job_a->Finish();
  job_g->Finish();  // Releases e.
  job_d->Finish();
  ASSERT_TRUE(job_e->running());
  ASSERT_TRUE(job_h->running());
  // h, e are running.
  job_e->Finish();  // Releases c.
  ASSERT_TRUE(job_c->running());
  job_c->Finish();
  job_h->Finish();

  Expect("abdfg.h...e..c..");
}

TEST_F(PrioritizedDispatcherTest, ChangePriority) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 2);
  // Reserve one slot only for HIGHEST priority requests.
  limits.reserved_slots[HIGHEST] = 1;
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', LOW);
  std::unique_ptr<TestJob> job_c = AddJob('c', MEDIUM);
  std::unique_ptr<TestJob> job_d = AddJob('d', MEDIUM);
  std::unique_ptr<TestJob> job_e = AddJob('e', IDLE);

  ASSERT_FALSE(job_b->running());
  ASSERT_FALSE(job_c->running());
  job_b->ChangePriority(MEDIUM);
  job_c->ChangePriority(LOW);

  ASSERT_TRUE(job_a->running());
  job_a->Finish();
  ASSERT_TRUE(job_d->running());
  job_d->Finish();

  EXPECT_FALSE(job_e->running());
  // Increasing |job_e|'s priority to HIGHEST should result in it being
  // started immediately.
  job_e->ChangePriority(HIGHEST);
  ASSERT_TRUE(job_e->running());
  job_e->Finish();

  ASSERT_TRUE(job_b->running());
  job_b->Finish();
  ASSERT_TRUE(job_c->running());
  job_c->Finish();

  Expect("a.d.be..c.");
}

TEST_F(PrioritizedDispatcherTest, Cancel) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', IDLE);
  std::unique_ptr<TestJob> job_c = AddJob('c', IDLE);
  std::unique_ptr<TestJob> job_d = AddJob('d', IDLE);
  std::unique_ptr<TestJob> job_e = AddJob('e', IDLE);

  ASSERT_FALSE(job_b->running());
  ASSERT_FALSE(job_d->running());
  job_b->Cancel();
  job_d->Cancel();

  ASSERT_TRUE(job_a->running());
  job_a->Finish();
  ASSERT_TRUE(job_c->running());
  job_c->Finish();
  ASSERT_TRUE(job_e->running());
  job_e->Finish();

  Expect("a.c.e.");
}

TEST_F(PrioritizedDispatcherTest, Evict) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', LOW);
  std::unique_ptr<TestJob> job_c = AddJob('c', HIGHEST);
  std::unique_ptr<TestJob> job_d = AddJob('d', LOW);
  std::unique_ptr<TestJob> job_e = AddJob('e', HIGHEST);

  EXPECT_EQ(job_b.get(), dispatcher_->EvictOldestLowest());
  EXPECT_EQ(job_d.get(), dispatcher_->EvictOldestLowest());

  ASSERT_TRUE(job_a->running());
  job_a->Finish();
  ASSERT_TRUE(job_c->running());
  job_c->Finish();
  ASSERT_TRUE(job_e->running());
  job_e->Finish();

  Expect("a.c.e.");
}

TEST_F(PrioritizedDispatcherTest, EvictFromEmpty) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);
  EXPECT_TRUE(dispatcher_->EvictOldestLowest() == nullptr);
}

TEST_F(PrioritizedDispatcherTest, AddWhileZeroLimits) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 2);
  Prepare(limits);

  dispatcher_->SetLimitsToZero();
  std::unique_ptr<TestJob> job_a = AddJob('a', LOW);
  std::unique_ptr<TestJob> job_b = AddJob('b', MEDIUM);
  std::unique_ptr<TestJob> job_c = AddJobAtHead('c', MEDIUM);

  EXPECT_EQ(0u, dispatcher_->num_running_jobs());
  EXPECT_EQ(3u, dispatcher_->num_queued_jobs());

  dispatcher_->SetLimits(limits);
  EXPECT_EQ(2u, dispatcher_->num_running_jobs());
  EXPECT_EQ(1u, dispatcher_->num_queued_jobs());

  ASSERT_TRUE(job_b->running());
  job_b->Finish();

  ASSERT_TRUE(job_c->running());
  job_c->Finish();

  ASSERT_TRUE(job_a->running());
  job_a->Finish();

  Expect("cb.a..");
}

TEST_F(PrioritizedDispatcherTest, ReduceLimitsWhileJobQueued) {
  PrioritizedDispatcher::Limits initial_limits(NUM_PRIORITIES, 2);
  Prepare(initial_limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', MEDIUM);
  std::unique_ptr<TestJob> job_b = AddJob('b', MEDIUM);
  std::unique_ptr<TestJob> job_c = AddJob('c', MEDIUM);
  std::unique_ptr<TestJob> job_d = AddJob('d', MEDIUM);
  std::unique_ptr<TestJob> job_e = AddJob('e', MEDIUM);

  EXPECT_EQ(2u, dispatcher_->num_running_jobs());
  EXPECT_EQ(3u, dispatcher_->num_queued_jobs());

  // Reduce limits to just allow one job at a time.  Running jobs should not
  // be affected.
  dispatcher_->SetLimits(PrioritizedDispatcher::Limits(NUM_PRIORITIES, 1));

  EXPECT_EQ(2u, dispatcher_->num_running_jobs());
  EXPECT_EQ(3u, dispatcher_->num_queued_jobs());

  // Finishing a job should not result in another job starting.
  ASSERT_TRUE(job_a->running());
  job_a->Finish();
  EXPECT_EQ(1u, dispatcher_->num_running_jobs());
  EXPECT_EQ(3u, dispatcher_->num_queued_jobs());

  ASSERT_TRUE(job_b->running());
  job_b->Finish();
  EXPECT_EQ(1u, dispatcher_->num_running_jobs());
  EXPECT_EQ(2u, dispatcher_->num_queued_jobs());

  // Increasing the limits again should let c start.
  dispatcher_->SetLimits(initial_limits);

  ASSERT_TRUE(job_c->running());
  job_c->Finish();
  ASSERT_TRUE(job_d->running());
  job_d->Finish();
  ASSERT_TRUE(job_e->running());
  job_e->Finish();

  Expect("ab..cd.e..");
}

TEST_F(PrioritizedDispatcherTest, ZeroLimitsThenCancel) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', IDLE);
  std::unique_ptr<TestJob> job_c = AddJob('c', IDLE);
  dispatcher_->SetLimitsToZero();

  ASSERT_TRUE(job_a->running());
  EXPECT_FALSE(job_b->running());
  EXPECT_FALSE(job_c->running());
  job_a->Finish();

  EXPECT_FALSE(job_b->running());
  EXPECT_FALSE(job_c->running());

  // Cancelling b shouldn't start job c.
  job_b->Cancel();
  EXPECT_FALSE(job_c->running());

  // Restoring the limits should start c.
  dispatcher_->SetLimits(limits);
  ASSERT_TRUE(job_c->running());
  job_c->Finish();

  Expect("a.c.");
}

TEST_F(PrioritizedDispatcherTest, ZeroLimitsThenIncreasePriority) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 2);
  limits.reserved_slots[HIGHEST] = 1;
  Prepare(limits);

  std::unique_ptr<TestJob> job_a = AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', IDLE);
  EXPECT_TRUE(job_a->running());
  EXPECT_FALSE(job_b->running());
  dispatcher_->SetLimitsToZero();

  job_b->ChangePriority(HIGHEST);
  EXPECT_FALSE(job_b->running());
  job_a->Finish();
  EXPECT_FALSE(job_b->running());

  job_b->Cancel();
  Expect("a.");
}

#if GTEST_HAS_DEATH_TEST
TEST_F(PrioritizedDispatcherTest, CancelNull) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);
  EXPECT_DCHECK_DEATH(dispatcher_->Cancel(PrioritizedDispatcher::Handle()));
}

TEST_F(PrioritizedDispatcherTest, CancelMissing) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES, 1);
  Prepare(limits);
  AddJob('a', IDLE);
  std::unique_ptr<TestJob> job_b = AddJob('b', IDLE);
  PrioritizedDispatcher::Handle handle = job_b->handle();
  ASSERT_FALSE(handle.is_null());
  dispatcher_->Cancel(handle);
  EXPECT_DCHECK_DEATH(dispatcher_->Cancel(handle));
}
#endif  // GTEST_HAS_DEATH_TEST

}  // namespace

}  // namespace net
```