Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The file name `compiler-dispatcher-unittest.cc` immediately suggests that this is a test file specifically for a component called "compiler dispatcher."  The directory `v8/test/unittests/compiler-dispatcher/` reinforces this. The "unittest" part indicates isolated testing of this specific component.

2. **Examine Includes:** The included headers give valuable clues about the file's functionality. Key includes are:
    * `"include/v8-platform.h"`: Interaction with the V8 platform layer (threading, tasks).
    * `"src/api/api-inl.h"`: V8 API interaction.
    * `"src/ast/..."`: Abstract Syntax Tree related structures. This suggests the dispatcher deals with code representations.
    * `"src/base/platform/..."`: Platform-independent threading primitives (condition variables, semaphores).
    * `"src/codegen/compiler.h"`:  Directly related to the compilation process.
    * `"src/compiler-dispatcher/lazy-compile-dispatcher.h"`:  This is the *target* of the tests. The file is testing the `LazyCompileDispatcher` class.
    * `"src/flags/flags.h"`: Interaction with V8's command-line flags.
    * `"src/handles/handles.h"`: Management of V8 objects.
    * `"src/objects/objects-inl.h"`: V8 object representations.
    * `"src/parsing/..."`:  Code parsing related structures.
    * `"test/unittests/..."`:  V8 testing utilities.
    * `"testing/gtest/include/gtest/gtest.h"`: The Google Test framework is used for structuring the tests.

3. **Analyze the `LazyCompileDispatcherTestFlags` Class:** This class is clearly a setup and teardown mechanism for tests. It manipulates V8 flags, specifically `v8_flags.lazy_compile_dispatcher`. This indicates that the `LazyCompileDispatcher` is controlled by this flag.

4. **Examine the `LazyCompileDispatcherTest` Class:** This class sets up the test environment. The `SetUpTestSuite` and `TearDownTestSuite` methods indicate actions performed before and after all tests in this suite. Crucially, `SetUpTestSuite` calls `LazyCompileDispatcherTestFlags::SetFlagsForTest()`, confirming the flag's importance. The `EnqueueUnoptimizedCompileJob` function is a helper for adding functions to the dispatcher's queue.

5. **Focus on the Test Cases (`TEST_F`)**: Each `TEST_F` macro defines an individual test. By reading the names of the tests, we can infer specific functionalities being tested:
    * `Construct`:  Testing the creation of the `LazyCompileDispatcher`.
    * `IsEnqueued`:  Testing if the dispatcher correctly tracks functions added to its queue.
    * `FinishNow`: Testing the immediate compilation of a function.
    * `CompileAndFinalize`: Testing the full compilation lifecycle, including background compilation and finalization via an idle task.
    * `IdleTaskNoIdleTime`, `IdleTaskSmallIdleTime`: Testing how the idle task handles varying amounts of available idle time.
    * `IdleTaskException`, `FinishNowException`: Testing how the dispatcher handles compilation errors.
    * `FinishNowWithWorkerTask`: Testing `FinishNow` when a background compilation is in progress.
    * `IdleTaskMultipleJobs`: Testing the handling of multiple compilation jobs.
    * `AbortJobNotStarted`, `AbortJobAlreadyStarted`: Testing the ability to cancel compilation jobs in different states.
    * `CompileLazyFinishesDispatcherJob`, `CompileLazy2FinishesDispatcherJob`: Testing integration with the "lazy compilation" mechanism in V8.
    * `CompileMultipleOnBackgroundThread`: Testing the parallel compilation of multiple functions.

6. **Look for Mocking:** The `MockPlatform` class is a clear sign of dependency injection and isolated testing. It overrides platform functionalities to control the testing environment (e.g., time, task posting). This helps in simulating different scenarios.

7. **Identify Key Interactions:** Notice how the tests interact with the `MockPlatform` to simulate background tasks (`RunJobTasks`, `RunJobTasksAndBlock`) and idle time (`RunIdleTask`). This reveals the asynchronous nature of the `LazyCompileDispatcher`.

8. **Code Logic and Data Flow (High-Level):**  The tests generally follow this pattern:
    * Create a `LazyCompileDispatcher` and a `MockPlatform`.
    * Create `SharedFunctionInfo` objects (representing JavaScript functions).
    * Enqueue these functions for compilation using `EnqueueUnoptimizedCompileJob`.
    * Simulate background compilation using `platform.RunJobTasks...`.
    * Simulate idle-time finalization using `platform.RunIdleTask`.
    * Assertions are used throughout to verify the state of the dispatcher and the compiled functions.

9. **Relate to JavaScript (if applicable):** The tests manipulate `SharedFunctionInfo`, which are V8's internal representation of JavaScript functions. The tests implicitly relate to the performance optimization of JavaScript execution by deferring compilation.

10. **Consider Potential Errors:**  The tests involving exceptions (`IdleTaskException`, `FinishNowException`) highlight potential error scenarios in the compilation process. The tests also implicitly cover scenarios where the dispatcher might not behave as expected under concurrency or timing constraints.

By following these steps, we can systematically understand the functionality of the `compiler-dispatcher-unittest.cc` file and the `LazyCompileDispatcher` it tests. This process involves reading the code, understanding the purpose of different classes and methods, and inferring the overall behavior from the individual test cases.
这个C++源代码文件 `v8/test/unittests/compiler-dispatcher/compiler-dispatcher-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 `LazyCompileDispatcher` 类的功能。

**以下是它的主要功能分解：**

1. **测试 `LazyCompileDispatcher` 类的基本操作:**
   - **构造和析构:** 测试 `LazyCompileDispatcher` 对象的创建和销毁。
   - **入队和查询:** 测试将待编译的 `SharedFunctionInfo` 对象加入到调度器队列，以及查询是否已入队的功能 (`IsEnqueued`)。
   - **立即完成编译:** 测试 `FinishNow` 方法，该方法会立即强制编译指定的函数，并将其从队列中移除。
   - **编译和最终化:** 测试完整的编译流程，包括将任务放入后台线程编译，以及在空闲时间进行最终化。
   - **处理空闲时间:** 测试当系统没有空闲时间或只有少量空闲时间时，调度器如何处理编译任务。

2. **模拟平台交互:**
   - 使用 `MockPlatform` 类来模拟 V8 平台层的一些功能，例如任务调度、时间管理等。这使得测试可以在隔离的环境中进行，而无需依赖真实的平台实现。
   - 通过 `MockPlatform` 控制后台编译任务的执行 (`RunJobTasks`, `RunJobTasksAndBlock`) 和空闲任务的执行 (`RunIdleTask`)。

3. **测试异常处理:**
   - 测试在编译过程中发生异常时，`LazyCompileDispatcher` 如何处理，例如 `IdleTaskException` 和 `FinishNowException` 测试用例。

4. **测试与 V8 编译流程的集成:**
   - 测试 `CompileLazy` 功能，这涉及到 V8 的延迟编译机制。当 JavaScript 函数第一次被调用时，V8 可能会选择延迟编译以提高启动速度。该测试验证了当延迟编译发生时，`LazyCompileDispatcher` 能否正确处理已入队的函数。

5. **测试任务取消 (Abort):**
   - 测试在编译任务尚未开始 (`AbortJobNotStarted`) 或已经开始 (`AbortJobAlreadyStarted`) 的情况下，取消任务的功能。

6. **测试并发场景:**
   - 测试在后台线程编译多个函数的情况 (`CompileMultipleOnBackgroundThread`)，以及多个任务同时在队列中的情况 (`IdleTaskMultipleJobs`)。

**关于文件扩展名和 Torque：**

- 如果 `v8/test/unittests/compiler-dispatcher/compiler-dispatcher-unittest.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。
- 但根据你提供的代码内容，该文件以 `.cc` 结尾，表明它是一个 C++ 文件，用于测试 C++ 代码。

**与 JavaScript 的功能关系及 JavaScript 示例：**

`LazyCompileDispatcher` 的核心功能是优化 JavaScript 代码的编译过程，特别是针对那些在启动阶段不立即执行的函数进行延迟编译。这有助于提高 V8 引擎的启动速度和初始响应性。

**JavaScript 示例：**

```javascript
function potentiallyExpensiveFunction() {
  // 复杂的计算或操作
  let sum = 0;
  for (let i = 0; i < 1000000; i++) {
    sum += i;
  }
  return sum;
}

// 在脚本启动时，这个函数可能不会立即被调用
// LazyCompileDispatcher 的作用就是将其编译推迟到合适的时机，
// 例如在空闲时间或者第一次被调用时。

console.log("脚本启动完成");

// 稍后调用该函数
let result = potentiallyExpensiveFunction();
console.log("函数调用结果:", result);
```

在这个例子中，`potentiallyExpensiveFunction` 可能是一个在脚本启动时不立即需要的函数。`LazyCompileDispatcher` 的目标就是避免在启动时立即编译这个函数，从而加快启动速度。当这个函数第一次被调用时，V8 会触发编译（如果还没有被调度器在后台或空闲时间编译）。

**代码逻辑推理和假设输入/输出：**

让我们以 `TEST_F(LazyCompileDispatcherTest, IsEnqueued)` 为例进行代码逻辑推理：

**假设输入：**

1. 一个 `MockPlatform` 实例 `platform`。
2. 一个 `LazyCompileDispatcher` 实例 `dispatcher`。
3. 一个未编译的 `SharedFunctionInfo` 对象 `shared`，代表一个 JavaScript 函数。

**代码逻辑：**

1. 断言 `shared` 对象尚未被编译 (`ASSERT_FALSE(shared->is_compiled());`)。
2. 断言 `dispatcher` 中尚未包含 `shared` 对象 (`ASSERT_FALSE(dispatcher.IsEnqueued(shared));`)。
3. 使用 `EnqueueUnoptimizedCompileJob` 将 `shared` 对象添加到 `dispatcher` 的队列中。
4. 断言 `dispatcher` 现在包含 `shared` 对象 (`ASSERT_TRUE(dispatcher.IsEnqueued(shared));`)。
5. 调用 `dispatcher.AbortAll()` 清空队列。
6. 断言 `dispatcher` 中不再包含 `shared` 对象 (`ASSERT_FALSE(dispatcher.IsEnqueued(shared));`)。
7. 断言没有挂起的空闲任务 (`ASSERT_FALSE(platform.IdleTaskPending());`)。
8. 断言有挂起的后台编译任务 (`ASSERT_TRUE(platform.JobTaskPending());`)。

**预期输出：**

所有 `ASSERT` 语句都应为真，测试用例才能通过。这个测试验证了 `LazyCompileDispatcher` 正确地管理了待编译函数的队列状态。

**涉及用户常见的编程错误（虽然这是 V8 内部测试，但可以引申）：**

虽然这个文件是 V8 内部的测试，但从其测试的功能中，我们可以推断出与用户编程相关的潜在错误：

1. **过度依赖同步编译：**  如果 V8 没有 `LazyCompileDispatcher` 这样的机制，那么所有函数都必须在首次遇到时同步编译，这会导致启动延迟。用户可能会因为编写大量复杂函数而遇到性能问题，尤其是在启动阶段。

2. **不理解 JavaScript 引擎的优化策略：** 用户可能不会意识到 V8 内部存在延迟编译这样的优化，可能会写出一些在启动时执行大量不必要代码的程序，导致性能下降。`LazyCompileDispatcher` 的测试确保了 V8 能够有效地进行这类优化。

3. **在性能敏感区域执行高开销操作：** 即使有延迟编译，如果用户在关键路径上（例如，用户交互的响应事件中）调用了尚未编译的复杂函数，仍然可能导致卡顿。了解哪些代码会被延迟编译以及如何避免在关键时刻触发编译是很重要的。

总而言之，`v8/test/unittests/compiler-dispatcher/compiler-dispatcher-unittest.cc` 是 V8 内部保证其延迟编译功能正确性的重要组成部分，间接地也影响着 JavaScript 开发者编写高效代码的方式。

### 提示词
```
这是目录为v8/test/unittests/compiler-dispatcher/compiler-dispatcher-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/compiler-dispatcher/compiler-dispatcher-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>

#include "include/v8-platform.h"
#include "src/api/api-inl.h"
#include "src/ast/ast-value-factory.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/base/platform/condition-variable.h"
#include "src/base/platform/semaphore.h"
#include "src/codegen/compiler.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/flags/flags.h"
#include "src/handles/handles.h"
#include "src/init/v8.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/parsing.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/zone/zone-list-inl.h"
#include "test/unittests/test-helpers.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

#ifdef DEBUG
#define DEBUG_ASSERT_EQ ASSERT_EQ
#else
#define DEBUG_ASSERT_EQ(...)
#endif

namespace v8 {
namespace internal {

class LazyCompileDispatcherTestFlags {
 public:
  LazyCompileDispatcherTestFlags(const LazyCompileDispatcherTestFlags&) =
      delete;
  LazyCompileDispatcherTestFlags& operator=(
      const LazyCompileDispatcherTestFlags&) = delete;
  static void SetFlagsForTest() {
    CHECK_NULL(save_flags_);
    save_flags_ = new SaveFlags();
    v8_flags.lazy_compile_dispatcher = true;
    FlagList::EnforceFlagImplications();
  }

  static void RestoreFlags() {
    CHECK_NOT_NULL(save_flags_);
    delete save_flags_;
    save_flags_ = nullptr;
  }

 private:
  static SaveFlags* save_flags_;
};

SaveFlags* LazyCompileDispatcherTestFlags::save_flags_ = nullptr;

class LazyCompileDispatcherTest : public TestWithNativeContext {
 public:
  LazyCompileDispatcherTest() = default;
  ~LazyCompileDispatcherTest() override = default;
  LazyCompileDispatcherTest(const LazyCompileDispatcherTest&) = delete;
  LazyCompileDispatcherTest& operator=(const LazyCompileDispatcherTest&) =
      delete;

  static void SetUpTestSuite() {
    LazyCompileDispatcherTestFlags::SetFlagsForTest();
    TestWithNativeContext::SetUpTestSuite();
  }

  static void TearDownTestSuite() {
    TestWithNativeContext::TearDownTestSuite();
    LazyCompileDispatcherTestFlags::RestoreFlags();
  }

  static void EnqueueUnoptimizedCompileJob(LazyCompileDispatcher* dispatcher,
                                           Isolate* isolate,
                                           Handle<SharedFunctionInfo> shared) {
    if (dispatcher->IsEnqueued(shared)) return;
    dispatcher->Enqueue(isolate->main_thread_local_isolate(), shared,
                        test::SourceCharacterStreamForShared(isolate, shared));
  }
};

namespace {

class DeferredPostJob {
 public:
  class DeferredJobHandle final : public JobHandle {
   public:
    explicit DeferredJobHandle(DeferredPostJob* owner) : owner_(owner) {
      owner->deferred_handle_ = this;
    }
    ~DeferredJobHandle() final {
      if (owner_) {
        owner_->deferred_handle_ = nullptr;
      }
    }

    void NotifyConcurrencyIncrease() final {
      DCHECK(!was_cancelled());
      if (real_handle()) {
        real_handle()->NotifyConcurrencyIncrease();
      }
      owner_->NotifyConcurrencyIncrease();
    }
    void Cancel() final {
      set_cancelled();
      if (real_handle()) {
        real_handle()->Cancel();
      }
    }
    void Join() final { UNREACHABLE(); }
    void CancelAndDetach() final { UNREACHABLE(); }
    bool IsActive() final { return real_handle() && real_handle()->IsActive(); }
    bool IsValid() final { return owner_->HandleIsValid(); }

    void ClearOwner() { owner_ = nullptr; }

   private:
    JobHandle* real_handle() { return owner_->real_handle_.get(); }
    bool was_cancelled() { return owner_->was_cancelled_; }
    void set_cancelled() {
      DCHECK(!was_cancelled());
      owner_->was_cancelled_ = true;
    }

    DeferredPostJob* owner_;
  };

  ~DeferredPostJob() {
    if (deferred_handle_) deferred_handle_->ClearOwner();
  }

  std::unique_ptr<JobHandle> CreateJob(TaskPriority priority,
                                       std::unique_ptr<JobTask> job_task) {
    DCHECK_NULL(job_task_);
    job_task_ = std::move(job_task);
    priority_ = priority;
    return std::make_unique<DeferredJobHandle>(this);
  }

  void NotifyConcurrencyIncrease() { do_post_ = true; }

  bool IsPending() { return job_task_ != nullptr; }

  void Clear() { job_task_.reset(); }

  void DoRealPostJob(Platform* platform) {
    if (do_post_)
      real_handle_ = platform->PostJob(priority_, std::move(job_task_));
    else
      real_handle_ = platform->CreateJob(priority_, std::move(job_task_));
    if (was_cancelled_) {
      real_handle_->Cancel();
    }
  }

  void BlockUntilComplete() {
    // Join the handle pointed to by the deferred handle. This invalidates that
    // handle, but LazyCompileDispatcher still wants to be able to cancel the
    // job it posted, so clear the deferred handle to go back to relying on
    // was_cancelled for validity.
    real_handle_->Join();
    real_handle_ = nullptr;
  }

  bool HandleIsValid() {
    return !was_cancelled_ && real_handle_ && real_handle_->IsValid();
  }

 private:
  std::unique_ptr<JobTask> job_task_;
  TaskPriority priority_;

  // Non-owning pointer to the handle returned by PostJob. The handle holds
  // a pointer to this instance, and registers/deregisters itself on
  // constuction/destruction.
  DeferredJobHandle* deferred_handle_ = nullptr;

  std::unique_ptr<JobHandle> real_handle_ = nullptr;
  bool was_cancelled_ = false;
  bool do_post_ = false;
};

class MockPlatform : public v8::Platform {
 public:
  MockPlatform()
      : time_(0.0),
        time_step_(0.0),
        idle_task_(nullptr),
        tracing_controller_(V8::GetCurrentPlatform()->GetTracingController()) {}
  ~MockPlatform() override {
    EXPECT_FALSE(deferred_post_job_.HandleIsValid());
    base::MutexGuard lock(&idle_task_mutex_);
    EXPECT_EQ(idle_task_, nullptr);
  }
  MockPlatform(const MockPlatform&) = delete;
  MockPlatform& operator=(const MockPlatform&) = delete;

  PageAllocator* GetPageAllocator() override { UNIMPLEMENTED(); }

  int NumberOfWorkerThreads() override { return 1; }

  std::shared_ptr<TaskRunner> GetForegroundTaskRunner(
      v8::Isolate* isolate, TaskPriority priority) override {
    return std::make_shared<MockForegroundTaskRunner>(this);
  }

  void PostTaskOnWorkerThreadImpl(TaskPriority priority,
                                  std::unique_ptr<Task> task,
                                  const SourceLocation& location) override {
    UNREACHABLE();
  }

  void PostDelayedTaskOnWorkerThreadImpl(
      TaskPriority priority, std::unique_ptr<Task> task,
      double delay_in_seconds, const SourceLocation& location) override {
    UNREACHABLE();
  }

  bool IdleTasksEnabled(v8::Isolate* isolate) override { return true; }

  std::unique_ptr<JobHandle> CreateJobImpl(
      TaskPriority priority, std::unique_ptr<JobTask> job_task,
      const SourceLocation& location) override {
    return deferred_post_job_.CreateJob(priority, std::move(job_task));
  }

  double MonotonicallyIncreasingTime() override {
    time_ += time_step_;
    return time_;
  }

  double CurrentClockTimeMillis() override {
    return time_ * base::Time::kMillisecondsPerSecond;
  }

  v8::TracingController* GetTracingController() override {
    return tracing_controller_;
  }

  void RunIdleTask(double deadline_in_seconds, double time_step) {
    time_step_ = time_step;
    std::unique_ptr<IdleTask> task;
    {
      base::MutexGuard lock(&idle_task_mutex_);
      task.swap(idle_task_);
    }
    task->Run(deadline_in_seconds);
  }

  bool IdleTaskPending() {
    base::MutexGuard lock(&idle_task_mutex_);
    return idle_task_ != nullptr;
  }

  bool JobTaskPending() { return deferred_post_job_.IsPending(); }

  void RunJobTasksAndBlock(Platform* platform) {
    deferred_post_job_.DoRealPostJob(platform);
    deferred_post_job_.BlockUntilComplete();
  }

  void RunJobTasks(Platform* platform) {
    deferred_post_job_.DoRealPostJob(platform);
  }

  void BlockUntilComplete() { deferred_post_job_.BlockUntilComplete(); }

  void ClearJobs() { deferred_post_job_.Clear(); }

  void ClearIdleTask() {
    base::MutexGuard lock(&idle_task_mutex_);
    CHECK_NOT_NULL(idle_task_);
    idle_task_.reset();
  }

 private:
  class MockForegroundTaskRunner final : public TaskRunner {
   public:
    explicit MockForegroundTaskRunner(MockPlatform* platform)
        : platform_(platform) {}

    void PostTaskImpl(std::unique_ptr<v8::Task>,
                      const SourceLocation&) override {
      UNREACHABLE();
    }

    void PostNonNestableTaskImpl(std::unique_ptr<v8::Task>,
                                 const SourceLocation&) override {
      UNREACHABLE();
    }

    void PostDelayedTaskImpl(std::unique_ptr<Task>, double,
                             const SourceLocation&) override {
      UNREACHABLE();
    }

    void PostIdleTaskImpl(std::unique_ptr<IdleTask> task,
                          const SourceLocation&) override {
      DCHECK(IdleTasksEnabled());
      base::MutexGuard lock(&platform_->idle_task_mutex_);
      ASSERT_TRUE(platform_->idle_task_ == nullptr);
      platform_->idle_task_ = std::move(task);
    }

    bool IdleTasksEnabled() override { return true; }

    bool NonNestableTasksEnabled() const override { return false; }

   private:
    MockPlatform* platform_;
  };

  double time_;
  double time_step_;

  // The posted JobTask.
  DeferredPostJob deferred_post_job_;

  // The posted idle task.
  std::unique_ptr<IdleTask> idle_task_;

  // Protects idle_task_.
  base::Mutex idle_task_mutex_;

  v8::TracingController* tracing_controller_;
};

}  // namespace

TEST_F(LazyCompileDispatcherTest, Construct) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, IsEnqueued) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_FALSE(dispatcher.IsEnqueued(shared));

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  ASSERT_TRUE(dispatcher.IsEnqueued(shared));

  dispatcher.AbortAll();
  ASSERT_FALSE(dispatcher.IsEnqueued(shared));

  ASSERT_FALSE(platform.IdleTaskPending());
  ASSERT_TRUE(platform.JobTaskPending());
}

TEST_F(LazyCompileDispatcherTest, FinishNow) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  ASSERT_TRUE(dispatcher.FinishNow(shared));
  // Finishing removes the SFI from the queue.
  ASSERT_FALSE(dispatcher.IsEnqueued(shared));
  ASSERT_TRUE(shared->is_compiled());

  ASSERT_FALSE(platform.IdleTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, CompileAndFinalize) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);
  ASSERT_TRUE(platform.JobTaskPending());

  // Run compile steps.
  platform.RunJobTasksAndBlock(V8::GetCurrentPlatform());

  // Since we haven't yet finalized the job, it should be enqueued for
  // finalization and waiting for an idle task.
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_TRUE(platform.IdleTaskPending());
  platform.RunIdleTask(1000.0, 0.0);

  ASSERT_FALSE(dispatcher.IsEnqueued(shared));
  ASSERT_TRUE(shared->is_compiled());
  ASSERT_FALSE(platform.JobTaskPending());
  ASSERT_FALSE(platform.IdleTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, IdleTaskNoIdleTime) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 0u);

  // Run compile steps.
  platform.RunJobTasksAndBlock(V8::GetCurrentPlatform());

  // Job should be ready to finalize.
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 0u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 1u);
  ASSERT_EQ(
      dispatcher.GetJobFor(shared, base::MutexGuard(&dispatcher.mutex_))->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_TRUE(platform.IdleTaskPending());

  // Grant no idle time and have time advance beyond it in one step.
  platform.RunIdleTask(0.0, 1.0);

  ASSERT_TRUE(dispatcher.IsEnqueued(shared));
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_TRUE(platform.IdleTaskPending());

  // Job should be ready to finalize.
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 0u);
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(
      dispatcher.GetJobFor(shared, base::MutexGuard(&dispatcher.mutex_))->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);

  // Now grant a lot of idle time and freeze time.
  platform.RunIdleTask(1000.0, 0.0);

  ASSERT_FALSE(dispatcher.IsEnqueued(shared));
  ASSERT_TRUE(shared->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());
  ASSERT_FALSE(platform.JobTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, IdleTaskSmallIdleTime) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared_1 =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared_1->is_compiled());
  Handle<SharedFunctionInfo> shared_2 =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared_2->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared_1);
  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared_2);

  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 2u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 2u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 0u);

  // Run compile steps.
  platform.RunJobTasksAndBlock(V8::GetCurrentPlatform());

  // Both jobs should be ready to finalize.
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 2u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 0u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 2u);
  ASSERT_EQ(
      dispatcher.GetJobFor(shared_1, base::MutexGuard(&dispatcher.mutex_))
          ->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_EQ(
      dispatcher.GetJobFor(shared_2, base::MutexGuard(&dispatcher.mutex_))
          ->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_TRUE(platform.IdleTaskPending());

  // Grant a small anount of idle time and have time advance beyond it in one
  // step.
  platform.RunIdleTask(2.0, 1.0);

  // Only one of the jobs should be finalized.
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 0u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 1u);
  if (dispatcher.IsEnqueued(shared_1)) {
    ASSERT_EQ(
        dispatcher.GetJobFor(shared_1, base::MutexGuard(&dispatcher.mutex_))
            ->state,
        LazyCompileDispatcher::Job::State::kReadyToFinalize);
  } else {
    ASSERT_EQ(
        dispatcher.GetJobFor(shared_2, base::MutexGuard(&dispatcher.mutex_))
            ->state,
        LazyCompileDispatcher::Job::State::kReadyToFinalize);
  }
  ASSERT_NE(dispatcher.IsEnqueued(shared_1), dispatcher.IsEnqueued(shared_2));
  ASSERT_NE(shared_1->is_compiled(), shared_2->is_compiled());
  ASSERT_TRUE(platform.IdleTaskPending());

  // Now grant a lot of idle time and freeze time.
  platform.RunIdleTask(1000.0, 0.0);

  ASSERT_FALSE(dispatcher.IsEnqueued(shared_1));
  ASSERT_FALSE(dispatcher.IsEnqueued(shared_2));
  ASSERT_TRUE(shared_1->is_compiled());
  ASSERT_TRUE(shared_2->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());
  ASSERT_FALSE(platform.JobTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, IdleTaskException) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, 50);

  std::string raw_script("(x) { var a = ");
  for (int i = 0; i < 1000; i++) {
    // Alternate + and - to avoid n-ary operation nodes.
    raw_script += "'x' + 'x' - ";
  }
  raw_script += " 'x'; };";
  test::ScriptResource* script = new test::ScriptResource(
      raw_script.c_str(), strlen(raw_script.c_str()), JSParameterCount(1));
  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), script);
  ASSERT_FALSE(shared->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  // Run compile steps and finalize.
  platform.RunJobTasksAndBlock(V8::GetCurrentPlatform());
  platform.RunIdleTask(1000.0, 0.0);

  ASSERT_FALSE(dispatcher.IsEnqueued(shared));
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_FALSE(i_isolate()->has_exception());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, FinishNowWithWorkerTask) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  ASSERT_TRUE(dispatcher.IsEnqueued(shared));
  ASSERT_FALSE(shared->is_compiled());
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 0u);
  ASSERT_NE(
      dispatcher.GetJobFor(shared, base::MutexGuard(&dispatcher.mutex_))->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_TRUE(platform.JobTaskPending());

  // This does not block, but races with the FinishNow() call below.
  platform.RunJobTasks(V8::GetCurrentPlatform());

  ASSERT_TRUE(dispatcher.FinishNow(shared));
  // Finishing removes the SFI from the queue.
  ASSERT_FALSE(dispatcher.IsEnqueued(shared));
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 0u);
  ASSERT_TRUE(shared->is_compiled());
  if (platform.IdleTaskPending()) platform.ClearIdleTask();
  ASSERT_FALSE(platform.JobTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, IdleTaskMultipleJobs) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared_1 =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared_1->is_compiled());
  Handle<SharedFunctionInfo> shared_2 =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared_2->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared_1);
  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared_2);

  ASSERT_TRUE(dispatcher.IsEnqueued(shared_1));
  ASSERT_TRUE(dispatcher.IsEnqueued(shared_2));

  // Run compile steps and finalize.
  platform.RunJobTasksAndBlock(V8::GetCurrentPlatform());
  platform.RunIdleTask(1000.0, 0.0);

  ASSERT_FALSE(dispatcher.IsEnqueued(shared_1));
  ASSERT_FALSE(dispatcher.IsEnqueued(shared_2));
  ASSERT_TRUE(shared_1->is_compiled());
  ASSERT_TRUE(shared_2->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());
  ASSERT_FALSE(platform.JobTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, FinishNowException) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, 50);

  std::string raw_script("(x) { var a = ");
  for (int i = 0; i < 1000; i++) {
    // Alternate + and - to avoid n-ary operation nodes.
    raw_script += "'x' + 'x' - ";
  }
  raw_script += " 'x'; };";
  test::ScriptResource* script = new test::ScriptResource(
      raw_script.c_str(), strlen(raw_script.c_str()), JSParameterCount(1));
  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), script);
  ASSERT_FALSE(shared->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  ASSERT_FALSE(dispatcher.FinishNow(shared));

  ASSERT_FALSE(dispatcher.IsEnqueued(shared));
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_TRUE(i_isolate()->has_exception());

  i_isolate()->clear_exception();
  ASSERT_FALSE(platform.IdleTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, AbortJobNotStarted) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  ASSERT_FALSE(shared->is_compiled());
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 0u);
  ASSERT_NE(
      dispatcher.GetJobFor(shared, base::MutexGuard(&dispatcher.mutex_))->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_TRUE(platform.JobTaskPending());

  dispatcher.AbortJob(shared);

  // Aborting removes the job from the queue.
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, AbortJobAlreadyStarted) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared);

  ASSERT_FALSE(shared->is_compiled());
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 0u);
  ASSERT_NE(
      dispatcher.GetJobFor(shared, base::MutexGuard(&dispatcher.mutex_))->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_TRUE(platform.JobTaskPending());

  // Have dispatcher block on the background thread when running the job.
  {
    base::LockGuard<base::Mutex> lock(&dispatcher.mutex_);
    dispatcher.block_for_testing_.SetValue(true);
  }

  // Start background thread and wait until it is about to run the job.
  platform.RunJobTasks(V8::GetCurrentPlatform());
  while (dispatcher.block_for_testing_.Value()) {
  }

  // Now abort while dispatcher is in the middle of running the job.
  dispatcher.AbortJob(shared);

  // Unblock background thread, and wait for job to complete.
  {
    base::LockGuard<base::Mutex> lock(&dispatcher.mutex_);
    dispatcher.semaphore_for_testing_.Signal();
  }
  platform.BlockUntilComplete();

  // Job should have finished running and then been aborted.
  ASSERT_FALSE(shared->is_compiled());
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 1u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 0u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 1u);
  ASSERT_EQ(
      dispatcher.GetJobFor(shared, base::MutexGuard(&dispatcher.mutex_))->state,
      LazyCompileDispatcher::Job::State::kAborted);
  ASSERT_FALSE(platform.JobTaskPending());
  ASSERT_TRUE(platform.IdleTaskPending());

  // Runt the pending idle task
  platform.RunIdleTask(1000.0, 0.0);

  // Aborting removes the SFI from the queue.
  ASSERT_FALSE(shared->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());
  ASSERT_FALSE(platform.JobTaskPending());
  dispatcher.AbortAll();
}

TEST_F(LazyCompileDispatcherTest, CompileLazyFinishesDispatcherJob) {
  // Use the real dispatcher so that CompileLazy checks the same one for
  // enqueued functions.
  LazyCompileDispatcher* dispatcher = i_isolate()->lazy_compile_dispatcher();

  const char raw_script[] = "function lazy() { return 42; }; lazy;";
  test::ScriptResource* script = new test::ScriptResource(
      raw_script, strlen(raw_script), JSParameterCount(0));
  DirectHandle<JSFunction> f = RunJS<JSFunction>(script);
  Handle<SharedFunctionInfo> shared(f->shared(), i_isolate());
  ASSERT_FALSE(shared->is_compiled());

  EnqueueUnoptimizedCompileJob(dispatcher, i_isolate(), shared);

  // Now force the function to run and ensure CompileLazy finished and dequeues
  // it from the dispatcher.
  RunJS("lazy();");
  ASSERT_TRUE(shared->is_compiled());
  ASSERT_FALSE(dispatcher->IsEnqueued(shared));
}

TEST_F(LazyCompileDispatcherTest, CompileLazy2FinishesDispatcherJob) {
  // Use the real dispatcher so that CompileLazy checks the same one for
  // enqueued functions.
  LazyCompileDispatcher* dispatcher = i_isolate()->lazy_compile_dispatcher();

  const char raw_source_2[] = "function lazy2() { return 42; }; lazy2;";
  test::ScriptResource* source_2 = new test::ScriptResource(
      raw_source_2, strlen(raw_source_2), JSParameterCount(0));
  DirectHandle<JSFunction> lazy2 = RunJS<JSFunction>(source_2);
  Handle<SharedFunctionInfo> shared_2(lazy2->shared(), i_isolate());
  ASSERT_FALSE(shared_2->is_compiled());

  const char raw_source_1[] = "function lazy1() { return lazy2(); }; lazy1;";
  test::ScriptResource* source_1 = new test::ScriptResource(
      raw_source_1, strlen(raw_source_1), JSParameterCount(0));
  DirectHandle<JSFunction> lazy1 = RunJS<JSFunction>(source_1);
  Handle<SharedFunctionInfo> shared_1(lazy1->shared(), i_isolate());
  ASSERT_FALSE(shared_1->is_compiled());

  EnqueueUnoptimizedCompileJob(dispatcher, i_isolate(), shared_1);
  EnqueueUnoptimizedCompileJob(dispatcher, i_isolate(), shared_2);

  ASSERT_TRUE(dispatcher->IsEnqueued(shared_1));
  ASSERT_TRUE(dispatcher->IsEnqueued(shared_2));

  RunJS("lazy1();");
  ASSERT_TRUE(shared_1->is_compiled());
  ASSERT_TRUE(shared_2->is_compiled());
  ASSERT_FALSE(dispatcher->IsEnqueued(shared_1));
  ASSERT_FALSE(dispatcher->IsEnqueued(shared_2));
}

TEST_F(LazyCompileDispatcherTest, CompileMultipleOnBackgroundThread) {
  MockPlatform platform;
  LazyCompileDispatcher dispatcher(i_isolate(), &platform, v8_flags.stack_size);

  Handle<SharedFunctionInfo> shared_1 =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared_1->is_compiled());

  Handle<SharedFunctionInfo> shared_2 =
      test::CreateSharedFunctionInfo(i_isolate(), nullptr);
  ASSERT_FALSE(shared_2->is_compiled());

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared_1);

  EnqueueUnoptimizedCompileJob(&dispatcher, i_isolate(), shared_2);

  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 2u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 2u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 0u);
  ASSERT_NE(
      dispatcher.GetJobFor(shared_1, base::MutexGuard(&dispatcher.mutex_))
          ->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_NE(
      dispatcher.GetJobFor(shared_2, base::MutexGuard(&dispatcher.mutex_))
          ->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);

  ASSERT_TRUE(dispatcher.IsEnqueued(shared_1));
  ASSERT_TRUE(dispatcher.IsEnqueued(shared_2));
  ASSERT_FALSE(shared_1->is_compiled());
  ASSERT_FALSE(shared_2->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());
  ASSERT_TRUE(platform.JobTaskPending());

  platform.RunJobTasksAndBlock(V8::GetCurrentPlatform());

  ASSERT_TRUE(platform.IdleTaskPending());
  ASSERT_FALSE(platform.JobTaskPending());
  DEBUG_ASSERT_EQ(dispatcher.all_jobs_.size(), 2u);
  ASSERT_EQ(dispatcher.pending_background_jobs_.size(), 0u);
  ASSERT_EQ(dispatcher.finalizable_jobs_.size(), 2u);
  ASSERT_EQ(
      dispatcher.GetJobFor(shared_1, base::MutexGuard(&dispatcher.mutex_))
          ->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);
  ASSERT_EQ(
      dispatcher.GetJobFor(shared_2, base::MutexGuard(&dispatcher.mutex_))
          ->state,
      LazyCompileDispatcher::Job::State::kReadyToFinalize);

  // Now grant a lot of idle time and freeze time.
  platform.RunIdleTask(1000.0, 0.0);

  ASSERT_FALSE(dispatcher.IsEnqueued(shared_1));
  ASSERT_FALSE(dispatcher.IsEnqueued(shared_2));
  ASSERT_TRUE(shared_1->is_compiled());
  ASSERT_TRUE(shared_2->is_compiled());
  ASSERT_FALSE(platform.IdleTaskPending());
  dispatcher.AbortAll();
}

}  // namespace internal
}  // namespace v8
```