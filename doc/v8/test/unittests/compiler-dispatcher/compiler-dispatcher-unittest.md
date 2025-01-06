Response: The user wants to understand the functionality of the C++ source code file `compiler-dispatcher-unittest.cc`. This file seems to contain unit tests for a component called `LazyCompileDispatcher`.

To summarise the functionality, I need to analyze the test cases and understand what aspects of the `LazyCompileDispatcher` they are testing.

Here's a breakdown of the tests and what they seem to be verifying:

- **Construct:** Tests the creation and destruction of `LazyCompileDispatcher`.
- **IsEnqueued:** Checks if the dispatcher correctly tracks whether a `SharedFunctionInfo` is enqueued for compilation.
- **FinishNow:** Verifies the synchronous compilation of a function when `FinishNow` is called.
- **CompileAndFinalize:** Tests the full compilation lifecycle, including background compilation and finalization via an idle task.
- **IdleTaskNoIdleTime:** Checks the behavior of the idle task when no idle time is available.
- **IdleTaskSmallIdleTime:** Tests the idle task's ability to process a subset of pending compilations when idle time is limited.
- **IdleTaskException:** Ensures the idle task handles compilation exceptions correctly.
- **FinishNowWithWorkerTask:** Tests the interaction between `FinishNow` and background compilation tasks.
- **IdleTaskMultipleJobs:** Verifies the idle task's ability to handle multiple pending compilations.
- **FinishNowException:** Checks how `FinishNow` handles compilation exceptions.
- **AbortJobNotStarted:** Tests the ability to abort a compilation job that hasn't started yet.
- **AbortJobAlreadyStarted:** Verifies the abortion of a compilation job that is currently running in the background.
- **CompileLazyFinishesDispatcherJob:** Checks if the `CompileLazy` mechanism correctly dequeues a function from the dispatcher.
- **CompileLazy2FinishesDispatcherJob:** Tests the interaction between `CompileLazy` and multiple enqueued functions.
- **CompileMultipleOnBackgroundThread:** Verifies the dispatcher's ability to handle multiple compilations on a background thread.

Based on these test cases, the `LazyCompileDispatcher` seems to be responsible for:

- **Managing a queue of functions waiting for compilation.**
- **Dispatching compilation tasks to background threads.**
- **Finalizing the compilation process on the main thread during idle time.**
- **Providing mechanisms for synchronous compilation (`FinishNow`).**
- **Handling compilation errors.**
- **Allowing abortion of pending or running compilation jobs.**
- **Integrating with the `CompileLazy` mechanism.**
这个C++源代码文件 `compiler-dispatcher-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 `LazyCompileDispatcher` 组件的功能。

总的来说，这个文件测试了 `LazyCompileDispatcher` 如何管理和执行 JavaScript 函数的延迟编译任务。 具体功能可以归纳为以下几点：

1. **延迟编译任务的入队和出队：**  测试 `LazyCompileDispatcher` 能否正确地将待编译的 `SharedFunctionInfo` 对象加入队列 (`Enqueue`)，以及在编译完成后或者被中止后将其移除队列 (`IsEnqueued`)。

2. **同步完成编译：** 测试 `FinishNow` 方法，该方法允许立即完成指定函数的编译，即使该函数原本在延迟编译队列中。

3. **异步编译和最终完成：** 测试 `LazyCompileDispatcher` 如何将编译任务分发到后台线程进行编译，并在主线程空闲时通过空闲任务 (`IdleTask`) 完成最终的编译步骤 (`CompileAndFinalize`)。

4. **空闲任务的调度和执行：**  测试空闲任务在不同空闲时间下的行为，例如，当没有空闲时间 (`IdleTaskNoIdleTime`) 或只有少量空闲时间 (`IdleTaskSmallIdleTime`) 时，空闲任务如何处理待完成的编译任务。

5. **编译过程中的异常处理：** 测试在异步编译或同步完成编译过程中发生异常时，`LazyCompileDispatcher` 如何处理这些异常 (`IdleTaskException`, `FinishNowException`)。

6. **与后台编译任务的交互：** 测试 `FinishNow` 方法与正在后台线程运行的编译任务之间的交互 (`FinishNowWithWorkerTask`)。

7. **处理多个编译任务：** 测试 `LazyCompileDispatcher` 如何同时管理和处理多个待编译的函数 (`IdleTaskMultipleJobs`, `CompileMultipleOnBackgroundThread`)。

8. **中止编译任务：** 测试 `AbortJob` 方法，该方法允许中止尚未开始或者正在后台线程运行的编译任务 (`AbortJobNotStarted`, `AbortJobAlreadyStarted`)。

9. **与 `CompileLazy` 机制的集成：** 测试当 JavaScript 代码执行到尚未编译的函数时，`CompileLazy` 机制如何触发编译，并确保该函数从 `LazyCompileDispatcher` 的队列中移除 (`CompileLazyFinishesDispatcherJob`, `CompileLazy2FinishesDispatcherJob`)。

简而言之，这个单元测试文件全面地测试了 `LazyCompileDispatcher` 的核心功能，包括任务的调度、执行、异常处理以及与其他编译机制的集成，确保了 V8 引擎能够有效地进行延迟编译，提高启动速度和性能。

此外，文件中还包含了一个 `MockPlatform` 类，用于模拟 V8 引擎的平台接口，方便进行隔离的单元测试。 `LazyCompileDispatcherTestFlags` 类用于在测试中临时设置和恢复相关的 V8 标志。

Prompt: ```这是目录为v8/test/unittests/compiler-dispatcher/compiler-dispatcher-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

"""
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

"""
```