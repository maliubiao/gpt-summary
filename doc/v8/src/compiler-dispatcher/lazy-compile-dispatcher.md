Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality in relation to JavaScript.

1. **Understand the Goal:** The request is to summarize the functionality of the `LazyCompileDispatcher` and explain its connection to JavaScript, providing a JavaScript example if relevant.

2. **Identify Key Classes and Data Structures:** Start by looking at the class definition and the main data structures it uses.

    * `LazyCompileDispatcher`: The central class.
    * `Job`:  Represents a compilation task.
    * `BackgroundCompileTask`:  The actual compilation logic.
    * `JobTask`:  A `v8::JobTask` used to run background work.
    * `pending_background_jobs_`: A list of jobs waiting to be processed in the background.
    * `finalizable_jobs_`: A list of jobs that have finished background compilation and are ready for finalization on the main thread.
    * `jobs_to_dispose_`:  A list of jobs waiting to be deleted.
    * `UncompiledData`:  Stores information about uncompiled JavaScript functions, including a pointer to the `Job`.

3. **Trace the Lifecycle of a Compilation Job:**  Follow the steps a piece of JavaScript code goes through when being lazily compiled. This will help understand the dispatcher's role.

    * **Enqueueing:** The `Enqueue` method seems to be the entry point. It creates a `Job` and a `BackgroundCompileTask`. Crucially, it associates the `Job` with the `SharedFunctionInfo` of the JavaScript function. The `SetUncompiledDataJobPointer` function is key here. This is the direct link between V8's internal representation of a JavaScript function and the background compilation job.
    * **Background Processing:** The `DoBackgroundWork` method is executed on a worker thread. It picks up pending jobs from `pending_background_jobs_`, runs the `BackgroundCompileTask` (which performs the actual compilation), and then moves the job to `finalizable_jobs_`.
    * **Finalization:** The `FinishNow` and `DoIdleWork` methods handle finalization. `FinishNow` forces immediate finalization, potentially blocking the main thread. `DoIdleWork` opportunistically finalizes jobs when the main thread is idle. Finalization involves taking the compiled code from the `BackgroundCompileTask` and making it usable by the V8 engine.
    * **Aborting:** The `AbortJob` and `AbortAll` methods allow canceling compilation tasks.
    * **Deletion:**  Jobs are eventually deleted, managed by `DeleteJob`.

4. **Identify the Connection to JavaScript:** The key connection lies in the `SharedFunctionInfo`. This internal V8 structure represents a JavaScript function. The `LazyCompileDispatcher` stores a pointer to its `Job` *within* the `SharedFunctionInfo`'s `UncompiledData`. This allows V8 to track the compilation status of a function.

5. **Explain the Benefits:**  Why have a `LazyCompileDispatcher`?

    * **Performance:** Background compilation avoids blocking the main thread, leading to a smoother user experience.
    * **Responsiveness:**  The UI remains responsive because compilation happens in the background.
    * **Efficiency:**  Utilizes multi-core processors by running compilation tasks in parallel.

6. **Formulate the Summary:**  Based on the above analysis, draft a summary of the `LazyCompileDispatcher`'s functionality. Focus on the core responsibilities: managing background compilation of JavaScript functions.

7. **Create the JavaScript Example:**  The JavaScript example should demonstrate the *effect* of lazy compilation. A function that is called multiple times will likely be compiled on subsequent calls, illustrating the "lazy" nature. Emphasize that the background compilation is transparent to the JavaScript code itself.

8. **Refine and Review:**  Read through the summary and the JavaScript example. Ensure they are clear, concise, and accurate. Check for any technical jargon that needs clarification. For example, explicitly mentioning "SharedFunctionInfo" and "UncompiledData" and their role in the connection. Ensure the JavaScript example clearly shows the *observable behavior* related to lazy compilation, even if the internal mechanics are hidden. Initially, I might have focused too much on the C++ details, but the request asked for the connection to JavaScript, so shifting the focus to the observable effects in JavaScript is important. Also, initially, I might have forgotten to emphasize the "lazy" aspect – the compilation doesn't happen immediately but is deferred until necessary.

This step-by-step approach, starting with the overall goal and drilling down into the details, helps in understanding complex code and explaining its relevance to a higher-level language like JavaScript.
这个C++源代码文件 `lazy-compile-dispatcher.cc`  实现了 V8 JavaScript 引擎中的一个关键组件：**延迟编译调度器 (Lazy Compile Dispatcher)**。

它的主要功能是：**管理 JavaScript 函数的后台编译任务，从而避免在主线程上进行耗时的编译操作，提高 JavaScript 执行的响应速度和性能。**

以下是其核心功能的归纳：

1. **接收编译请求 (Enqueue):** 当 V8 引擎需要编译一个 JavaScript 函数，但选择延迟编译时，会调用 `Enqueue` 方法将该函数的编译任务添加到调度器中。这包括了需要编译的 `SharedFunctionInfo` 对象和字符流 (函数源代码)。

2. **创建后台编译任务 (BackgroundCompileTask):**  `Enqueue` 方法会创建一个 `BackgroundCompileTask` 对象，该对象封装了在后台线程执行实际编译工作的逻辑。

3. **管理编译任务队列:**  调度器维护着一个或多个队列来管理待编译和已完成编译的函数。  `pending_background_jobs_` 存储待后台编译的任务， `finalizable_jobs_` 存储已完成后台编译，等待主线程最终完成的任务。

4. **在后台线程执行编译 (DoBackgroundWork):**  调度器会创建后台工作线程，并在这些线程上执行 `DoBackgroundWork` 方法。该方法会从待编译队列中取出任务，并调用 `BackgroundCompileTask` 执行实际的编译操作。

5. **与 JavaScript 函数对象关联:**  调度器通过修改 `SharedFunctionInfo` 对象中的 `UncompiledData`，将编译任务（`Job` 对象）的指针存储起来。这样，V8 引擎可以知道一个函数是否正在或已经完成了后台编译。

6. **主线程完成编译 (FinishNow, DoIdleWork):**
   - `FinishNow`: 当主线程需要立即执行一个正在后台编译的函数时，会调用 `FinishNow` 方法。该方法会等待后台编译完成，并在主线程上完成最后的编译步骤。
   - `DoIdleWork`:  当主线程空闲时，调度器会执行 `DoIdleWork`，从已完成后台编译的任务队列中取出任务，并在主线程上完成最后的编译步骤。这利用了主线程的空闲时间，进一步减少编译带来的卡顿。

7. **取消编译任务 (AbortJob, AbortAll):**  调度器提供了取消单个或所有后台编译任务的功能。

8. **优化编译流程:** 通过将耗时的编译操作放在后台线程执行，主线程可以继续处理其他 JavaScript 代码，保持应用的响应性。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`LazyCompileDispatcher` 的存在对 JavaScript 开发者来说是透明的，我们无法直接在 JavaScript 代码中控制它。但是，它的工作方式直接影响着 JavaScript 代码的执行性能和体验。

**核心思想是：延迟编译那些可能不会立即执行的代码，并且将编译过程放在后台进行，避免阻塞主线程。**

**JavaScript 示例 (概念性):**

考虑以下 JavaScript 代码：

```javascript
function potentiallyComplexFunction() {
  // 一段复杂的逻辑，编译耗时
  let sum = 0;
  for (let i = 0; i < 100000; i++) {
    sum += Math.sqrt(i) * Math.random();
  }
  return sum;
}

// 初始加载时，可能不会立即调用这个函数
console.log("应用程序启动");

// 稍后，在用户交互或者特定条件下调用这个函数
setTimeout(() => {
  let result = potentiallyComplexFunction();
  console.log("复杂函数的结果:", result);
}, 5000);
```

**在 V8 引擎中，`LazyCompileDispatcher` 可能按以下方式工作：**

1. 当 V8 引擎解析到 `potentiallyComplexFunction` 的定义时，**不会立即进行完整的编译**，而是会生成一些基本的中间表示。
2. 当 `setTimeout` 中的回调函数被触发，并且即将调用 `potentiallyComplexFunction` 时，如果该函数还没有被编译，V8 引擎会将该函数的编译任务 **放入 `LazyCompileDispatcher` 的队列中**。
3. `LazyCompileDispatcher` 会在 **后台线程** 中启动对 `potentiallyComplexFunction` 的编译。
4. 在后台编译完成之前，如果 JavaScript 主线程需要执行其他代码，可以继续执行，不会被 `potentiallyComplexFunction` 的编译阻塞。
5. 当后台编译完成后，`LazyCompileDispatcher` 会通知主线程，主线程会在合适的时机完成最后的编译步骤。
6. 最终，当 `potentiallyComplexFunction` 真正被调用时，它可以以编译后的高效代码执行。

**没有 `LazyCompileDispatcher` 的情况:**

如果所有编译都在主线程上进行，那么当解析到 `potentiallyComplexFunction` 或者第一次调用它时，主线程可能会被编译过程阻塞一段时间，导致页面卡顿或无响应。

**总结:**

`LazyCompileDispatcher` 是 V8 引擎为了提高 JavaScript 执行性能和用户体验而设计的一个重要组件。它通过将耗时的编译任务转移到后台线程，并延迟编译不必要的代码，显著减少了主线程的阻塞，使得 JavaScript 应用更加流畅和响应迅速。虽然开发者无法直接操作它，但它的存在默默地优化着 JavaScript 代码的执行过程。

### 提示词
```
这是目录为v8/src/compiler-dispatcher/lazy-compile-dispatcher.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"

#include <atomic>

#include "include/v8-platform.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/time.h"
#include "src/codegen/compiler.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/heap/parked-scope.h"
#include "src/logging/counters.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/instance-type.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/scanner.h"
#include "src/tasks/cancelable-task.h"
#include "src/tasks/task-utils.h"
#include "src/zone/zone-list-inl.h"  // crbug.com/v8/8816

namespace v8 {
namespace internal {

// The maximum amount of time we should allow a single function's FinishNow to
// spend opportunistically finalizing other finalizable jobs.
static constexpr int kMaxOpportunisticFinalizeTimeMs = 1;

class LazyCompileDispatcher::JobTask : public v8::JobTask {
 public:
  explicit JobTask(LazyCompileDispatcher* lazy_compile_dispatcher)
      : lazy_compile_dispatcher_(lazy_compile_dispatcher) {}

  void Run(JobDelegate* delegate) final {
    lazy_compile_dispatcher_->DoBackgroundWork(delegate);
  }

  size_t GetMaxConcurrency(size_t worker_count) const final {
    size_t n = lazy_compile_dispatcher_->num_jobs_for_background_.load(
        std::memory_order_relaxed);
    if (v8_flags.lazy_compile_dispatcher_max_threads == 0) return n;
    return std::min(
        n, static_cast<size_t>(v8_flags.lazy_compile_dispatcher_max_threads));
  }

 private:
  LazyCompileDispatcher* lazy_compile_dispatcher_;
};

LazyCompileDispatcher::Job::Job(std::unique_ptr<BackgroundCompileTask> task)
    : task(std::move(task)), state(Job::State::kPending) {}

LazyCompileDispatcher::Job::~Job() = default;

LazyCompileDispatcher::LazyCompileDispatcher(Isolate* isolate,
                                             Platform* platform,
                                             size_t max_stack_size)
    : isolate_(isolate),
      worker_thread_runtime_call_stats_(
          isolate->counters()->worker_thread_runtime_call_stats()),
      background_compile_timer_(
          isolate->counters()->compile_function_on_background()),
      taskrunner_(platform->GetForegroundTaskRunner(
          reinterpret_cast<v8::Isolate*>(isolate))),
      platform_(platform),
      max_stack_size_(max_stack_size),
      trace_compiler_dispatcher_(v8_flags.trace_compiler_dispatcher),
      idle_task_manager_(new CancelableTaskManager()),
      idle_task_scheduled_(false),
      num_jobs_for_background_(0),
      main_thread_blocking_on_job_(nullptr),
      block_for_testing_(false),
      semaphore_for_testing_(0) {
  job_handle_ = platform_->PostJob(TaskPriority::kUserVisible,
                                   std::make_unique<JobTask>(this));
}

LazyCompileDispatcher::~LazyCompileDispatcher() {
  // AbortAll must be called before LazyCompileDispatcher is destroyed.
  CHECK(!job_handle_->IsValid());
}

namespace {

// If the SharedFunctionInfo's UncompiledData has a job slot, then write into
// it. Otherwise, allocate a new UncompiledData with a job slot, and then write
// into that. Since we have two optional slots (preparse data and job), this
// gets a little messy.
void SetUncompiledDataJobPointer(LocalIsolate* isolate,
                                 DirectHandle<SharedFunctionInfo> shared_info,
                                 Address job_address) {
  Tagged<UncompiledData> uncompiled_data =
      shared_info->uncompiled_data(isolate);
  switch (uncompiled_data->map(isolate)->instance_type()) {
    // The easy cases -- we already have a job slot, so can write into it and
    // return.
    case UNCOMPILED_DATA_WITH_PREPARSE_DATA_AND_JOB_TYPE:
      Cast<UncompiledDataWithPreparseDataAndJob>(uncompiled_data)
          ->set_job(job_address);
      break;
    case UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_WITH_JOB_TYPE:
      Cast<UncompiledDataWithoutPreparseDataWithJob>(uncompiled_data)
          ->set_job(job_address);
      break;

    // Otherwise, we'll have to allocate a new UncompiledData (with or without
    // preparse data as appropriate), set the job pointer on that, and update
    // the SharedFunctionInfo to use the new UncompiledData
    case UNCOMPILED_DATA_WITH_PREPARSE_DATA_TYPE: {
      Handle<String> inferred_name(uncompiled_data->inferred_name(), isolate);
      Handle<PreparseData> preparse_data(
          Cast<UncompiledDataWithPreparseData>(uncompiled_data)
              ->preparse_data(),
          isolate);
      DirectHandle<UncompiledDataWithPreparseDataAndJob> new_uncompiled_data =
          isolate->factory()->NewUncompiledDataWithPreparseDataAndJob(
              inferred_name, uncompiled_data->start_position(),
              uncompiled_data->end_position(), preparse_data);

      new_uncompiled_data->set_job(job_address);
      shared_info->set_uncompiled_data(*new_uncompiled_data);
      break;
    }
    case UNCOMPILED_DATA_WITHOUT_PREPARSE_DATA_TYPE: {
      DCHECK(IsUncompiledDataWithoutPreparseData(uncompiled_data));
      Handle<String> inferred_name(uncompiled_data->inferred_name(), isolate);
      DirectHandle<UncompiledDataWithoutPreparseDataWithJob>
          new_uncompiled_data =
              isolate->factory()->NewUncompiledDataWithoutPreparseDataWithJob(
                  inferred_name, uncompiled_data->start_position(),
                  uncompiled_data->end_position());

      new_uncompiled_data->set_job(job_address);
      shared_info->set_uncompiled_data(*new_uncompiled_data);
      break;
    }

    default:
      UNREACHABLE();
  }
}

}  // namespace

void LazyCompileDispatcher::Enqueue(
    LocalIsolate* isolate, Handle<SharedFunctionInfo> shared_info,
    std::unique_ptr<Utf16CharacterStream> character_stream) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.LazyCompilerDispatcherEnqueue");
  RCS_SCOPE(isolate, RuntimeCallCounterId::kCompileEnqueueOnDispatcher);

  Job* job = new Job(std::make_unique<BackgroundCompileTask>(
      isolate_, shared_info, std::move(character_stream),
      worker_thread_runtime_call_stats_, background_compile_timer_,
      static_cast<int>(max_stack_size_)));

  SetUncompiledDataJobPointer(isolate, shared_info,
                              reinterpret_cast<Address>(job));

  // Post a background worker task to perform the compilation on the worker
  // thread.
  {
    base::MutexGuard lock(&mutex_);
    if (trace_compiler_dispatcher_) {
      PrintF("LazyCompileDispatcher: enqueued job for ");
      ShortPrint(*shared_info);
      PrintF("\n");
    }

#ifdef DEBUG
    all_jobs_.insert(job);
#endif
    pending_background_jobs_.push_back(job);
    NotifyAddedBackgroundJob(lock);
  }
  // This is not in NotifyAddedBackgroundJob to avoid being inside the mutex.
  job_handle_->NotifyConcurrencyIncrease();
}

bool LazyCompileDispatcher::IsEnqueued(
    DirectHandle<SharedFunctionInfo> shared) const {
  if (!shared->HasUncompiledData()) return false;
  Job* job = nullptr;
  Tagged<UncompiledData> data = shared->uncompiled_data(isolate_);
  if (IsUncompiledDataWithPreparseDataAndJob(data)) {
    job = reinterpret_cast<Job*>(
        Cast<UncompiledDataWithPreparseDataAndJob>(data)->job());
  } else if (IsUncompiledDataWithoutPreparseDataWithJob(data)) {
    job = reinterpret_cast<Job*>(
        Cast<UncompiledDataWithoutPreparseDataWithJob>(data)->job());
  }
  return job != nullptr;
}

void LazyCompileDispatcher::WaitForJobIfRunningOnBackground(
    Job* job, const base::MutexGuard& lock) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.LazyCompilerDispatcherWaitForBackgroundJob");
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kCompileWaitForDispatcher);

  if (!job->is_running_on_background()) {
    if (job->state == Job::State::kPending) {
      DCHECK_EQ(std::count(pending_background_jobs_.begin(),
                           pending_background_jobs_.end(), job),
                1);

      // TODO(leszeks): Remove from pending jobs without walking the whole
      // vector.
      pending_background_jobs_.erase(
          std::remove(pending_background_jobs_.begin(),
                      pending_background_jobs_.end(), job),
          pending_background_jobs_.end());
      job->state = Job::State::kPendingToRunOnForeground;
      NotifyRemovedBackgroundJob(lock);
    } else {
      DCHECK_EQ(job->state, Job::State::kReadyToFinalize);
      DCHECK_EQ(
          std::count(finalizable_jobs_.begin(), finalizable_jobs_.end(), job),
          1);

      // TODO(leszeks): Remove from finalizable jobs without walking the whole
      // vector.
      finalizable_jobs_.erase(
          std::remove(finalizable_jobs_.begin(), finalizable_jobs_.end(), job),
          finalizable_jobs_.end());
      job->state = Job::State::kFinalizingNow;
    }
    return;
  }
  DCHECK_NULL(main_thread_blocking_on_job_);
  main_thread_blocking_on_job_ = job;
  while (main_thread_blocking_on_job_ != nullptr) {
    main_thread_blocking_signal_.Wait(&mutex_);
  }

  DCHECK_EQ(job->state, Job::State::kReadyToFinalize);
  DCHECK_EQ(std::count(finalizable_jobs_.begin(), finalizable_jobs_.end(), job),
            1);

  // TODO(leszeks): Remove from finalizable jobs without walking the whole
  // vector.
  finalizable_jobs_.erase(
      std::remove(finalizable_jobs_.begin(), finalizable_jobs_.end(), job),
      finalizable_jobs_.end());
  job->state = Job::State::kFinalizingNow;
}

bool LazyCompileDispatcher::FinishNow(
    DirectHandle<SharedFunctionInfo> function) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.LazyCompilerDispatcherFinishNow");
  RCS_SCOPE(isolate_, RuntimeCallCounterId::kCompileFinishNowOnDispatcher);
  if (trace_compiler_dispatcher_) {
    PrintF("LazyCompileDispatcher: finishing ");
    ShortPrint(*function);
    PrintF(" now\n");
  }

  Job* job;

  {
    base::MutexGuard lock(&mutex_);
    job = GetJobFor(function, lock);
    WaitForJobIfRunningOnBackground(job, lock);
  }

  if (job->state == Job::State::kPendingToRunOnForeground) {
    job->task->RunOnMainThread(isolate_);
    job->state = Job::State::kFinalizingNow;
  }

  if (DEBUG_BOOL) {
    base::MutexGuard lock(&mutex_);
    DCHECK_EQ(std::count(pending_background_jobs_.begin(),
                         pending_background_jobs_.end(), job),
              0);
    DCHECK_EQ(
        std::count(finalizable_jobs_.begin(), finalizable_jobs_.end(), job), 0);
    DCHECK_EQ(job->state, Job::State::kFinalizingNow);
  }

  bool success = Compiler::FinalizeBackgroundCompileTask(
      job->task.get(), isolate_, Compiler::KEEP_EXCEPTION);
  job->state = Job::State::kFinalized;

  DCHECK_NE(success, isolate_->has_exception());
  DeleteJob(job);

  // Opportunistically finalize all other jobs for a maximum time of
  // kMaxOpportunisticFinalizeTimeMs.
  double deadline_in_seconds = platform_->MonotonicallyIncreasingTime() +
                               kMaxOpportunisticFinalizeTimeMs / 1000.0;
  while (deadline_in_seconds > platform_->MonotonicallyIncreasingTime()) {
    if (!FinalizeSingleJob()) break;
  }

  return success;
}

void LazyCompileDispatcher::AbortJob(
    DirectHandle<SharedFunctionInfo> shared_info) {
  if (trace_compiler_dispatcher_) {
    PrintF("LazyCompileDispatcher: aborting job for ");
    ShortPrint(*shared_info);
    PrintF("\n");
  }
  base::LockGuard<base::Mutex> lock(&mutex_);

  Job* job = GetJobFor(shared_info, lock);
  if (job->is_running_on_background()) {
    // Job is currently running on the background thread, wait until it's done
    // and remove job then.
    job->state = Job::State::kAbortRequested;
  } else {
    if (job->state == Job::State::kPending) {
      DCHECK_EQ(std::count(pending_background_jobs_.begin(),
                           pending_background_jobs_.end(), job),
                1);

      pending_background_jobs_.erase(
          std::remove(pending_background_jobs_.begin(),
                      pending_background_jobs_.end(), job),
          pending_background_jobs_.end());
      job->state = Job::State::kAbortingNow;
      NotifyRemovedBackgroundJob(lock);
    } else if (job->state == Job::State::kReadyToFinalize) {
      DCHECK_EQ(
          std::count(finalizable_jobs_.begin(), finalizable_jobs_.end(), job),
          1);

      finalizable_jobs_.erase(
          std::remove(finalizable_jobs_.begin(), finalizable_jobs_.end(), job),
          finalizable_jobs_.end());
      job->state = Job::State::kAbortingNow;
    } else {
      UNREACHABLE();
    }
    job->task->AbortFunction();
    job->state = Job::State::kFinalized;
    DeleteJob(job, lock);
  }
}

void LazyCompileDispatcher::AbortAll() {
  idle_task_manager_->TryAbortAll();
  job_handle_->Cancel();

  {
    base::MutexGuard lock(&mutex_);
    for (Job* job : pending_background_jobs_) {
      job->task->AbortFunction();
      job->state = Job::State::kFinalized;
      DeleteJob(job, lock);
    }
    pending_background_jobs_.clear();
    for (Job* job : finalizable_jobs_) {
      job->task->AbortFunction();
      job->state = Job::State::kFinalized;
      DeleteJob(job, lock);
    }
    finalizable_jobs_.clear();
    for (Job* job : jobs_to_dispose_) {
      delete job;
    }
    jobs_to_dispose_.clear();

    DCHECK_EQ(all_jobs_.size(), 0);
    num_jobs_for_background_ = 0;
    VerifyBackgroundTaskCount(lock);
  }

  idle_task_manager_->CancelAndWait();
}

LazyCompileDispatcher::Job* LazyCompileDispatcher::GetJobFor(
    DirectHandle<SharedFunctionInfo> shared, const base::MutexGuard&) const {
  if (!shared->HasUncompiledData()) return nullptr;
  Tagged<UncompiledData> data = shared->uncompiled_data(isolate_);
  if (IsUncompiledDataWithPreparseDataAndJob(data)) {
    return reinterpret_cast<Job*>(
        Cast<UncompiledDataWithPreparseDataAndJob>(data)->job());
  } else if (IsUncompiledDataWithoutPreparseDataWithJob(data)) {
    return reinterpret_cast<Job*>(
        Cast<UncompiledDataWithoutPreparseDataWithJob>(data)->job());
  }
  return nullptr;
}

void LazyCompileDispatcher::ScheduleIdleTaskFromAnyThread(
    const base::MutexGuard&) {
  if (!taskrunner_->IdleTasksEnabled()) return;
  if (idle_task_scheduled_) return;

  idle_task_scheduled_ = true;
  // TODO(leszeks): Using a full task manager for a single cancellable task is
  // overkill, we could probably do the cancelling ourselves.
  taskrunner_->PostIdleTask(MakeCancelableIdleTask(
      idle_task_manager_.get(),
      [this](double deadline_in_seconds) { DoIdleWork(deadline_in_seconds); }));
}

void LazyCompileDispatcher::DoBackgroundWork(JobDelegate* delegate) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.LazyCompileDispatcherDoBackgroundWork");

  LocalIsolate isolate(isolate_, ThreadKind::kBackground);
  UnparkedScope unparked_scope(&isolate);
  LocalHandleScope handle_scope(&isolate);

  ReusableUnoptimizedCompileState reusable_state(&isolate);

  while (true) {
    // Return immediately on yield, avoiding the second loop.
    if (delegate->ShouldYield()) return;

    Job* job = nullptr;
    {
      base::MutexGuard lock(&mutex_);

      if (pending_background_jobs_.empty()) break;
      job = pending_background_jobs_.back();
      pending_background_jobs_.pop_back();
      DCHECK_EQ(job->state, Job::State::kPending);

      job->state = Job::State::kRunning;
    }

    if (V8_UNLIKELY(block_for_testing_.Value())) {
      block_for_testing_.SetValue(false);
      semaphore_for_testing_.Wait();
    }

    if (trace_compiler_dispatcher_) {
      PrintF("LazyCompileDispatcher: doing background work\n");
    }

    job->task->Run(&isolate, &reusable_state);

    {
      base::MutexGuard lock(&mutex_);
      if (job->state == Job::State::kRunning) {
        job->state = Job::State::kReadyToFinalize;
        // Schedule an idle task to finalize the compilation on the main thread
        // if the job has a shared function info registered.
      } else {
        DCHECK_EQ(job->state, Job::State::kAbortRequested);
        job->state = Job::State::kAborted;
      }
      finalizable_jobs_.push_back(job);
      NotifyRemovedBackgroundJob(lock);

      if (main_thread_blocking_on_job_ == job) {
        main_thread_blocking_on_job_ = nullptr;
        main_thread_blocking_signal_.NotifyOne();
      } else {
        ScheduleIdleTaskFromAnyThread(lock);
      }
    }
  }

  while (!delegate->ShouldYield()) {
    Job* job = nullptr;
    {
      base::MutexGuard lock(&mutex_);
      if (jobs_to_dispose_.empty()) break;
      job = jobs_to_dispose_.back();
      jobs_to_dispose_.pop_back();
      if (jobs_to_dispose_.empty()) {
        num_jobs_for_background_--;
      }
    }
    delete job;
  }

  // Don't touch |this| anymore after this point, as it might have been
  // deleted.
}

LazyCompileDispatcher::Job* LazyCompileDispatcher::PopSingleFinalizeJob() {
  base::MutexGuard lock(&mutex_);

  if (finalizable_jobs_.empty()) return nullptr;

  Job* job = finalizable_jobs_.back();
  finalizable_jobs_.pop_back();
  DCHECK(job->state == Job::State::kReadyToFinalize ||
         job->state == Job::State::kAborted);
  if (job->state == Job::State::kReadyToFinalize) {
    job->state = Job::State::kFinalizingNow;
  } else {
    DCHECK_EQ(job->state, Job::State::kAborted);
    job->state = Job::State::kAbortingNow;
  }
  return job;
}

bool LazyCompileDispatcher::FinalizeSingleJob() {
  Job* job = PopSingleFinalizeJob();
  if (job == nullptr) return false;

  if (trace_compiler_dispatcher_) {
    PrintF("LazyCompileDispatcher: idle finalizing job\n");
  }

  if (job->state == Job::State::kFinalizingNow) {
    HandleScope scope(isolate_);
    Compiler::FinalizeBackgroundCompileTask(job->task.get(), isolate_,
                                            Compiler::CLEAR_EXCEPTION);
  } else {
    DCHECK_EQ(job->state, Job::State::kAbortingNow);
    job->task->AbortFunction();
  }
  job->state = Job::State::kFinalized;
  DeleteJob(job);
  return true;
}

void LazyCompileDispatcher::DoIdleWork(double deadline_in_seconds) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.compile"),
               "V8.LazyCompilerDispatcherDoIdleWork");
  {
    base::MutexGuard lock(&mutex_);
    idle_task_scheduled_ = false;
  }

  if (trace_compiler_dispatcher_) {
    PrintF("LazyCompileDispatcher: received %0.1lfms of idle time\n",
           (deadline_in_seconds - platform_->MonotonicallyIncreasingTime()) *
               static_cast<double>(base::Time::kMillisecondsPerSecond));
  }
  while (deadline_in_seconds > platform_->MonotonicallyIncreasingTime()) {
    // Find a job which is pending finalization and has a shared function info
    auto there_was_a_job = FinalizeSingleJob();
    if (!there_was_a_job) return;
  }

  // We didn't return above so there still might be jobs to finalize.
  {
    base::MutexGuard lock(&mutex_);
    ScheduleIdleTaskFromAnyThread(lock);
  }
}

void LazyCompileDispatcher::DeleteJob(Job* job) {
  DCHECK(job->state == Job::State::kFinalized);
  base::MutexGuard lock(&mutex_);
  DeleteJob(job, lock);
}

void LazyCompileDispatcher::DeleteJob(Job* job, const base::MutexGuard&) {
  DCHECK(job->state == Job::State::kFinalized);
#ifdef DEBUG
  all_jobs_.erase(job);
#endif
  jobs_to_dispose_.push_back(job);
  if (jobs_to_dispose_.size() == 1) {
    num_jobs_for_background_++;
  }
}

#ifdef DEBUG
void LazyCompileDispatcher::VerifyBackgroundTaskCount(const base::MutexGuard&) {
  size_t pending_jobs = 0;
  size_t running_jobs = 0;
  size_t finalizable_jobs = 0;

  for (Job* job : all_jobs_) {
    switch (job->state) {
      case Job::State::kPending:
        pending_jobs++;
        break;
      case Job::State::kRunning:
      case Job::State::kAbortRequested:
        running_jobs++;
        break;
      case Job::State::kReadyToFinalize:
      case Job::State::kAborted:
        finalizable_jobs++;
        break;
      case Job::State::kPendingToRunOnForeground:
      case Job::State::kFinalizingNow:
      case Job::State::kAbortingNow:
      case Job::State::kFinalized:
        // Ignore.
        break;
    }
  }

  CHECK_EQ(pending_background_jobs_.size(), pending_jobs);
  CHECK_EQ(finalizable_jobs_.size(), finalizable_jobs);
  CHECK_EQ(num_jobs_for_background_.load(),
           pending_jobs + running_jobs + (jobs_to_dispose_.empty() ? 0 : 1));
}
#endif

}  // namespace internal
}  // namespace v8
```