Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understanding the Core Request:** The request asks for the functionality of the `LazyCompileDispatcher` class in V8, treating the provided code as the primary source of truth. It also asks about Torque, JavaScript relevance, code logic, and potential user errors.

2. **Initial Skim and Keyword Spotting:** The first step is a quick read-through to identify key terms and patterns. Keywords like "compile," "background," "task," "job," "thread," "mutex," "idle," "SharedFunctionInfo," and "UncompiledData" immediately stand out. The class name itself, `LazyCompileDispatcher`, strongly suggests its purpose: managing compilation in a lazy, dispatch-based manner.

3. **Identifying the Main Actors:**  From the keywords, I can infer the main components involved:
    * **Jobs:** Represent individual compilation tasks. The `Job` struct and `BackgroundCompileTask` are obvious indicators.
    * **Dispatcher:** The `LazyCompileDispatcher` itself, responsible for managing and scheduling these jobs.
    * **Threads:** Background threads for performing compilation and the main thread for finalization. The mention of `Platform`, `TaskRunner`, and mutexes supports this.
    * **SharedFunctionInfo and UncompiledData:**  These V8 structures are central to representing JavaScript functions and their compilation status.

4. **Tracing the Workflow (High-Level):** Based on the identified actors, I can start to map out the general flow:
    * A JavaScript function needs to be compiled.
    * The `LazyCompileDispatcher` receives a request (via `Enqueue`).
    * A `Job` is created and associated with the function's `SharedFunctionInfo`.
    * The actual compilation is offloaded to a background thread.
    * The main thread can either wait for compilation (`FinishNow`) or the compilation can complete in the background and be finalized later during idle time (`DoIdleWork`).

5. **Analyzing Key Methods:**  Next, I examine the key methods to understand their specific roles:
    * **`Enqueue`:**  Adds a new compilation job to the queue, linking it to the `SharedFunctionInfo`. The logic around `SetUncompiledDataJobPointer` is important for understanding how the job is tracked.
    * **`DoBackgroundWork`:** The main loop for background compilation. It pulls jobs from the queue, runs the compilation task, and then moves them to a "finalizable" state.
    * **`FinishNow`:** Forces immediate completion of a compilation job on the main thread.
    * **`AbortJob`:** Cancels a pending or running compilation job.
    * **`DoIdleWork`:**  Handles finalization of completed jobs during idle time on the main thread.
    * **`GetJobFor` and `IsEnqueued`:** Utility methods for checking the status of a compilation job.

6. **Understanding Synchronization and Threading:** The presence of `mutex_`, `main_thread_blocking_signal_`, and the use of `Platform::PostJob` clearly indicate multi-threading and the need for synchronization to avoid race conditions. The different job states (`kPending`, `kRunning`, `kReadyToFinalize`, etc.) reflect the lifecycle of a background compilation.

7. **Addressing Specific Questions:**  Now, I can address the specific points raised in the request:

    * **Functionality Summary:** Synthesize the information gathered into a concise description of the class's purpose.
    * **Torque:**  Check the file extension (`.cc`). If it were `.tq`, it would be Torque. In this case, it's C++.
    * **JavaScript Relevance:**  Connect the C++ code to its impact on JavaScript execution. The key link is the compilation of JavaScript functions. Provide a simple JavaScript example that would trigger lazy compilation.
    * **Code Logic Reasoning:** Focus on a specific part of the code, like `SetUncompiledDataJobPointer`. Explain the different cases and the reason for the conditional logic (handling existing/missing job slots). Create a hypothetical scenario with inputs and expected outputs to illustrate the logic.
    * **Common Programming Errors:** Think about common mistakes users might make that relate to background compilation. For example, assuming a function is compiled immediately or not handling potential errors during compilation.

8. **Refinement and Structuring:** Finally, organize the information logically, using clear headings and bullet points. Ensure the language is precise and avoids jargon where possible. Review the explanation for clarity and completeness. For example, adding the explanation about `WaitForJobIfRunningOnBackground` adds significant value to understanding the synchronization aspects.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the idle task is about starting new compilations. **Correction:**  Looking closer at `DoIdleWork`, it's primarily about *finalizing* already completed background compilations.
* **Initial thought:** The mutex is just for protecting the job queues. **Correction:** It also protects access to job states and is used for signaling between threads. The `WaitForJobIfRunningOnBackground` method highlights this.
* **Missing detail:** I initially overlooked the significance of `UncompiledData` and its structure. **Correction:**  Realized it's the key to linking the C++ job with the JavaScript function and added explanation about the different `UncompiledData` types.

By following this systematic approach, I can effectively analyze the provided C++ code and generate a comprehensive and accurate explanation that addresses all aspects of the user's request.
好的，让我们来分析一下 `v8/src/compiler-dispatcher/lazy-compile-dispatcher.cc` 这个 V8 源代码文件的功能。

**主要功能:**

`LazyCompileDispatcher` 的主要功能是**延迟（lazy）地将 JavaScript 函数的编译任务调度到后台线程执行**。  这意味着当一个 JavaScript 函数首次被调用时，V8 不会立即在主线程上进行完整的编译，而是将编译任务交给 `LazyCompileDispatcher`，让其在后台线程中进行编译。 这样可以避免在主线程上执行耗时的编译操作，从而提高 JavaScript 程序的启动速度和响应性。

更具体地说，`LazyCompileDispatcher` 负责：

1. **接收编译请求:** 当需要延迟编译一个函数时，V8 会调用 `LazyCompileDispatcher::Enqueue` 方法，将函数的 `SharedFunctionInfo` 和源代码流（`Utf16CharacterStream`）放入队列。
2. **创建和管理后台编译任务:**  `Enqueue` 方法会创建一个 `BackgroundCompileTask` 对象，封装了具体的编译逻辑，并将其包装在一个 `Job` 对象中。
3. **调度到后台线程:**  `LazyCompileDispatcher` 使用 V8 的平台抽象层 (`v8::Platform`) 来创建和管理后台线程上的任务 (`JobTask`)。  这些后台线程会调用 `LazyCompileDispatcher::DoBackgroundWork` 来执行实际的编译任务。
4. **管理任务状态:** `LazyCompileDispatcher` 维护着后台编译任务的状态（例如，`kPending`，`kRunning`，`kReadyToFinalize`，`kFinalized` 等），并使用互斥锁 (`mutex_`) 来确保对这些状态的线程安全访问。
5. **主线程等待与强制编译:**  主线程可以通过 `LazyCompileDispatcher::FinishNow` 方法来强制等待某个函数的后台编译完成。这通常发生在函数即将被执行，但后台编译尚未完成时。
6. **空闲时段的任务处理:**  `LazyCompileDispatcher` 还会利用主线程的空闲时间 (`DoIdleWork`) 来完成已完成的后台编译任务的最终化（finalization）。
7. **任务取消:**  `LazyCompileDispatcher` 提供了 `AbortJob` 和 `AbortAll` 方法来取消正在进行或等待执行的后台编译任务。
8. **性能监控:**  该类还集成了性能监控，例如通过 `RuntimeCallStatsScope` 和性能计数器来跟踪编译相关的事件。

**关于文件后缀 `.tq`:**

如果 `v8/src/compiler-dispatcher/lazy-compile-dispatcher.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用来定义内置函数和运行时函数的领域特定语言。由于该文件后缀是 `.cc`，所以它是一个标准的 C++ 源代码文件。

**与 JavaScript 功能的关系及示例:**

`LazyCompileDispatcher` 的核心功能是优化 JavaScript 代码的执行效率。  它通过将耗时的编译操作移到后台线程，使得主线程可以更快地响应用户交互和其他关键任务。

**JavaScript 示例:**

```javascript
function myFunction() {
  // 一些复杂的计算或者逻辑
  let sum = 0;
  for (let i = 0; i < 1000000; i++) {
    sum += i;
  }
  return sum;
}

// 首次调用 myFunction 时，可能会触发 LazyCompileDispatcher 将其编译任务放入后台。
myFunction();

// 后续调用 myFunction 时，如果后台编译已完成，则会直接执行编译后的代码。
myFunction();
```

在这个例子中，当 `myFunction` 首次被调用时，V8 可能会选择使用 `LazyCompileDispatcher` 在后台编译 `myFunction`。  这样，第一次调用可能会稍微慢一些，因为需要启动后台编译。但是，随后的调用将会更快，因为已经有编译好的代码可以直接执行。

**代码逻辑推理及假设输入与输出:**

让我们关注 `LazyCompileDispatcher::Enqueue` 方法中的 `SetUncompiledDataJobPointer` 函数。

**假设输入:**

* `isolate`: 当前的 V8 隔离区 (Isolate) 对象。
* `shared_info`: 指向需要编译的 JavaScript 函数的 `SharedFunctionInfo` 对象的句柄。这个对象包含了函数的元数据，例如名称和源代码位置。
* `job_address`: 指向为该函数创建的 `Job` 对象的地址。

**代码逻辑:**

`SetUncompiledDataJobPointer` 的目的是将后台编译任务的 `Job` 对象的地址存储到 `SharedFunctionInfo` 的 `UncompiledData` 中。  `UncompiledData` 存储了函数的未编译状态信息。  由于 `UncompiledData` 可能已经包含了预解析数据 (preparse data)，所以需要处理不同的 `UncompiledData` 类型：

* **如果 `UncompiledData` 已经有 job 槽位:** 直接将 `job_address` 写入。
* **如果 `UncompiledData` 没有 job 槽位:**
    * 创建一个新的 `UncompiledData` 对象，该对象包含 job 槽位 (可能也包含预解析数据，取决于原来的 `UncompiledData` 类型)。
    * 将 `job_address` 写入新的 `UncompiledData` 对象。
    * 更新 `SharedFunctionInfo`，使其指向新的 `UncompiledData` 对象。

**假设场景与输出:**

1. **场景 1: `SharedFunctionInfo` 的 `UncompiledData` 没有预解析数据，也没有 job 槽位。**
   * **输入:** `shared_info` 指向一个 `UncompiledDataWithoutPreparseData` 类型的对象。
   * **输出:**  一个新的 `UncompiledDataWithoutPreparseDataWithJob` 对象被创建，`job_address` 被写入，并且 `shared_info` 被更新以指向这个新对象。

2. **场景 2: `SharedFunctionInfo` 的 `UncompiledData` 包含预解析数据，但没有 job 槽位。**
   * **输入:** `shared_info` 指向一个 `UncompiledDataWithPreparseData` 类型的对象。
   * **输出:** 一个新的 `UncompiledDataWithPreparseDataAndJob` 对象被创建（复制了原来的预解析数据），`job_address` 被写入，并且 `shared_info` 被更新以指向这个新对象。

**涉及用户常见的编程错误:**

虽然 `LazyCompileDispatcher` 是 V8 内部的实现细节，但理解其工作原理可以帮助开发者避免一些与性能相关的常见错误：

1. **过早假设代码已编译:** 开发者可能会假设某个函数在首次调用后就立即被完全编译。然而，`LazyCompileDispatcher` 的存在意味着编译可能发生在后台，并在稍后的时间点完成。 如果某些逻辑依赖于编译后的代码的特定行为（虽然这种情况不太常见），可能会出现意外。

2. **在性能关键区域进行大量首次调用的代码:** 如果应用程序在启动或性能关键路径上首次调用大量不同的函数，可能会导致后台编译线程的负载过高，反而影响性能。 最佳实践是预热 (warm-up) 关键代码路径，提前触发这些函数的编译。

3. **不理解 V8 的优化策略:** `LazyCompileDispatcher` 是 V8 优化策略的一部分。开发者应该理解 V8 如何进行代码优化（例如，通过 Crankshaft 和 TurboFan），以便编写更易于 V8 优化的代码。

**总结:**

`v8/src/compiler-dispatcher/lazy-compile-dispatcher.cc` 是 V8 中一个关键的组件，负责将 JavaScript 函数的编译任务调度到后台线程，从而提高应用程序的性能和响应性。理解其工作原理有助于开发者更好地理解 V8 的内部机制，并编写更高效的 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/compiler-dispatcher/lazy-compile-dispatcher.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler-dispatcher/lazy-compile-dispatcher.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```