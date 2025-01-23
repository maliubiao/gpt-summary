Response:
The user wants to understand the functionality of the `v8/include/v8-platform.h` file in the V8 source code. They've provided the first part of the file's content. I need to:

1. **List the functionalities** defined in the provided code snippet.
2. **Check if it's a Torque file**:  Based on the filename ending (`.h` not `.tq`), it's not a Torque file.
3. **Determine if it relates to Javascript**: Analyze the code for concepts related to Javascript execution.
4. **Provide Javascript examples** if there's a connection to Javascript.
5. **Illustrate code logic with examples**: If there are logical parts, give example inputs and expected outputs.
6. **Highlight common programming errors**: Identify potential mistakes users might make when interacting with these functionalities.
7. **Summarize the overall functionality** of this code snippet.

**Functionality Breakdown:**

- **Task Scheduling:** Defines interfaces for `Task` and `IdleTask`, and a `TaskRunner` for scheduling them with different priorities and delays.
- **Job Management:**  Introduces `JobDelegate`, `JobHandle`, and `JobTask` for managing parallelizable work.
- **Blocking Call Handling:** Defines `BlockingType` and `ScopedBlockingCall` to manage sections of code that might block the thread.
- **Tracing:** Provides a `TracingController` to record trace events for debugging and profiling.
- **Memory Management:**  Includes a `PageAllocator` interface for managing memory pages with different permissions, including shared memory.
- **Thread Isolation:** Defines a `ThreadIsolatedAllocator` for per-thread memory protection.
- **Shared Memory Handles:** Defines a type `PlatformSharedMemoryHandle` and related conversion functions for platform-specific shared memory identifiers.
- **Virtual Address Space Management:** Introduces the `VirtualAddressSpace` class for managing a region of virtual memory with functionalities for allocating private and shared memory, setting permissions, and managing guard regions.

Based on this analysis, the file provides core platform abstraction interfaces for V8.
这是 `v8/include/v8-platform.h` 的第一部分代码，它定义了 V8 引擎与底层平台交互所需的一系列抽象接口。以下是它的主要功能归纳：

**主要功能:**

1. **任务调度 (Task Scheduling):**
   - 定义了 `Task` 接口，表示一个待执行的工作单元。
   - 定义了 `IdleTask` 接口，表示空闲时执行的工作单元，带有执行截止时间参数。
   - 定义了 `TaskRunner` 接口，用于调度 `Task` 和 `IdleTask` 的执行。它允许以不同的方式发布任务，例如立即执行、延迟执行、在空闲时执行以及是否允许嵌套执行。
   - 定义了 `TaskPriority` 枚举，表示任务的不同优先级。

2. **并行任务管理 (Job Management):**
   - 定义了 `JobTask` 接口，表示可以并行执行的工作单元。
   - 定义了 `JobDelegate` 接口，用于在 `JobTask` 中与调度器通信，例如检查是否应该让出 CPU、通知并发增加等。
   - 定义了 `JobHandle` 接口，用于控制 `JobTask` 的执行，例如通知并发增加、等待任务完成、取消任务等。

3. **阻塞调用处理 (Blocking Call Handling):**
   - 定义了 `BlockingType` 枚举，表示阻塞调用的可能性。
   - 定义了 `ScopedBlockingCall` 类，用于标记可能阻塞线程的代码区域，允许平台进行优化。

4. **追踪 (Tracing):**
   - 定义了 `ConvertableToTraceFormat` 接口，用于将复杂参数转换为追踪事件的格式。
   - 定义了 `TracingController` 类，允许嵌入器记录 V8 的追踪事件。

5. **内存管理 (Memory Management):**
   - 定义了 `PageAllocator` 类，用于抽象底层平台的内存页分配和管理，包括分配、释放、设置权限等操作，并支持共享内存。
   - 定义了 `ThreadIsolatedAllocator` 类，用于提供线程隔离的内存分配器。
   - 定义了 `PlatformSharedMemoryHandle` 类型，用于表示平台相关的共享内存句柄，并提供了不同平台句柄类型之间的转换函数。
   - 定义了 `PagePermissions` 枚举，表示内存页的权限。
   - 定义了 `VirtualAddressSpace` 类，用于管理虚拟内存地址空间，提供更细粒度的内存管理功能，包括分配私有和共享内存、设置权限和管理保护区域。

**关于文件类型和 JavaScript 关系:**

- 文件名 `v8-platform.h` 以 `.h` 结尾，这表明它是一个 C++ 头文件，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。

- `v8/include/v8-platform.h` 文件定义了 V8 引擎与底层操作系统或嵌入环境交互的抽象层。虽然它本身不是 JavaScript 代码，但其中定义的功能与 JavaScript 的执行息息相关。例如：
    - **任务调度:** JavaScript 中的 `setTimeout`, `setInterval`, `requestAnimationFrame` 等异步操作的底层实现可能依赖于 `TaskRunner` 提供的任务调度机制。
    - **并行任务:**  JavaScript 的 Web Workers 或 SharedArrayBuffer 等功能可能利用了 `JobTask` 来执行并行计算。
    - **内存管理:** V8 引擎的垃圾回收、堆内存分配等操作会使用 `PageAllocator` 来与操作系统进行内存交互。

**JavaScript 示例 (与任务调度相关):**

```javascript
// 假设 V8 内部使用 TaskRunner 来处理 setTimeout
console.log("开始");

setTimeout(() => {
  console.log("延迟 1 秒后执行");
}, 1000);

console.log("继续执行");
```

在这个例子中，`setTimeout` 的回调函数会被封装成一个 `Task`，然后通过 V8 内部的 `TaskRunner` 调度，在 1 秒后执行。虽然 JavaScript 代码本身不直接操作 `TaskRunner`，但 V8 引擎的实现会利用这些底层的平台接口。

**代码逻辑推理 (以 TaskRunner 为例):**

**假设输入:**
- 一个 `TaskRunner` 实例 `runner`。
- 一个 `Task` 实例 `myTask`，其 `Run()` 方法会打印 "Task executed"。

**操作:**
```c++
std::unique_ptr<Task> myTask = std::make_unique<class : public Task {
 public:
  void Run() override {
    // 在实际 V8 内部，这会调用 JavaScript 代码
    printf("Task executed\n");
  }
};
runner->PostTask(std::move(myTask));
```

**预期输出:**
当 `runner` 执行其队列中的任务时，控制台会打印 "Task executed"。

**用户常见的编程错误 (可能与嵌入 V8 相关):**

1. **在不合适的线程中调用 V8 API:** V8 的某些操作只能在特定的线程中执行 (例如，Isolate 的操作通常需要在创建它的线程中进行)。如果嵌入程序不正确地管理线程，可能会导致崩溃或其他未定义的行为。例如，在一个由 `TaskRunner` 调度的任务中直接访问另一个 Isolate 的数据而没有适当的同步机制。

2. **错误地管理 Task 的生命周期:**  `TaskRunner::PostTask` 会接管 `Task` 的所有权。用户不应该在 `PostTask` 后继续持有和操作该 `Task` 指针。

3. **不理解任务的执行顺序和优先级:**  不同类型的任务 (例如，普通任务、延迟任务、空闲任务) 可能有不同的执行顺序和优先级。如果嵌入程序对任务的执行时机有严格的要求，需要仔细考虑使用哪种 `PostTask` 方法。

**总结:**

`v8/include/v8-platform.h` 的第一部分定义了 V8 与底层平台交互的关键抽象接口，涵盖了任务调度、并行任务管理、阻塞调用处理、追踪和内存管理等核心功能。这些接口使得 V8 能够以平台无关的方式利用底层系统的资源，并为 JavaScript 代码的执行提供必要的支持。 嵌入 V8 的程序需要理解这些接口，以便正确地配置和集成 V8 引擎。

### 提示词
```
这是目录为v8/include/v8-platform.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-platform.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_V8_PLATFORM_H_
#define V8_V8_PLATFORM_H_

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>  // For abort.

#include <memory>
#include <string>

#include "v8-source-location.h"  // NOLINT(build/include_directory)
#include "v8config.h"            // NOLINT(build/include_directory)

namespace v8 {

class Isolate;

// Valid priorities supported by the task scheduling infrastructure.
enum class TaskPriority : uint8_t {
  /**
   * Best effort tasks are not critical for performance of the application. The
   * platform implementation should preempt such tasks if higher priority tasks
   * arrive.
   */
  kBestEffort,
  /**
   * User visible tasks are long running background tasks that will
   * improve performance and memory usage of the application upon completion.
   * Example: background compilation and garbage collection.
   */
  kUserVisible,
  /**
   * User blocking tasks are highest priority tasks that block the execution
   * thread (e.g. major garbage collection). They must be finished as soon as
   * possible.
   */
  kUserBlocking,
  kMaxPriority = kUserBlocking
};

/**
 * A Task represents a unit of work.
 */
class Task {
 public:
  virtual ~Task() = default;

  virtual void Run() = 0;
};

/**
 * An IdleTask represents a unit of work to be performed in idle time.
 * The Run method is invoked with an argument that specifies the deadline in
 * seconds returned by MonotonicallyIncreasingTime().
 * The idle task is expected to complete by this deadline.
 */
class IdleTask {
 public:
  virtual ~IdleTask() = default;
  virtual void Run(double deadline_in_seconds) = 0;
};

/**
 * A TaskRunner allows scheduling of tasks. The TaskRunner may still be used to
 * post tasks after the isolate gets destructed, but these tasks may not get
 * executed anymore. All tasks posted to a given TaskRunner will be invoked in
 * sequence. Tasks can be posted from any thread.
 */
class TaskRunner {
 public:
  /**
   * Schedules a task to be invoked by this TaskRunner. The TaskRunner
   * implementation takes ownership of |task|.
   *
   * Embedders should override PostTaskImpl instead of this.
   */
  void PostTask(std::unique_ptr<Task> task,
                const SourceLocation& location = SourceLocation::Current()) {
    PostTaskImpl(std::move(task), location);
  }

  /**
   * Schedules a task to be invoked by this TaskRunner. The TaskRunner
   * implementation takes ownership of |task|. The |task| cannot be nested
   * within other task executions.
   *
   * Tasks which shouldn't be interleaved with JS execution must be posted with
   * |PostNonNestableTask| or |PostNonNestableDelayedTask|. This is because the
   * embedder may process tasks in a callback which is called during JS
   * execution.
   *
   * In particular, tasks which execute JS must be non-nestable, since JS
   * execution is not allowed to nest.
   *
   * Requires that |TaskRunner::NonNestableTasksEnabled()| is true.
   *
   * Embedders should override PostNonNestableTaskImpl instead of this.
   */
  void PostNonNestableTask(
      std::unique_ptr<Task> task,
      const SourceLocation& location = SourceLocation::Current()) {
    PostNonNestableTaskImpl(std::move(task), location);
  }

  /**
   * Schedules a task to be invoked by this TaskRunner. The task is scheduled
   * after the given number of seconds |delay_in_seconds|. The TaskRunner
   * implementation takes ownership of |task|.
   *
   * Embedders should override PostDelayedTaskImpl instead of this.
   */
  void PostDelayedTask(
      std::unique_ptr<Task> task, double delay_in_seconds,
      const SourceLocation& location = SourceLocation::Current()) {
    PostDelayedTaskImpl(std::move(task), delay_in_seconds, location);
  }

  /**
   * Schedules a task to be invoked by this TaskRunner. The task is scheduled
   * after the given number of seconds |delay_in_seconds|. The TaskRunner
   * implementation takes ownership of |task|. The |task| cannot be nested
   * within other task executions.
   *
   * Tasks which shouldn't be interleaved with JS execution must be posted with
   * |PostNonNestableTask| or |PostNonNestableDelayedTask|. This is because the
   * embedder may process tasks in a callback which is called during JS
   * execution.
   *
   * In particular, tasks which execute JS must be non-nestable, since JS
   * execution is not allowed to nest.
   *
   * Requires that |TaskRunner::NonNestableDelayedTasksEnabled()| is true.
   *
   * Embedders should override PostNonNestableDelayedTaskImpl instead of this.
   */
  void PostNonNestableDelayedTask(
      std::unique_ptr<Task> task, double delay_in_seconds,
      const SourceLocation& location = SourceLocation::Current()) {
    PostNonNestableDelayedTaskImpl(std::move(task), delay_in_seconds, location);
  }

  /**
   * Schedules an idle task to be invoked by this TaskRunner. The task is
   * scheduled when the embedder is idle. Requires that
   * |TaskRunner::IdleTasksEnabled()| is true. Idle tasks may be reordered
   * relative to other task types and may be starved for an arbitrarily long
   * time if no idle time is available. The TaskRunner implementation takes
   * ownership of |task|.
   *
   * Embedders should override PostIdleTaskImpl instead of this.
   */
  void PostIdleTask(
      std::unique_ptr<IdleTask> task,
      const SourceLocation& location = SourceLocation::Current()) {
    PostIdleTaskImpl(std::move(task), location);
  }

  /**
   * Returns true if idle tasks are enabled for this TaskRunner.
   */
  virtual bool IdleTasksEnabled() = 0;

  /**
   * Returns true if non-nestable tasks are enabled for this TaskRunner.
   */
  virtual bool NonNestableTasksEnabled() const { return false; }

  /**
   * Returns true if non-nestable delayed tasks are enabled for this TaskRunner.
   */
  virtual bool NonNestableDelayedTasksEnabled() const { return false; }

  TaskRunner() = default;
  virtual ~TaskRunner() = default;

  TaskRunner(const TaskRunner&) = delete;
  TaskRunner& operator=(const TaskRunner&) = delete;

 protected:
  /**
   * Implementation of above methods with an additional `location` argument.
   */
  virtual void PostTaskImpl(std::unique_ptr<Task> task,
                            const SourceLocation& location) {}
  virtual void PostNonNestableTaskImpl(std::unique_ptr<Task> task,
                                       const SourceLocation& location) {}
  virtual void PostDelayedTaskImpl(std::unique_ptr<Task> task,
                                   double delay_in_seconds,
                                   const SourceLocation& location) {}
  virtual void PostNonNestableDelayedTaskImpl(std::unique_ptr<Task> task,
                                              double delay_in_seconds,
                                              const SourceLocation& location) {}
  virtual void PostIdleTaskImpl(std::unique_ptr<IdleTask> task,
                                const SourceLocation& location) {}
};

/**
 * Delegate that's passed to Job's worker task, providing an entry point to
 * communicate with the scheduler.
 */
class JobDelegate {
 public:
  /**
   * Returns true if this thread *must* return from the worker task on the
   * current thread ASAP. Workers should periodically invoke ShouldYield (or
   * YieldIfNeeded()) as often as is reasonable.
   * After this method returned true, ShouldYield must not be called again.
   */
  virtual bool ShouldYield() = 0;

  /**
   * Notifies the scheduler that max concurrency was increased, and the number
   * of worker should be adjusted accordingly. See Platform::PostJob() for more
   * details.
   */
  virtual void NotifyConcurrencyIncrease() = 0;

  /**
   * Returns a task_id unique among threads currently running this job, such
   * that GetTaskId() < worker count. To achieve this, the same task_id may be
   * reused by a different thread after a worker_task returns.
   */
  virtual uint8_t GetTaskId() = 0;

  /**
   * Returns true if the current task is called from the thread currently
   * running JobHandle::Join().
   */
  virtual bool IsJoiningThread() const = 0;
};

/**
 * Handle returned when posting a Job. Provides methods to control execution of
 * the posted Job.
 */
class JobHandle {
 public:
  virtual ~JobHandle() = default;

  /**
   * Notifies the scheduler that max concurrency was increased, and the number
   * of worker should be adjusted accordingly. See Platform::PostJob() for more
   * details.
   */
  virtual void NotifyConcurrencyIncrease() = 0;

  /**
   * Contributes to the job on this thread. Doesn't return until all tasks have
   * completed and max concurrency becomes 0. When Join() is called and max
   * concurrency reaches 0, it should not increase again. This also promotes
   * this Job's priority to be at least as high as the calling thread's
   * priority.
   */
  virtual void Join() = 0;

  /**
   * Forces all existing workers to yield ASAP. Waits until they have all
   * returned from the Job's callback before returning.
   */
  virtual void Cancel() = 0;

  /*
   * Forces all existing workers to yield ASAP but doesn’t wait for them.
   * Warning, this is dangerous if the Job's callback is bound to or has access
   * to state which may be deleted after this call.
   */
  virtual void CancelAndDetach() = 0;

  /**
   * Returns true if there's any work pending or any worker running.
   */
  virtual bool IsActive() = 0;

  /**
   * Returns true if associated with a Job and other methods may be called.
   * Returns false after Join() or Cancel() was called. This may return true
   * even if no workers are running and IsCompleted() returns true
   */
  virtual bool IsValid() = 0;

  /**
   * Returns true if job priority can be changed.
   */
  virtual bool UpdatePriorityEnabled() const { return false; }

  /**
   *  Update this Job's priority.
   */
  virtual void UpdatePriority(TaskPriority new_priority) {}
};

/**
 * A JobTask represents work to run in parallel from Platform::PostJob().
 */
class JobTask {
 public:
  virtual ~JobTask() = default;

  virtual void Run(JobDelegate* delegate) = 0;

  /**
   * Controls the maximum number of threads calling Run() concurrently, given
   * the number of threads currently assigned to this job and executing Run().
   * Run() is only invoked if the number of threads previously running Run() was
   * less than the value returned. In general, this should return the latest
   * number of incomplete work items (smallest unit of work) left to process,
   * including items that are currently in progress. |worker_count| is the
   * number of threads currently assigned to this job which some callers may
   * need to determine their return value. Since GetMaxConcurrency() is a leaf
   * function, it must not call back any JobHandle methods.
   */
  virtual size_t GetMaxConcurrency(size_t worker_count) const = 0;
};

/**
 * A "blocking call" refers to any call that causes the calling thread to wait
 * off-CPU. It includes but is not limited to calls that wait on synchronous
 * file I/O operations: read or write a file from disk, interact with a pipe or
 * a socket, rename or delete a file, enumerate files in a directory, etc.
 * Acquiring a low contention lock is not considered a blocking call.
 */

/**
 * BlockingType indicates the likelihood that a blocking call will actually
 * block.
 */
enum class BlockingType {
  // The call might block (e.g. file I/O that might hit in memory cache).
  kMayBlock,
  // The call will definitely block (e.g. cache already checked and now pinging
  // server synchronously).
  kWillBlock
};

/**
 * This class is instantiated with CreateBlockingScope() in every scope where a
 * blocking call is made and serves as a precise annotation of the scope that
 * may/will block. May be implemented by an embedder to adjust the thread count.
 * CPU usage should be minimal within that scope. ScopedBlockingCalls can be
 * nested.
 */
class ScopedBlockingCall {
 public:
  virtual ~ScopedBlockingCall() = default;
};

/**
 * The interface represents complex arguments to trace events.
 */
class ConvertableToTraceFormat {
 public:
  virtual ~ConvertableToTraceFormat() = default;

  /**
   * Append the class info to the provided |out| string. The appended
   * data must be a valid JSON object. Strings must be properly quoted, and
   * escaped. There is no processing applied to the content after it is
   * appended.
   */
  virtual void AppendAsTraceFormat(std::string* out) const = 0;
};

/**
 * V8 Tracing controller.
 *
 * Can be implemented by an embedder to record trace events from V8.
 *
 * Will become obsolete in Perfetto SDK build (v8_use_perfetto = true).
 */
class TracingController {
 public:
  virtual ~TracingController() = default;

  // In Perfetto mode, trace events are written using Perfetto's Track Event
  // API directly without going through the embedder. However, it is still
  // possible to observe tracing being enabled and disabled.
#if !defined(V8_USE_PERFETTO)
  /**
   * Called by TRACE_EVENT* macros, don't call this directly.
   * The name parameter is a category group for example:
   * TRACE_EVENT0("v8,parse", "V8.Parse")
   * The pointer returned points to a value with zero or more of the bits
   * defined in CategoryGroupEnabledFlags.
   **/
  virtual const uint8_t* GetCategoryGroupEnabled(const char* name) {
    static uint8_t no = 0;
    return &no;
  }

  /**
   * Adds a trace event to the platform tracing system. These function calls are
   * usually the result of a TRACE_* macro from trace-event-no-perfetto.h when
   * tracing and the category of the particular trace are enabled. It is not
   * advisable to call these functions on their own; they are really only meant
   * to be used by the trace macros. The returned handle can be used by
   * UpdateTraceEventDuration to update the duration of COMPLETE events.
   */
  virtual uint64_t AddTraceEvent(
      char phase, const uint8_t* category_enabled_flag, const char* name,
      const char* scope, uint64_t id, uint64_t bind_id, int32_t num_args,
      const char** arg_names, const uint8_t* arg_types,
      const uint64_t* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* arg_convertables,
      unsigned int flags) {
    return 0;
  }
  virtual uint64_t AddTraceEventWithTimestamp(
      char phase, const uint8_t* category_enabled_flag, const char* name,
      const char* scope, uint64_t id, uint64_t bind_id, int32_t num_args,
      const char** arg_names, const uint8_t* arg_types,
      const uint64_t* arg_values,
      std::unique_ptr<ConvertableToTraceFormat>* arg_convertables,
      unsigned int flags, int64_t timestamp) {
    return 0;
  }

  /**
   * Sets the duration field of a COMPLETE trace event. It must be called with
   * the handle returned from AddTraceEvent().
   **/
  virtual void UpdateTraceEventDuration(const uint8_t* category_enabled_flag,
                                        const char* name, uint64_t handle) {}
#endif  // !defined(V8_USE_PERFETTO)

  class TraceStateObserver {
   public:
    virtual ~TraceStateObserver() = default;
    virtual void OnTraceEnabled() = 0;
    virtual void OnTraceDisabled() = 0;
  };

  /**
   * Adds tracing state change observer.
   * Does nothing in Perfetto SDK build (v8_use_perfetto = true).
   */
  virtual void AddTraceStateObserver(TraceStateObserver*) {}

  /**
   * Removes tracing state change observer.
   * Does nothing in Perfetto SDK build (v8_use_perfetto = true).
   */
  virtual void RemoveTraceStateObserver(TraceStateObserver*) {}
};

/**
 * A V8 memory page allocator.
 *
 * Can be implemented by an embedder to manage large host OS allocations.
 */
class PageAllocator {
 public:
  virtual ~PageAllocator() = default;

  /**
   * Gets the page granularity for AllocatePages and FreePages. Addresses and
   * lengths for those calls should be multiples of AllocatePageSize().
   */
  virtual size_t AllocatePageSize() = 0;

  /**
   * Gets the page granularity for SetPermissions and ReleasePages. Addresses
   * and lengths for those calls should be multiples of CommitPageSize().
   */
  virtual size_t CommitPageSize() = 0;

  /**
   * Sets the random seed so that GetRandomMmapAddr() will generate repeatable
   * sequences of random mmap addresses.
   */
  virtual void SetRandomMmapSeed(int64_t seed) = 0;

  /**
   * Returns a randomized address, suitable for memory allocation under ASLR.
   * The address will be aligned to AllocatePageSize.
   */
  virtual void* GetRandomMmapAddr() = 0;

  /**
   * Memory permissions.
   */
  enum Permission {
    kNoAccess,
    kRead,
    kReadWrite,
    kReadWriteExecute,
    kReadExecute,
    // Set this when reserving memory that will later require kReadWriteExecute
    // permissions. The resulting behavior is platform-specific, currently
    // this is used to set the MAP_JIT flag on Apple Silicon.
    // TODO(jkummerow): Remove this when Wasm has a platform-independent
    // w^x implementation.
    // TODO(saelo): Remove this once all JIT pages are allocated through the
    // VirtualAddressSpace API.
    kNoAccessWillJitLater
  };

  /**
   * Allocates memory in range with the given alignment and permission.
   */
  virtual void* AllocatePages(void* address, size_t length, size_t alignment,
                              Permission permissions) = 0;

  /**
   * Frees memory in a range that was allocated by a call to AllocatePages.
   */
  virtual bool FreePages(void* address, size_t length) = 0;

  /**
   * Releases memory in a range that was allocated by a call to AllocatePages.
   */
  virtual bool ReleasePages(void* address, size_t length,
                            size_t new_length) = 0;

  /**
   * Sets permissions on pages in an allocated range.
   */
  virtual bool SetPermissions(void* address, size_t length,
                              Permission permissions) = 0;

  /**
   * Recommits discarded pages in the given range with given permissions.
   * Discarded pages must be recommitted with their original permissions
   * before they are used again.
   */
  virtual bool RecommitPages(void* address, size_t length,
                             Permission permissions) {
    // TODO(v8:12797): make it pure once it's implemented on Chromium side.
    return false;
  }

  /**
   * Frees memory in the given [address, address + size) range. address and size
   * should be operating system page-aligned. The next write to this
   * memory area brings the memory transparently back. This should be treated as
   * a hint to the OS that the pages are no longer needed. It does not guarantee
   * that the pages will be discarded immediately or at all.
   */
  virtual bool DiscardSystemPages(void* address, size_t size) { return true; }

  /**
   * Decommits any wired memory pages in the given range, allowing the OS to
   * reclaim them, and marks the region as inacessible (kNoAccess). The address
   * range stays reserved and can be accessed again later by changing its
   * permissions. However, in that case the memory content is guaranteed to be
   * zero-initialized again. The memory must have been previously allocated by a
   * call to AllocatePages. Returns true on success, false otherwise.
   */
  virtual bool DecommitPages(void* address, size_t size) = 0;

  /**
   * Block any modifications to the given mapping such as changing permissions
   * or unmapping the pages on supported platforms.
   * The address space reservation will exist until the process ends, but it's
   * possible to release the memory using DiscardSystemPages. Note that this
   * might require write permissions to the page as e.g. on Linux, mseal will
   * block discarding sealed anonymous memory.
   */
  virtual bool SealPages(void* address, size_t length) {
    // TODO(360048056): make it pure once it's implemented on Chromium side.
    return false;
  }

  /**
   * INTERNAL ONLY: This interface has not been stabilised and may change
   * without notice from one release to another without being deprecated first.
   */
  class SharedMemoryMapping {
   public:
    // Implementations are expected to free the shared memory mapping in the
    // destructor.
    virtual ~SharedMemoryMapping() = default;
    virtual void* GetMemory() const = 0;
  };

  /**
   * INTERNAL ONLY: This interface has not been stabilised and may change
   * without notice from one release to another without being deprecated first.
   */
  class SharedMemory {
   public:
    // Implementations are expected to free the shared memory in the destructor.
    virtual ~SharedMemory() = default;
    virtual std::unique_ptr<SharedMemoryMapping> RemapTo(
        void* new_address) const = 0;
    virtual void* GetMemory() const = 0;
    virtual size_t GetSize() const = 0;
  };

  /**
   * INTERNAL ONLY: This interface has not been stabilised and may change
   * without notice from one release to another without being deprecated first.
   *
   * Reserve pages at a fixed address returning whether the reservation is
   * possible. The reserved memory is detached from the PageAllocator and so
   * should not be freed by it. It's intended for use with
   * SharedMemory::RemapTo, where ~SharedMemoryMapping would free the memory.
   */
  virtual bool ReserveForSharedMemoryMapping(void* address, size_t size) {
    return false;
  }

  /**
   * INTERNAL ONLY: This interface has not been stabilised and may change
   * without notice from one release to another without being deprecated first.
   *
   * Allocates shared memory pages. Not all PageAllocators need support this and
   * so this method need not be overridden.
   * Allocates a new read-only shared memory region of size |length| and copies
   * the memory at |original_address| into it.
   */
  virtual std::unique_ptr<SharedMemory> AllocateSharedPages(
      size_t length, const void* original_address) {
    return {};
  }

  /**
   * INTERNAL ONLY: This interface has not been stabilised and may change
   * without notice from one release to another without being deprecated first.
   *
   * If not overridden and changed to return true, V8 will not attempt to call
   * AllocateSharedPages or RemapSharedPages. If overridden, AllocateSharedPages
   * and RemapSharedPages must also be overridden.
   */
  virtual bool CanAllocateSharedPages() { return false; }
};

/**
 * An allocator that uses per-thread permissions to protect the memory.
 *
 * The implementation is platform/hardware specific, e.g. using pkeys on x64.
 *
 * INTERNAL ONLY: This interface has not been stabilised and may change
 * without notice from one release to another without being deprecated first.
 */
class ThreadIsolatedAllocator {
 public:
  virtual ~ThreadIsolatedAllocator() = default;

  virtual void* Allocate(size_t size) = 0;

  virtual void Free(void* object) = 0;

  enum class Type {
    kPkey,
  };

  virtual Type Type() const = 0;

  /**
   * Return the pkey used to implement the thread isolation if Type == kPkey.
   */
  virtual int Pkey() const { return -1; }

  /**
   * Per-thread permissions can be reset on signal handler entry. Even reading
   * ThreadIsolated memory will segfault in that case.
   * Call this function on signal handler entry to ensure that read permissions
   * are restored.
   */
  static void SetDefaultPermissionsForSignalHandler();
};

// Opaque type representing a handle to a shared memory region.
using PlatformSharedMemoryHandle = intptr_t;
static constexpr PlatformSharedMemoryHandle kInvalidSharedMemoryHandle = -1;

// Conversion routines from the platform-dependent shared memory identifiers
// into the opaque PlatformSharedMemoryHandle type. These use the underlying
// types (e.g. unsigned int) instead of the typedef'd ones (e.g. mach_port_t)
// to avoid pulling in large OS header files into this header file. Instead,
// the users of these routines are expected to include the respecitve OS
// headers in addition to this one.
#if V8_OS_DARWIN
// Convert between a shared memory handle and a mach_port_t referencing a memory
// entry object.
inline PlatformSharedMemoryHandle SharedMemoryHandleFromMachMemoryEntry(
    unsigned int port) {
  return static_cast<PlatformSharedMemoryHandle>(port);
}
inline unsigned int MachMemoryEntryFromSharedMemoryHandle(
    PlatformSharedMemoryHandle handle) {
  return static_cast<unsigned int>(handle);
}
#elif V8_OS_FUCHSIA
// Convert between a shared memory handle and a zx_handle_t to a VMO.
inline PlatformSharedMemoryHandle SharedMemoryHandleFromVMO(uint32_t handle) {
  return static_cast<PlatformSharedMemoryHandle>(handle);
}
inline uint32_t VMOFromSharedMemoryHandle(PlatformSharedMemoryHandle handle) {
  return static_cast<uint32_t>(handle);
}
#elif V8_OS_WIN
// Convert between a shared memory handle and a Windows HANDLE to a file mapping
// object.
inline PlatformSharedMemoryHandle SharedMemoryHandleFromFileMapping(
    void* handle) {
  return reinterpret_cast<PlatformSharedMemoryHandle>(handle);
}
inline void* FileMappingFromSharedMemoryHandle(
    PlatformSharedMemoryHandle handle) {
  return reinterpret_cast<void*>(handle);
}
#else
// Convert between a shared memory handle and a file descriptor.
inline PlatformSharedMemoryHandle SharedMemoryHandleFromFileDescriptor(int fd) {
  return static_cast<PlatformSharedMemoryHandle>(fd);
}
inline int FileDescriptorFromSharedMemoryHandle(
    PlatformSharedMemoryHandle handle) {
  return static_cast<int>(handle);
}
#endif

/**
 * Possible permissions for memory pages.
 */
enum class PagePermissions {
  kNoAccess,
  kRead,
  kReadWrite,
  kReadWriteExecute,
  kReadExecute,
};

/**
 * Class to manage a virtual memory address space.
 *
 * This class represents a contiguous region of virtual address space in which
 * sub-spaces and (private or shared) memory pages can be allocated, freed, and
 * modified. This interface is meant to eventually replace the PageAllocator
 * interface, and can be used as an alternative in the meantime.
 *
 * This API is not yet stable and may change without notice!
 */
class VirtualAddressSpace {
 public:
  using Address = uintptr_t;

  VirtualAddressSpace(size_t page_size, size_t allocation_granularity,
                      Address base, size_t size,
                      PagePermissions max_page_permissions)
      : page_size_(page_size),
        allocation_granularity_(allocation_granularity),
        base_(base),
        size_(size),
        max_page_permissions_(max_page_permissions) {}

  virtual ~VirtualAddressSpace() = default;

  /**
   * The page size used inside this space. Guaranteed to be a power of two.
   * Used as granularity for all page-related operations except for allocation,
   * which use the allocation_granularity(), see below.
   *
   * \returns the page size in bytes.
   */
  size_t page_size() const { return page_size_; }

  /**
   * The granularity of page allocations and, by extension, of subspace
   * allocations. This is guaranteed to be a power of two and a multiple of the
   * page_size(). In practice, this is equal to the page size on most OSes, but
   * on Windows it is usually 64KB, while the page size is 4KB.
   *
   * \returns the allocation granularity in bytes.
   */
  size_t allocation_granularity() const { return allocation_granularity_; }

  /**
   * The base address of the address space managed by this instance.
   *
   * \returns the base address of this address space.
   */
  Address base() const { return base_; }

  /**
   * The size of the address space managed by this instance.
   *
   * \returns the size of this address space in bytes.
   */
  size_t size() const { return size_; }

  /**
   * The maximum page permissions that pages allocated inside this space can
   * obtain.
   *
   * \returns the maximum page permissions.
   */
  PagePermissions max_page_permissions() const { return max_page_permissions_; }

  /**
   * Whether the |address| is inside the address space managed by this instance.
   *
   * \returns true if it is inside the address space, false if not.
   */
  bool Contains(Address address) const {
    return (address >= base()) && (address < base() + size());
  }

  /**
   * Sets the random seed so that GetRandomPageAddress() will generate
   * repeatable sequences of random addresses.
   *
   * \param The seed for the PRNG.
   */
  virtual void SetRandomSeed(int64_t seed) = 0;

  /**
   * Returns a random address inside this address space, suitable for page
   * allocations hints.
   *
   * \returns a random address aligned to allocation_granularity().
   */
  virtual Address RandomPageAddress() = 0;

  /**
   * Allocates private memory pages with the given alignment and permissions.
   *
   * \param hint If nonzero, the allocation is attempted to be placed at the
   * given address first. If that fails, the allocation is attempted to be
   * placed elsewhere, possibly nearby, but that is not guaranteed. Specifying
   * zero for the hint always causes this function to choose a random address.
   * The hint, if specified, must be aligned to the specified alignment.
   *
   * \param size The size of the allocation in bytes. Must be a multiple of the
   * allocation_granularity().
   *
   * \param alignment The alignment of the allocation in bytes. Must be a
   * multiple of the allocation_granularity() and should be a power of two.
   *
   * \param permissions The page permissions of the newly allocated pages.
   *
   * \returns the start address of the allocated pages on success, zero on
   * failure.
   */
  static constexpr Address kNoHint = 0;
  virtual V8_WARN_UNUSED_RESULT Address
  AllocatePages(Address hint, size_t size, size_t alignment,
                PagePermissions permissions) = 0;

  /**
   * Frees previously allocated pages.
   *
   * This function will terminate the process on failure as this implies a bug
   * in the client. As such, there is no return value.
   *
   * \param address The start address of the pages to free. This address must
   * have been obtained through a call to AllocatePages.
   *
   * \param size The size in bytes of the region to free. This must match the
   * size passed to AllocatePages when the pages were allocated.
   */
  virtual void FreePages(Address address, size_t size) = 0;

  /**
   * Sets permissions of all allocated pages in the given range.
   *
   * This operation can fail due to OOM, in which case false is returned. If
   * the operation fails for a reason other than OOM, this function will
   * terminate the process as this implies a bug in the client.
   *
   * \param address The start address of the range. Must be aligned to
   * page_size().
   *
   * \param size The size in bytes of the range. Must be a multiple
   * of page_size().
   *
   * \param permissions The new permissions for the range.
   *
   * \returns true on success, false on OOM.
   */
  virtual V8_WARN_UNUSED_RESULT bool SetPagePermissions(
      Address address, size_t size, PagePermissions permissions) = 0;

  /**
   * Creates a guard region at the specified address.
   *
   * Guard regions are guaranteed to cause a fault when accessed and generally
   * do not count towards any memory consumption limits. Further, allocating
   * guard regions can usually not fail in subspaces if the region does not
   * overlap with another region, subspace, or page allocation.
   *
   * \param address The start address of the guard region. Must be aligned to
   * the allocation_granularity().
   *
   * \param size The size of the guard region in bytes. Must be a multiple of
   * the allocation_granularity().
   *
   * \returns true on success, false otherwise.
   */
  virtual V8_WARN_UNUSED_RESULT bool AllocateGuardRegion(Address address,
                                                         size_t size) = 0;

  /**
   * Frees an existing guard region.
   *
   * This function will terminate the process on failure as this implies a bug
   * in the client. As such, there is no return value.
   *
   * \param address The start address of the guard region to free. This address
   * must have previously been used as address parameter in a successful
   * invocation of AllocateGuardRegion.
   *
   * \param size The size in bytes of the guard region to free. This must match
   * the size passed to AllocateGuardRegion when the region was created.
   */
  virtual void FreeGuardRegion(Address address, size_t size) = 0;

  /**
   * Allocates shared memory pages with the given permissions.
   *
   * \param hint Placement hint. See AllocatePages.
   *
   * \param size The size of the allocation in bytes. Must be a multiple of the
   * allocation_granularity().
   *
   * \param permissions
```