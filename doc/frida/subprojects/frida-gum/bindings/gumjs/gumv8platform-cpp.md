Response:
The user wants a summary of the functionality of the C++ source code file `gumv8platform.cpp` which is part of Frida. They are particularly interested in:

1. **General Functionality:** What does this code do?
2. **Reversing Relevance:** How does it relate to reverse engineering?
3. **Low-level Details:** Does it interact with the binary level, Linux/Android kernel, or frameworks?
4. **Logical Reasoning:** Are there any logical inferences or conditional logic? If so, provide examples with inputs and outputs.
5. **Common User Errors:** What mistakes might a user make that lead to this code being executed?
6. **User Journey:** How does a user's interaction with Frida eventually lead to the execution of this code?
7. **Summary of Functions:**  A concise overview of the file's purpose.

Let's break down the code section by section to address these points.

**Overall Impression:** The code seems to be implementing a V8 platform abstraction layer for Frida. It manages tasks, threading, memory allocation, and synchronization primitives, adapting V8's requirements to Frida's architecture.

**Step-by-step analysis:**

1. **Includes and Namespaces:** Standard includes and namespace declaration. No immediate reversing implications.
2. **`kMaxWorkerPerJob`:**  A constant limiting the number of worker threads. Potentially relevant to resource management during dynamic instrumentation.
3. **`gum_page_protection_from_v8`:** A function to convert V8's page protection flags to Frida's. This directly touches on memory management, a core aspect of reversing and dynamic analysis.
4. **`GumV8MainContextOperation`:**  Manages operations that need to run on the main JavaScript thread. This is crucial for coordinating Frida's instrumentation logic with the target process. The states (Scheduled, Running, Completed, etc.) indicate a state machine for operation management.
5. **`GumV8ThreadPoolOperation`:**  Handles operations that can run on background threads. This improves performance by offloading tasks that don't need to be on the main thread.
6. **`GumV8DelayedThreadPoolOperation`:**  Similar to `GumV8ThreadPoolOperation` but allows for a delay before execution. Useful for scheduling actions in the future.
7. **`GumV8ForegroundTaskRunner`:**  Manages tasks that need to run on the V8 isolate's foreground thread. This is likely used for tasks that need to interact directly with the V8 engine.
8. **`GumV8JobState` and related classes (`GumV8JobHandle`, `GumV8JobWorker`):** Implement a job scheduling mechanism, potentially for parallel processing within V8. This relates to how Frida might execute complex instrumentation tasks efficiently. The `JobDelegate` suggests a way for V8 to interact with Frida's job management.
9. **`GumV8PageAllocator`:**  A custom page allocator for V8. This is a significant point, as it indicates Frida controls memory allocation for the V8 engine it embeds. This is critical for instrumentation, as Frida needs to allocate memory in the target process.
10. **`GumV8ArrayBufferAllocator`:** A custom allocator for V8's ArrayBuffers. Similar to the page allocator, this gives Frida control over memory used by JavaScript data structures.
11. **`GumV8ThreadingBackend` and related classes (`GumMutex`, `GumRecursiveMutex`, `GumSharedMutex`, `GumConditionVariable`):** Provide Frida's own implementations of threading and synchronization primitives (mutexes, condition variables). This suggests Frida is managing concurrency internally and adapting it to V8's needs.
12. **`GumV8PlatformLocker` and `GumV8PlatformUnlocker`:** RAII wrappers for locking and unlocking the platform mutex, ensuring thread safety.
13. **`GumV8Platform` Class:**  The core of the file. It orchestrates the interaction between Frida and the V8 engine. It manages isolates, schedules tasks, handles threading, and provides memory allocation. The methods like `ScheduleOnJSThread`, `ScheduleOnThreadPool`, `DisposeIsolate`, etc., are key to its functionality.
14. **`GumV8Operation`:** A base class for operations scheduled on the platform, keeping track of the associated V8 isolate.

**Answering the user's questions:**

* **Functionality:** Implements a V8 platform interface for Frida, managing the lifecycle of V8 isolates, scheduling tasks on different threads, handling memory allocation, and providing synchronization primitives.
* **Reversing Relevance:**  Crucial for Frida's ability to dynamically instrument JavaScript code. It allows Frida to execute JavaScript within the target process, intercept function calls, modify variables, etc. The memory allocation aspects are directly tied to how Frida injects code and data.
* **Low-level Details:**  Yes, it interacts with binary/OS concepts. The `GumV8PageAllocator` directly interfaces with memory management (likely using `mmap` or similar OS calls). The threading backend utilizes OS-level threading primitives (like pthreads or Windows threads wrapped by GLib). On Darwin (`HAVE_DARWIN`), it includes `<mach/mach.h>` and `<sys/mman.h>`, indicating direct interaction with the Mach kernel for memory management.
* **Logical Reasoning:**  The state machines in the `*Operation` classes are examples of logical reasoning. For instance, in `GumV8MainContextOperation::Cancel`, the operation only attempts to cancel if it's in the `kScheduled` state. If it's already running or completed, cancellation is skipped.
    * **Input (Hypothetical):** Call `Cancel()` on a `GumV8MainContextOperation` that is in the `kRunning` state.
    * **Output:** The `Cancel()` method will return without taking any action.
* **Common User Errors:**  While the code itself doesn't directly expose user-facing errors, incorrect usage of Frida's API that leads to resource contention or deadlocks within the V8 environment could surface here. For example, scheduling too many tasks on the JS thread might overwhelm it. Incorrect memory manipulation through Frida's scripting API could also lead to crashes within the allocated memory regions managed by this code.
* **User Journey:** A typical Frida user might:
    1. Write a Frida script in JavaScript.
    2. Use the Frida client (CLI or Python) to attach to a target process.
    3. Frida injects its agent into the target process.
    4. The agent initializes the V8 engine using the `GumV8Platform`.
    5. The user's JavaScript script is executed within this V8 environment.
    6. When the script interacts with the target process (e.g., hooking functions), this often involves scheduling tasks (like code injection or callback execution) that are managed by the `GumV8Platform`.
* **Summary of Functions:** This file implements the platform interface required by the V8 JavaScript engine within the Frida framework. It provides abstractions for threading, memory management, and task scheduling, enabling Frida to execute JavaScript code within a target process for dynamic instrumentation. It bridges the gap between the high-level JavaScript environment and the underlying operating system and hardware.
```cpp
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8platform.h"

#include "gumscriptbackend.h"
#include "gumv8scope.h"

#include <algorithm>
#include <gum/gumcloak.h>
#include <gum/gumcodesegment.h>
#include <gum/gummemory.h>
#ifdef HAVE_DARWIN
# include <mach/mach.h>
# include <sys/mman.h>
#endif

using namespace v8;

namespace
{
  constexpr size_t kMaxWorkerPerJob = 32;
}

static GumPageProtection gum_page_protection_from_v8 (
    PageAllocator::Permission permission);

class GumV8MainContextOperation : public GumV8Operation
{
public:
  GumV8MainContextOperation (GumV8Platform * platform,
      std::function<void ()> func, GSource * source,
      guint delay_in_milliseconds);
  ~GumV8MainContextOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceling,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  GSource * source;
  guint delay_in_milliseconds;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8ThreadPoolOperation : public GumV8Operation
{
public:
  GumV8ThreadPoolOperation (GumV8Platform * platform,
      std::function<void ()> func);
  ~GumV8ThreadPoolOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8DelayedThreadPoolOperation : public GumV8Operation
{
public:
  GumV8DelayedThreadPoolOperation (GumV8Platform * platform,
      std::function<void ()> func, GSource * source);
  ~GumV8DelayedThreadPoolOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceling,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  GSource * source;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8ForegroundTaskRunner : public TaskRunner
{
public:
  GumV8ForegroundTaskRunner (GumV8Platform * platform, Isolate * isolate);
  ~GumV8ForegroundTaskRunner () override;

  void PostTask (std::unique_ptr<Task> task) override;
  void PostNonNestableTask (std::unique_ptr<Task> task) override;
  void PostDelayedTask (std::unique_ptr<Task> task,
      double delay_in_seconds) override;
  void PostNonNestableDelayedTask (std::unique_ptr<Task> task,
      double delay_in_seconds) override;
  void PostIdleTask (std::unique_ptr<IdleTask> task) override;
  bool IdleTasksEnabled () override;
  bool NonNestableTasksEnabled () const override;
  bool NonNestableDelayedTasksEnabled () const override;

private:
  void Run (Task * task);
  void Run (IdleTask * task);

  GumV8Platform * platform;
  Isolate * isolate;
  GHashTable * pending;
};

/* The following three classes are based on the default implementation in V8. */

class GumV8JobState : public std::enable_shared_from_this<GumV8JobState>
{
public:
  GumV8JobState (GumV8Platform * platform, std::unique_ptr<JobTask> job_task,
      TaskPriority priority, size_t num_worker_threads);
  GumV8JobState (const GumV8JobState &) = delete;
  GumV8JobState & operator= (const GumV8JobState &) = delete;
  virtual ~GumV8JobState ();

  void NotifyConcurrencyIncrease ();
  uint8_t AcquireTaskId ();
  void ReleaseTaskId (uint8_t task_id);
  void Join ();
  void CancelAndWait ();
  void CancelAndDetach ();
  bool IsActive ();
  void UpdatePriority (TaskPriority new_priority);
  bool CanRunFirstTask ();
  bool DidRunTask ();

private:
  bool WaitForParticipationOpportunityLocked ();
  size_t CappedMaxConcurrency (size_t worker_count) const;
  void CallOnWorkerThread (TaskPriority with_priority,
      std::unique_ptr<Task> task);

public:
  class JobDelegate : public v8::JobDelegate
  {
  public:
    explicit JobDelegate (GumV8JobState * parent, bool is_joining_thread);
    virtual ~JobDelegate ();

    void NotifyConcurrencyIncrease () override;
    bool ShouldYield () override;
    uint8_t GetTaskId () override;
    bool IsJoiningThread () const override { return is_joining_thread; }

  private:
    static constexpr uint8_t kInvalidTaskId = G_MAXUINT8;

    GumV8JobState * parent;
    uint8_t task_id = kInvalidTaskId;
    bool is_joining_thread;
  };

private:
  GMutex mutex;
  Isolate * isolate;
  GumV8Platform * platform;
  std::unique_ptr<JobTask> job_task;
  TaskPriority priority;
  size_t num_worker_threads;
  size_t active_workers = 0;
  GCond worker_released_cond;
  size_t pending_tasks = 0;
  std::atomic<uint32_t> assigned_task_ids { 0 };
  std::atomic_bool is_canceled { false };
};

class GumV8JobHandle : public JobHandle
{
public:
  GumV8JobHandle (std::shared_ptr<GumV8JobState> state);
  GumV8JobHandle (const GumV8JobHandle &) = delete;
  GumV8JobHandle & operator= (const GumV8JobHandle &) = delete;
  ~GumV8JobHandle () override;

  void NotifyConcurrencyIncrease () override;
  void Join () override;
  void Cancel () override;
  void CancelAndDetach () override;
  bool IsActive () override;
  bool IsValid () override { return state != nullptr; }
  bool UpdatePriorityEnabled () const override { return true; }
  void UpdatePriority (TaskPriority new_priority) override;

private:
  std::shared_ptr<GumV8JobState> state;
};

class GumV8JobWorker : public Task
{
public:
  GumV8JobWorker (std::weak_ptr<GumV8JobState> state, JobTask * job_task);
  GumV8JobWorker (const GumV8JobWorker &) = delete;
  GumV8JobWorker & operator= (const GumV8JobWorker &) = delete;
  ~GumV8JobWorker () override = default;

  void Run () override;

private:
  std::weak_ptr<GumV8JobState> state;
  JobTask * job_task;
};

class GumV8PageAllocator : public PageAllocator
{
public:
  GumV8PageAllocator () = default;

  size_t AllocatePageSize () override;
  size_t CommitPageSize () override;
  void SetRandomMmapSeed (int64_t seed) override;
  void * GetRandomMmapAddr () override;
  void * AllocatePages (void * address, size_t length, size_t alignment,
      Permission permissions) override;
  bool FreePages (void * address, size_t length) override;
  bool ReleasePages (void * address, size_t length, size_t new_length) override;
  bool SetPermissions (void * address, size_t length,
      Permission permissions) override;
  bool RecommitPages (void * address, size_t length, Permission permissions)
      override;
  bool DiscardSystemPages (void * address, size_t size) override;
  bool DecommitPages (void * address, size_t size) override;
};

class GumV8ArrayBufferAllocator : public ArrayBuffer::Allocator
{
public:
  GumV8ArrayBufferAllocator () = default;

  void * Allocate (size_t length) override;
  void * AllocateUninitialized (size_t length) override;
  void Free (void * data, size_t length) override;
  void * Reallocate (void * data, size_t old_length, size_t new_length)
      override;
};

class GumV8ThreadingBackend : public ThreadingBackend
{
public:
  GumV8ThreadingBackend () = default;

  MutexImpl * CreatePlainMutex () override;
  MutexImpl * CreateRecursiveMutex () override;
  SharedMutexImpl * CreateSharedMutex () override;
  ConditionVariableImpl * CreateConditionVariable () override;
};

class GumMutex : public MutexImpl
{
public:
  GumMutex ();
  ~GumMutex () override;

  void Lock () override;
  void Unlock () override;
  bool TryLock () override;

private:
  GMutex mutex;

  friend class GumConditionVariable;
};

class GumRecursiveMutex : public MutexImpl
{
public:
  GumRecursiveMutex ();
  ~GumRecursiveMutex () override;

  void Lock () override;
  void Unlock () override;
  bool TryLock () override;

private:
  GRecMutex mutex;
};

class GumSharedMutex : public SharedMutexImpl
{
public:
  GumSharedMutex ();
  ~GumSharedMutex () override;

  void LockShared () override;
  void LockExclusive () override;
  void UnlockShared () override;
  void UnlockExclusive () override;
  bool TryLockShared () override;
  bool TryLockExclusive () override;

private:
  GRWLock lock;
};

class GumConditionVariable : public ConditionVariableImpl
{
public:
  GumConditionVariable ();
  ~GumConditionVariable () override;

  void NotifyOne () override;
  void NotifyAll () override;
  void Wait (MutexImpl * mutex) override;
  bool WaitFor (MutexImpl * mutex, int64_t delta_in_microseconds) override;

private:
  GCond cond;
};

class GumMutexLocker
{
public:
  GumMutexLocker (GMutex * mutex)
    : mutex (mutex)
  {
    g_mutex_lock (mutex);
  }

  GumMutexLocker (const GumMutexLocker &) = delete;

  GumMutexLocker & operator= (const GumMutexLocker &) = delete;

  ~GumMutexLocker ()
  {
    g_mutex_unlock (mutex);
  }

private:
  GMutex * mutex;
};

class GumMutexUnlocker
{
public:
  GumMutexUnlocker (GMutex * mutex)
    : mutex (mutex)
  {
    g_mutex_unlock (mutex);
  }

  GumMutexUnlocker (const GumMutexUnlocker &) = delete;

  GumMutexUnlocker & operator= (const GumMutexUnlocker &) = delete;

  ~GumMutexUnlocker ()
  {
    g_mutex_lock (mutex);
  }

private:
  GMutex * mutex;
};

class GumV8PlatformLocker
{
public:
  GumV8PlatformLocker (GumV8Platform * platform)
    : locker (&platform->mutex)
  {
  }

private:
  GumMutexLocker locker;
};

class GumV8PlatformUnlocker
{
public:
  GumV8PlatformUnlocker (GumV8Platform * platform)
    : unlocker (&platform->mutex)
  {
  }

private:
  GumMutexUnlocker unlocker;
};

GumV8Platform::GumV8Platform ()
  : disposing (false),
    scheduler (gum_script_backend_get_scheduler ()),
    page_allocator (new GumV8PageAllocator ()),
    array_buffer_allocator (new GumV8ArrayBufferAllocator ()),
    threading_backend (new GumV8ThreadingBackend ()),
    tracing_controller (new TracingController ())
{
  g_mutex_init (&mutex);

  g_object_ref (scheduler);

  V8::InitializePlatform (this);
  V8::Initialize ();
}

GumV8Platform::~GumV8Platform ()
{
  PerformOnJSThread (G_PRIORITY_HIGH, [=]() { Dispose (); });

  g_object_unref (scheduler);

  g_mutex_clear (&mutex);
}

void
GumV8Platform::Dispose ()
{
  disposing = true;

  CancelPendingOperations ();

  for (const auto & isolate : dying_isolates)
    isolate->Dispose ();
  dying_isolates.clear ();

  V8::Dispose ();
  V8::DisposePlatform ();
}

void
GumV8Platform::CancelPendingOperations ()
{
  GMainContext * main_context = gum_script_scheduler_get_js_context (scheduler);

  while (true)
  {
    std::unordered_set<std::shared_ptr<GumV8Operation>> js_ops_copy;
    std::unordered_set<std::shared_ptr<GumV8Operation>> pool_ops_copy;
    {
      GumV8PlatformLocker locker (this);

      js_ops_copy = js_ops;
      pool_ops_copy = pool_ops;
    }

    for (const auto & op : js_ops_copy)
      op->Cancel ();

    for (const auto & op : pool_ops_copy)
      op->Cancel ();
    for (const auto & op : pool_ops_copy)
      op->Await ();

    {
      GumV8PlatformLocker locker (this);
      if (js_ops.empty () && pool_ops.empty ())
        break;
    }

    bool anything_pending = false;
    while (g_main_context_pending (main_context))
    {
      anything_pending = true;
      g_main_context_iteration (main_context, FALSE);
    }
    if (!anything_pending)
      g_thread_yield ();
  }
}

void
GumV8Platform::DisposeIsolate (Isolate ** isolate)
{
  Isolate * i = (Isolate *) g_steal_pointer (isolate);

  {
    GumV8PlatformLocker locker (this);
    dying_isolates.insert (i);
  }

  MaybeDisposeIsolate (i);
}

void
GumV8Platform::MaybeDisposeIsolate (Isolate * isolate)
{
  auto isolate_ops = GetPendingOperationsFor (isolate);
  for (const auto & op : isolate_ops)
    op->Cancel ();
  if (!isolate_ops.empty ())
    return;

  {
    GumV8PlatformLocker locker (this);

    if (disposing || dying_isolates.find (isolate) == dying_isolates.end ())
      return;

    foreground_runners.erase (isolate);
    dying_isolates.erase (isolate);
  }

  isolate->Dispose ();
}

void
GumV8Platform::ForgetIsolate (Isolate * isolate)
{
  std::unordered_set<std::shared_ptr<GumV8Operation>> isolate_ops;
  do
  {
    isolate_ops = GetPendingOperationsFor (isolate);

    for (const auto & op : isolate_ops)
      op->Cancel ();
    for (const auto & op : isolate_ops)
      op->Await ();
  }
  while (!isolate_ops.empty ());

  {
    GumV8PlatformLocker locker (this);

    foreground_runners.erase (isolate);
  }
}

std::unordered_set<std::shared_ptr<GumV8Operation>>
GumV8Platform::GetPendingOperationsFor (Isolate * isolate)
{
  std::unordered_set<std::shared_ptr<GumV8Operation>> isolate_ops;

  GumV8PlatformLocker locker (this);

  for (const auto & op : js_ops)
  {
    if (op->IsAnchoredTo (isolate))
      isolate_ops.insert (op);
  }

  for (const auto & op : pool_ops)
  {
    if (op->IsAnchoredTo (isolate))
      isolate_ops.insert (op);
  }

  return isolate_ops;
}

void
GumV8Platform::OnOperationRemoved (GumV8Operation * op)
{
  Isolate * isolate = op->isolate;
  if (isolate == nullptr)
    return;

  {
    GumV8PlatformLocker locker (this);
    if (dying_isolates.find (isolate) == dying_isolates.end ())
      return;
  }

  ScheduleOnJSThread (G_PRIORITY_HIGH, [=]()
      {
        MaybeDisposeIsolate (isolate);
      });
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThread (std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (0, G_PRIORITY_DEFAULT, f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThread (gint priority,
                                   std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (0, priority, f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThreadDelayed (guint delay_in_milliseconds,
                                          std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (delay_in_milliseconds, G_PRIORITY_DEFAULT,
      f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThreadDelayed (guint delay_in_milliseconds,
                                          gint priority,
                                          std::function<void ()> f)
{
  GSource * source = (delay_in_milliseconds != 0)
      ? g_timeout_source_new (delay_in_milliseconds)
      : g_idle_source_new ();
  g_source_set_priority (source, priority);

  auto op = std::make_shared<GumV8MainContextOperation> (this, f, source,
      delay_in_milliseconds);

  {
    GumV8PlatformLocker locker (this);
    js_ops.insert (op);
  }

  g_source_set_callback (source, PerformMainContextOperation,
      new std::shared_ptr<GumV8MainContextOperation> (op),
      ReleaseMainContextOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  return op;
}

void
GumV8Platform::PerformOnJSThread (std::function<void ()> f)
{
  PerformOnJSThread (G_PRIORITY_DEFAULT, f);
}

void
GumV8Platform::PerformOnJSThread (gint priority,
                                  std::function<void ()> f)
{
  GSource * source = g_idle_source_new ();
  g_source_set_priority (source, priority);

  auto op = std::make_shared<GumV8MainContextOperation> (this, f, source, 0);

  g_source_set_callback (source, PerformMainContextOperation,
      new std::shared_ptr<GumV8MainContextOperation> (op),
      ReleaseSynchronousMainContextOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  op->Await ();
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnThreadPool (std::function<void ()> f)
{
  auto op = std::make_shared<GumV8ThreadPoolOperation> (this, f);

  {
    GumV8PlatformLocker locker (this);
    pool_ops.insert (op);
  }

  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      PerformThreadPoolOperation,
      new std::shared_ptr<GumV8ThreadPoolOperation> (op),
      ReleaseThreadPoolOperation);

  return op;
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnThreadPoolDelayed (guint delay_in_milliseconds,
                                            std::function<void ()> f)
{
  GSource * source = g_timeout_source_new (delay_in_milliseconds);
  g_source_set_priority (source, G_PRIORITY_HIGH);

  auto op = std::make_shared<GumV8DelayedThreadPoolOperation> (this, f, source);

  {
    GumV8PlatformLocker locker (this);
    pool_ops.insert (op);
  }

  g_source_set_callback (source, StartDelayedThreadPoolOperation,
      new std::shared_ptr<GumV8DelayedThreadPoolOperation> (op),
      ReleaseDelayedThreadPoolOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  return op;
}

gboolean
GumV8Platform::PerformMainContextOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8MainContextOperation> *) data;

  (*operation)->Perform ();

  return FALSE;
}

void
GumV8Platform::ReleaseMainContextOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8MainContextOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  {
    GumV8PlatformLocker locker (platform);

    platform->js_ops.erase (op);
  }

  platform->OnOperationRemoved (op.get ());

  delete ptr;
}

void
GumV8Platform::ReleaseSynchronousMainContextOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8MainContextOperation> *) data;

  delete ptr;
}

void
GumV8Platform::PerformThreadPoolOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8ThreadPoolOperation> *) data;

  (*operation)->Perform ();
}

void
GumV8Platform::ReleaseThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8ThreadPoolOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  {
    GumV8PlatformLocker locker (platform);

    platform->pool_ops.erase (op);
  }

  platform->OnOperationRemoved (op.get ());

  delete ptr;
}

gboolean
GumV8Platform::StartDelayedThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;
  auto op = *ptr;

  gum_script_scheduler_push_job_on_thread_pool (op->platform->scheduler,
      PerformDelayedThreadPoolOperation,
      new std::shared_ptr<GumV8DelayedThreadPoolOperation> (op),
      ReleaseDelayedThreadPoolOperation);

  return FALSE;
}

void
GumV8Platform::PerformDelayedThreadPoolOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;

  (*operation)->Perform ();
}

void
GumV8Platform::ReleaseDelayedThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  bool removed = false;
  {
    GumV8PlatformLocker locker (platform);

    switch (op->state)
    {
      case GumV8DelayedThreadPoolOperation::kScheduled:
      case GumV8DelayedThreadPoolOperation::kRunning:
        break;
      case GumV8DelayedThreadPoolOperation::kCompleted:
      case GumV8DelayedThreadPoolOperation::kCanceling:
      case GumV8DelayedThreadPoolOperation::kCanceled:
        platform->pool_ops.erase (op);
        removed = true;
        break;
    }
  }

  if (removed)
    platform->OnOperationRemoved (op.get ());

  delete ptr;
}

PageAllocator *
GumV8Platform::GetPageAllocator ()
{
  return page_allocator.get ();
}

int
GumV8Platform::NumberOfWorkerThreads ()
{
  return g_get_num_processors ();
}

std::shared_ptr<TaskRunner>
GumV8Platform::GetForegroundTaskRunner (Isolate * isolate)
{
  GumV8PlatformLocker locker (this);

  auto runner = foreground_runners[isolate];
  if (!runner)
  {
    runner = std::make_shared<GumV8ForegroundTaskRunner> (this, isolate);
    foreground_runners[isolate] = runner;
  }

  return runner;
}

void
GumV8Platform::CallOnWorkerThread (std::unique_ptr<Task> task)
{
  std::shared_ptr<Task> t (std::move (task));
  ScheduleOnThreadPool ([=]() { t->Run (); });
}

void
GumV8Platform::CallDelayedOnWorkerThread (std::unique_ptr<Task> task,
                                          double delay_in_seconds)
{
  std::shared_ptr<Task> t (std::move (task));
  ScheduleOnThreadPoolDelayed (delay_in_seconds * 1000.0, [=]()
      {
        t->Run ();
      });
}

bool
GumV8Platform::IdleTasksEnabled (Isolate * isolate)
{
  return true;
}

std::unique_ptr<JobHandle>
GumV8Platform::CreateJob (TaskPriority priority,
                          std::unique_ptr<JobTask> job_task)
{
  size_t num_worker_threads = NumberOfWorkerThreads ();
  if (priority == TaskPriority::kBestEffort)
    num_worker_threads = std::min (num_worker_threads, (size_t) 2);

  return std::make_unique<GumV8JobHandle> (std::make_shared<GumV8JobState> (
      this, std::move (job_task), priority, num_worker_threads));
}

double
GumV8Platform::MonotonicallyIncreasingTime ()
{
  gint64 usec = g_get_monotonic_time ();

  double result = (double) (usec / G_USEC_PER_SEC);
  result += (double) (usec % G_USEC_PER_SEC) / (double) G_USEC_PER_SEC;
  return result;
}

double
GumV8Platform::CurrentClockTimeMillis ()
{
  gint64 usec = g_get_real_time ();

  double result = (double) (usec / 1000);
  result += (double) (usec % 1000) / 1000.0;
  return result;
}

ThreadingBackend *
GumV8Platform::GetThreadingBackend ()
{
  return threading_backend.get ();
}

TracingController *
GumV8Platform::GetTracingController ()
{
  return tracing_controller.get ();
### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8platform.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8platform.h"

#include "gumscriptbackend.h"
#include "gumv8scope.h"

#include <algorithm>
#include <gum/gumcloak.h>
#include <gum/gumcodesegment.h>
#include <gum/gummemory.h>
#ifdef HAVE_DARWIN
# include <mach/mach.h>
# include <sys/mman.h>
#endif

using namespace v8;

namespace
{
  constexpr size_t kMaxWorkerPerJob = 32;
}

static GumPageProtection gum_page_protection_from_v8 (
    PageAllocator::Permission permission);

class GumV8MainContextOperation : public GumV8Operation
{
public:
  GumV8MainContextOperation (GumV8Platform * platform,
      std::function<void ()> func, GSource * source,
      guint delay_in_milliseconds);
  ~GumV8MainContextOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceling,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  GSource * source;
  guint delay_in_milliseconds;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8ThreadPoolOperation : public GumV8Operation
{
public:
  GumV8ThreadPoolOperation (GumV8Platform * platform,
      std::function<void ()> func);
  ~GumV8ThreadPoolOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8DelayedThreadPoolOperation : public GumV8Operation
{
public:
  GumV8DelayedThreadPoolOperation (GumV8Platform * platform,
      std::function<void ()> func, GSource * source);
  ~GumV8DelayedThreadPoolOperation () override;

  void Perform ();
  void Cancel () override;
  void Await () override;

private:
  enum State
  {
    kScheduled,
    kRunning,
    kCompleted,
    kCanceling,
    kCanceled
  };

  GumV8Platform * platform;
  std::function<void ()> func;
  GSource * source;
  volatile State state;
  GCond cond;

  friend class GumV8Platform;
};

class GumV8ForegroundTaskRunner : public TaskRunner
{
public:
  GumV8ForegroundTaskRunner (GumV8Platform * platform, Isolate * isolate);
  ~GumV8ForegroundTaskRunner () override;

  void PostTask (std::unique_ptr<Task> task) override;
  void PostNonNestableTask (std::unique_ptr<Task> task) override;
  void PostDelayedTask (std::unique_ptr<Task> task,
      double delay_in_seconds) override;
  void PostNonNestableDelayedTask (std::unique_ptr<Task> task,
      double delay_in_seconds) override;
  void PostIdleTask (std::unique_ptr<IdleTask> task) override;
  bool IdleTasksEnabled () override;
  bool NonNestableTasksEnabled () const override;
  bool NonNestableDelayedTasksEnabled () const override;

private:
  void Run (Task * task);
  void Run (IdleTask * task);

  GumV8Platform * platform;
  Isolate * isolate;
  GHashTable * pending;
};

/* The following three classes are based on the default implementation in V8. */

class GumV8JobState : public std::enable_shared_from_this<GumV8JobState>
{
public:
  GumV8JobState (GumV8Platform * platform, std::unique_ptr<JobTask> job_task,
      TaskPriority priority, size_t num_worker_threads);
  GumV8JobState (const GumV8JobState &) = delete;
  GumV8JobState & operator= (const GumV8JobState &) = delete;
  virtual ~GumV8JobState ();

  void NotifyConcurrencyIncrease ();
  uint8_t AcquireTaskId ();
  void ReleaseTaskId (uint8_t task_id);
  void Join ();
  void CancelAndWait ();
  void CancelAndDetach ();
  bool IsActive ();
  void UpdatePriority (TaskPriority new_priority);
  bool CanRunFirstTask ();
  bool DidRunTask ();

private:
  bool WaitForParticipationOpportunityLocked ();
  size_t CappedMaxConcurrency (size_t worker_count) const;
  void CallOnWorkerThread (TaskPriority with_priority,
      std::unique_ptr<Task> task);

public:
  class JobDelegate : public v8::JobDelegate
  {
  public:
    explicit JobDelegate (GumV8JobState * parent, bool is_joining_thread);
    virtual ~JobDelegate ();

    void NotifyConcurrencyIncrease () override;
    bool ShouldYield () override;
    uint8_t GetTaskId () override;
    bool IsJoiningThread () const override { return is_joining_thread; }

  private:
    static constexpr uint8_t kInvalidTaskId = G_MAXUINT8;

    GumV8JobState * parent;
    uint8_t task_id = kInvalidTaskId;
    bool is_joining_thread;
  };

private:
  GMutex mutex;
  Isolate * isolate;
  GumV8Platform * platform;
  std::unique_ptr<JobTask> job_task;
  TaskPriority priority;
  size_t num_worker_threads;
  size_t active_workers = 0;
  GCond worker_released_cond;
  size_t pending_tasks = 0;
  std::atomic<uint32_t> assigned_task_ids { 0 };
  std::atomic_bool is_canceled { false };
};

class GumV8JobHandle : public JobHandle
{
public:
  GumV8JobHandle (std::shared_ptr<GumV8JobState> state);
  GumV8JobHandle (const GumV8JobHandle &) = delete;
  GumV8JobHandle & operator= (const GumV8JobHandle &) = delete;
  ~GumV8JobHandle () override;

  void NotifyConcurrencyIncrease () override;
  void Join () override;
  void Cancel () override;
  void CancelAndDetach () override;
  bool IsActive () override;
  bool IsValid () override { return state != nullptr; }
  bool UpdatePriorityEnabled () const override { return true; }
  void UpdatePriority (TaskPriority new_priority) override;

private:
  std::shared_ptr<GumV8JobState> state;
};

class GumV8JobWorker : public Task
{
public:
  GumV8JobWorker (std::weak_ptr<GumV8JobState> state, JobTask * job_task);
  GumV8JobWorker (const GumV8JobWorker &) = delete;
  GumV8JobWorker & operator= (const GumV8JobWorker &) = delete;
  ~GumV8JobWorker () override = default;

  void Run () override;

private:
  std::weak_ptr<GumV8JobState> state;
  JobTask * job_task;
};

class GumV8PageAllocator : public PageAllocator
{
public:
  GumV8PageAllocator () = default;

  size_t AllocatePageSize () override;
  size_t CommitPageSize () override;
  void SetRandomMmapSeed (int64_t seed) override;
  void * GetRandomMmapAddr () override;
  void * AllocatePages (void * address, size_t length, size_t alignment,
      Permission permissions) override;
  bool FreePages (void * address, size_t length) override;
  bool ReleasePages (void * address, size_t length, size_t new_length) override;
  bool SetPermissions (void * address, size_t length,
      Permission permissions) override;
  bool RecommitPages (void * address, size_t length, Permission permissions)
      override;
  bool DiscardSystemPages (void * address, size_t size) override;
  bool DecommitPages (void * address, size_t size) override;
};

class GumV8ArrayBufferAllocator : public ArrayBuffer::Allocator
{
public:
  GumV8ArrayBufferAllocator () = default;

  void * Allocate (size_t length) override;
  void * AllocateUninitialized (size_t length) override;
  void Free (void * data, size_t length) override;
  void * Reallocate (void * data, size_t old_length, size_t new_length)
      override;
};

class GumV8ThreadingBackend : public ThreadingBackend
{
public:
  GumV8ThreadingBackend () = default;

  MutexImpl * CreatePlainMutex () override;
  MutexImpl * CreateRecursiveMutex () override;
  SharedMutexImpl * CreateSharedMutex () override;
  ConditionVariableImpl * CreateConditionVariable () override;
};

class GumMutex : public MutexImpl
{
public:
  GumMutex ();
  ~GumMutex () override;

  void Lock () override;
  void Unlock () override;
  bool TryLock () override;

private:
  GMutex mutex;

  friend class GumConditionVariable;
};

class GumRecursiveMutex : public MutexImpl
{
public:
  GumRecursiveMutex ();
  ~GumRecursiveMutex () override;

  void Lock () override;
  void Unlock () override;
  bool TryLock () override;

private:
  GRecMutex mutex;
};

class GumSharedMutex : public SharedMutexImpl
{
public:
  GumSharedMutex ();
  ~GumSharedMutex () override;

  void LockShared () override;
  void LockExclusive () override;
  void UnlockShared () override;
  void UnlockExclusive () override;
  bool TryLockShared () override;
  bool TryLockExclusive () override;

private:
  GRWLock lock;
};

class GumConditionVariable : public ConditionVariableImpl
{
public:
  GumConditionVariable ();
  ~GumConditionVariable () override;

  void NotifyOne () override;
  void NotifyAll () override;
  void Wait (MutexImpl * mutex) override;
  bool WaitFor (MutexImpl * mutex, int64_t delta_in_microseconds) override;

private:
  GCond cond;
};

class GumMutexLocker
{
public:
  GumMutexLocker (GMutex * mutex)
    : mutex (mutex)
  {
    g_mutex_lock (mutex);
  }

  GumMutexLocker (const GumMutexLocker &) = delete;

  GumMutexLocker & operator= (const GumMutexLocker &) = delete;

  ~GumMutexLocker ()
  {
    g_mutex_unlock (mutex);
  }

private:
  GMutex * mutex;
};

class GumMutexUnlocker
{
public:
  GumMutexUnlocker (GMutex * mutex)
    : mutex (mutex)
  {
    g_mutex_unlock (mutex);
  }

  GumMutexUnlocker (const GumMutexUnlocker &) = delete;

  GumMutexUnlocker & operator= (const GumMutexUnlocker &) = delete;

  ~GumMutexUnlocker ()
  {
    g_mutex_lock (mutex);
  }

private:
  GMutex * mutex;
};

class GumV8PlatformLocker
{
public:
  GumV8PlatformLocker (GumV8Platform * platform)
    : locker (&platform->mutex)
  {
  }

private:
  GumMutexLocker locker;
};

class GumV8PlatformUnlocker
{
public:
  GumV8PlatformUnlocker (GumV8Platform * platform)
    : unlocker (&platform->mutex)
  {
  }

private:
  GumMutexUnlocker unlocker;
};

GumV8Platform::GumV8Platform ()
  : disposing (false),
    scheduler (gum_script_backend_get_scheduler ()),
    page_allocator (new GumV8PageAllocator ()),
    array_buffer_allocator (new GumV8ArrayBufferAllocator ()),
    threading_backend (new GumV8ThreadingBackend ()),
    tracing_controller (new TracingController ())
{
  g_mutex_init (&mutex);

  g_object_ref (scheduler);

  V8::InitializePlatform (this);
  V8::Initialize ();
}

GumV8Platform::~GumV8Platform ()
{
  PerformOnJSThread (G_PRIORITY_HIGH, [=]() { Dispose (); });

  g_object_unref (scheduler);

  g_mutex_clear (&mutex);
}

void
GumV8Platform::Dispose ()
{
  disposing = true;

  CancelPendingOperations ();

  for (const auto & isolate : dying_isolates)
    isolate->Dispose ();
  dying_isolates.clear ();

  V8::Dispose ();
  V8::DisposePlatform ();
}

void
GumV8Platform::CancelPendingOperations ()
{
  GMainContext * main_context = gum_script_scheduler_get_js_context (scheduler);

  while (true)
  {
    std::unordered_set<std::shared_ptr<GumV8Operation>> js_ops_copy;
    std::unordered_set<std::shared_ptr<GumV8Operation>> pool_ops_copy;
    {
      GumV8PlatformLocker locker (this);

      js_ops_copy = js_ops;
      pool_ops_copy = pool_ops;
    }

    for (const auto & op : js_ops_copy)
      op->Cancel ();

    for (const auto & op : pool_ops_copy)
      op->Cancel ();
    for (const auto & op : pool_ops_copy)
      op->Await ();

    {
      GumV8PlatformLocker locker (this);
      if (js_ops.empty () && pool_ops.empty ())
        break;
    }

    bool anything_pending = false;
    while (g_main_context_pending (main_context))
    {
      anything_pending = true;
      g_main_context_iteration (main_context, FALSE);
    }
    if (!anything_pending)
      g_thread_yield ();
  }
}

void
GumV8Platform::DisposeIsolate (Isolate ** isolate)
{
  Isolate * i = (Isolate *) g_steal_pointer (isolate);

  {
    GumV8PlatformLocker locker (this);
    dying_isolates.insert (i);
  }

  MaybeDisposeIsolate (i);
}

void
GumV8Platform::MaybeDisposeIsolate (Isolate * isolate)
{
  auto isolate_ops = GetPendingOperationsFor (isolate);
  for (const auto & op : isolate_ops)
    op->Cancel ();
  if (!isolate_ops.empty ())
    return;

  {
    GumV8PlatformLocker locker (this);

    if (disposing || dying_isolates.find (isolate) == dying_isolates.end ())
      return;

    foreground_runners.erase (isolate);
    dying_isolates.erase (isolate);
  }

  isolate->Dispose ();
}

void
GumV8Platform::ForgetIsolate (Isolate * isolate)
{
  std::unordered_set<std::shared_ptr<GumV8Operation>> isolate_ops;
  do
  {
    isolate_ops = GetPendingOperationsFor (isolate);

    for (const auto & op : isolate_ops)
      op->Cancel ();
    for (const auto & op : isolate_ops)
      op->Await ();
  }
  while (!isolate_ops.empty ());

  {
    GumV8PlatformLocker locker (this);

    foreground_runners.erase (isolate);
  }
}

std::unordered_set<std::shared_ptr<GumV8Operation>>
GumV8Platform::GetPendingOperationsFor (Isolate * isolate)
{
  std::unordered_set<std::shared_ptr<GumV8Operation>> isolate_ops;

  GumV8PlatformLocker locker (this);

  for (const auto & op : js_ops)
  {
    if (op->IsAnchoredTo (isolate))
      isolate_ops.insert (op);
  }

  for (const auto & op : pool_ops)
  {
    if (op->IsAnchoredTo (isolate))
      isolate_ops.insert (op);
  }

  return isolate_ops;
}

void
GumV8Platform::OnOperationRemoved (GumV8Operation * op)
{
  Isolate * isolate = op->isolate;
  if (isolate == nullptr)
    return;

  {
    GumV8PlatformLocker locker (this);
    if (dying_isolates.find (isolate) == dying_isolates.end ())
      return;
  }

  ScheduleOnJSThread (G_PRIORITY_HIGH, [=]()
      {
        MaybeDisposeIsolate (isolate);
      });
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThread (std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (0, G_PRIORITY_DEFAULT, f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThread (gint priority,
                                   std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (0, priority, f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThreadDelayed (guint delay_in_milliseconds,
                                          std::function<void ()> f)
{
  return ScheduleOnJSThreadDelayed (delay_in_milliseconds, G_PRIORITY_DEFAULT,
      f);
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnJSThreadDelayed (guint delay_in_milliseconds,
                                          gint priority,
                                          std::function<void ()> f)
{
  GSource * source = (delay_in_milliseconds != 0)
      ? g_timeout_source_new (delay_in_milliseconds)
      : g_idle_source_new ();
  g_source_set_priority (source, priority);

  auto op = std::make_shared<GumV8MainContextOperation> (this, f, source,
      delay_in_milliseconds);

  {
    GumV8PlatformLocker locker (this);
    js_ops.insert (op);
  }

  g_source_set_callback (source, PerformMainContextOperation,
      new std::shared_ptr<GumV8MainContextOperation> (op),
      ReleaseMainContextOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  return op;
}

void
GumV8Platform::PerformOnJSThread (std::function<void ()> f)
{
  PerformOnJSThread (G_PRIORITY_DEFAULT, f);
}

void
GumV8Platform::PerformOnJSThread (gint priority,
                                  std::function<void ()> f)
{
  GSource * source = g_idle_source_new ();
  g_source_set_priority (source, priority);

  auto op = std::make_shared<GumV8MainContextOperation> (this, f, source, 0);

  g_source_set_callback (source, PerformMainContextOperation,
      new std::shared_ptr<GumV8MainContextOperation> (op),
      ReleaseSynchronousMainContextOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  op->Await ();
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnThreadPool (std::function<void ()> f)
{
  auto op = std::make_shared<GumV8ThreadPoolOperation> (this, f);

  {
    GumV8PlatformLocker locker (this);
    pool_ops.insert (op);
  }

  gum_script_scheduler_push_job_on_thread_pool (scheduler,
      PerformThreadPoolOperation,
      new std::shared_ptr<GumV8ThreadPoolOperation> (op),
      ReleaseThreadPoolOperation);

  return op;
}

std::shared_ptr<GumV8Operation>
GumV8Platform::ScheduleOnThreadPoolDelayed (guint delay_in_milliseconds,
                                            std::function<void ()> f)
{
  GSource * source = g_timeout_source_new (delay_in_milliseconds);
  g_source_set_priority (source, G_PRIORITY_HIGH);

  auto op = std::make_shared<GumV8DelayedThreadPoolOperation> (this, f, source);

  {
    GumV8PlatformLocker locker (this);
    pool_ops.insert (op);
  }

  g_source_set_callback (source, StartDelayedThreadPoolOperation,
      new std::shared_ptr<GumV8DelayedThreadPoolOperation> (op),
      ReleaseDelayedThreadPoolOperation);
  g_source_attach (source, gum_script_scheduler_get_js_context (scheduler));

  return op;
}

gboolean
GumV8Platform::PerformMainContextOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8MainContextOperation> *) data;

  (*operation)->Perform ();

  return FALSE;
}

void
GumV8Platform::ReleaseMainContextOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8MainContextOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  {
    GumV8PlatformLocker locker (platform);

    platform->js_ops.erase (op);
  }

  platform->OnOperationRemoved (op.get ());

  delete ptr;
}

void
GumV8Platform::ReleaseSynchronousMainContextOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8MainContextOperation> *) data;

  delete ptr;
}

void
GumV8Platform::PerformThreadPoolOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8ThreadPoolOperation> *) data;

  (*operation)->Perform ();
}

void
GumV8Platform::ReleaseThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8ThreadPoolOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  {
    GumV8PlatformLocker locker (platform);

    platform->pool_ops.erase (op);
  }

  platform->OnOperationRemoved (op.get ());

  delete ptr;
}

gboolean
GumV8Platform::StartDelayedThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;
  auto op = *ptr;

  gum_script_scheduler_push_job_on_thread_pool (op->platform->scheduler,
      PerformDelayedThreadPoolOperation,
      new std::shared_ptr<GumV8DelayedThreadPoolOperation> (op),
      ReleaseDelayedThreadPoolOperation);

  return FALSE;
}

void
GumV8Platform::PerformDelayedThreadPoolOperation (gpointer data)
{
  auto operation = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;

  (*operation)->Perform ();
}

void
GumV8Platform::ReleaseDelayedThreadPoolOperation (gpointer data)
{
  auto ptr = (std::shared_ptr<GumV8DelayedThreadPoolOperation> *) data;

  auto op = *ptr;
  auto platform = op->platform;
  bool removed = false;
  {
    GumV8PlatformLocker locker (platform);

    switch (op->state)
    {
      case GumV8DelayedThreadPoolOperation::kScheduled:
      case GumV8DelayedThreadPoolOperation::kRunning:
        break;
      case GumV8DelayedThreadPoolOperation::kCompleted:
      case GumV8DelayedThreadPoolOperation::kCanceling:
      case GumV8DelayedThreadPoolOperation::kCanceled:
        platform->pool_ops.erase (op);
        removed = true;
        break;
    }
  }

  if (removed)
    platform->OnOperationRemoved (op.get ());

  delete ptr;
}

PageAllocator *
GumV8Platform::GetPageAllocator ()
{
  return page_allocator.get ();
}

int
GumV8Platform::NumberOfWorkerThreads ()
{
  return g_get_num_processors ();
}

std::shared_ptr<TaskRunner>
GumV8Platform::GetForegroundTaskRunner (Isolate * isolate)
{
  GumV8PlatformLocker locker (this);

  auto runner = foreground_runners[isolate];
  if (!runner)
  {
    runner = std::make_shared<GumV8ForegroundTaskRunner> (this, isolate);
    foreground_runners[isolate] = runner;
  }

  return runner;
}

void
GumV8Platform::CallOnWorkerThread (std::unique_ptr<Task> task)
{
  std::shared_ptr<Task> t (std::move (task));
  ScheduleOnThreadPool ([=]() { t->Run (); });
}

void
GumV8Platform::CallDelayedOnWorkerThread (std::unique_ptr<Task> task,
                                          double delay_in_seconds)
{
  std::shared_ptr<Task> t (std::move (task));
  ScheduleOnThreadPoolDelayed (delay_in_seconds * 1000.0, [=]()
      {
        t->Run ();
      });
}

bool
GumV8Platform::IdleTasksEnabled (Isolate * isolate)
{
  return true;
}

std::unique_ptr<JobHandle>
GumV8Platform::CreateJob (TaskPriority priority,
                          std::unique_ptr<JobTask> job_task)
{
  size_t num_worker_threads = NumberOfWorkerThreads ();
  if (priority == TaskPriority::kBestEffort)
    num_worker_threads = std::min (num_worker_threads, (size_t) 2);

  return std::make_unique<GumV8JobHandle> (std::make_shared<GumV8JobState> (
      this, std::move (job_task), priority, num_worker_threads));
}

double
GumV8Platform::MonotonicallyIncreasingTime ()
{
  gint64 usec = g_get_monotonic_time ();

  double result = (double) (usec / G_USEC_PER_SEC);
  result += (double) (usec % G_USEC_PER_SEC) / (double) G_USEC_PER_SEC;
  return result;
}

double
GumV8Platform::CurrentClockTimeMillis ()
{
  gint64 usec = g_get_real_time ();

  double result = (double) (usec / 1000);
  result += (double) (usec % 1000) / 1000.0;
  return result;
}

ThreadingBackend *
GumV8Platform::GetThreadingBackend ()
{
  return threading_backend.get ();
}

TracingController *
GumV8Platform::GetTracingController ()
{
  return tracing_controller.get ();
}

ArrayBuffer::Allocator *
GumV8Platform::GetArrayBufferAllocator () const
{
  return array_buffer_allocator.get ();
}

GumV8Operation::GumV8Operation ()
  : isolate (Isolate::TryGetCurrent ())
{
}

void
GumV8Operation::AnchorTo (v8::Isolate * i)
{
  isolate = i;
}

bool
GumV8Operation::IsAnchoredTo (Isolate * i) const
{
  return isolate == i;
}

GumV8MainContextOperation::GumV8MainContextOperation (
    GumV8Platform * platform,
    std::function<void ()> func,
    GSource * source,
    guint delay_in_milliseconds)
  : platform (platform),
    func (func),
    source (source),
    delay_in_milliseconds (delay_in_milliseconds),
    state (kScheduled)
{
  g_cond_init (&cond);
}

GumV8MainContextOperation::~GumV8MainContextOperation ()
{
  g_source_unref (source);
  g_cond_clear (&cond);
}

void
GumV8MainContextOperation::Perform ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kRunning;
  }

  func ();

  {
    GumV8PlatformLocker locker (platform);
    state = kCompleted;
    g_cond_signal (&cond);
  }
}

void
GumV8MainContextOperation::Cancel ()
{
  if (delay_in_milliseconds == 0)
    return;

  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kCanceling;
  }

  g_source_destroy (source);

  {
    GumV8PlatformLocker locker (platform);
    state = kCanceled;
    g_cond_signal (&cond);
  }
}

void
GumV8MainContextOperation::Await ()
{
  GumV8PlatformLocker locker (platform);

  GMainContext * context =
      gum_script_scheduler_get_js_context (platform->scheduler);
  gboolean called_from_js_thread = g_main_context_is_owner (context);

  while (state != kCompleted && state != kCanceled)
  {
    if (called_from_js_thread)
    {
      g_mutex_unlock (&platform->mutex);
      g_main_context_iteration (context, TRUE);
      g_mutex_lock (&platform->mutex);
    }
    else
    {
      g_cond_wait (&cond, &platform->mutex);
    }
  }
}

GumV8ThreadPoolOperation::GumV8ThreadPoolOperation (
    GumV8Platform * platform,
    std::function<void ()> func)
  : platform (platform),
    func (func),
    state (kScheduled)
{
  g_cond_init (&cond);
}

GumV8ThreadPoolOperation::~GumV8ThreadPoolOperation ()
{
  g_cond_clear (&cond);
}

void
GumV8ThreadPoolOperation::Perform ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kRunning;
  }

  func ();

  {
    GumV8PlatformLocker locker (platform);
    state = kCompleted;
    g_cond_signal (&cond);
  }
}

void
GumV8ThreadPoolOperation::Cancel ()
{
}

void
GumV8ThreadPoolOperation::Await ()
{
  GumV8PlatformLocker locker (platform);
  while (state != kCompleted && state != kCanceled)
    g_cond_wait (&cond, &platform->mutex);
}

GumV8DelayedThreadPoolOperation::GumV8DelayedThreadPoolOperation (
    GumV8Platform * platform,
    std::function<void ()> func,
    GSource * source)
  : platform (platform),
    func (func),
    source (source),
    state (kScheduled)
{
  g_cond_init (&cond);
}

GumV8DelayedThreadPoolOperation::~GumV8DelayedThreadPoolOperation ()
{
  g_source_unref (source);
  g_cond_clear (&cond);
}

void
GumV8DelayedThreadPoolOperation::Perform ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kRunning;
  }

  func ();

  {
    GumV8PlatformLocker locker (platform);
    state = kCompleted;
    g_cond_signal (&cond);
  }
}

void
GumV8DelayedThreadPoolOperation::Cancel ()
{
  {
    GumV8PlatformLocker locker (platform);
    if (state != kScheduled)
      return;
    state = kCanceling;
  }

  g_source_destroy (source);

  {
    GumV8PlatformLocker locker (platform);
    state = kCanceled;
    g_cond_signal (&cond);
  }
}

void
GumV8DelayedThreadPoolOperation::Await ()
{
  GumV8PlatformLocker locker (platform);
  while (state != kCompleted && state != kCanceled)
    g_cond_wait (&cond, &platform->mutex);
}

GumV8ForegroundTaskRunner::GumV8ForegroundTaskRunner (GumV8Platform * platform,
                                                      Isolate * isolate)
  : platform (platform),
    isolate (isolate),
    pending (g_hash_table_new (NULL, NULL))
{
}

GumV8ForegroundTaskRunner::~GumV8ForegroundTaskRunner ()
{
  g_hash_table_unref (pending);
}

void
GumV8ForegroundTaskRunner::PostTask (std::unique_ptr<Task> task)
{
  std::shared_ptr<Task> t (std::move (task));
  platform->ScheduleOnJSThread ([=]()
      {
        Run (t.get ());
      });
}

void
GumV8ForegroundTaskRunner::PostNonNestableTask (std::unique_ptr<Task> task)
{
  PostTask (std::move (task));
}

void
GumV8ForegroundTaskRunner::PostDelayedTask (std::unique_ptr<Task> task,
                                            double delay_in_seconds)
{
  std::shared_ptr<Task> t (std::move (task));
  platform->ScheduleOnJSThreadDelayed (delay_in_seconds * 1000.0, [=]()
      {
        Run (t.get ());
      });
}

void
GumV8ForegroundTaskRunner::PostNonNestableDelayedTask (
    std::unique_ptr<Task> task,
    double delay_in_seconds)
{
  PostDelayedTask (std::move (task), delay_in_seconds);
}

void
GumV8ForegroundTaskRunner::PostIdleTask (std::unique_ptr<IdleTask> task)
{
  std::shared_ptr<IdleTask> t (std::move (task));
  platform->ScheduleOnJSThread (G_PRIORITY_LOW, [=]()
      {
        Run (t.get ());
      });
}

bool
GumV8ForegroundTaskRunner::IdleTasksEnabled ()
{
  return true;
}

bool
GumV8ForegroundTaskRunner::NonNestableTasksEnabled () const
{
  return true;
}

bool
GumV8ForegroundTaskRunner::NonNestableDelayedTasksEnabled () const
{
  return true;
}

void
GumV8ForegroundTaskRunner::Run (Task * task)
{
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  task->Run ();
}

void
GumV8ForegroundTaskRunner::Run (IdleTask * task)
{
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  const double deadline_in_seconds =
      platform->MonotonicallyIncreasingTime () + (1.0 / 60.0);
  task->Run (deadline_in_seconds);
}

GumV8JobState::GumV8JobState (GumV8Platform * platform,
                              std::unique_ptr<JobTask> job_task,
                              TaskPriority priority,
                              size_t num_worker_threads)
  : isolate (Isolate::GetCurrent ()),
    platform (platform),
    job_task (std::move (job_task)),
    priority (priority),
    num_worker_threads (std::min (num_worker_threads, kMaxWorkerPerJob))
{
  g_mutex_init (&mutex);
  g_cond_init (&worker_released_cond);
}

GumV8JobState::~GumV8JobState ()
{
  g_assert (active_workers == 0);

  g_cond_clear (&worker_released_cond);
  g_mutex_clear (&mutex);
}

void
GumV8JobState::NotifyConcurrencyIncrease ()
{
  if (is_canceled.load (std::memory_order_relaxed))
    return;

  size_t num_tasks_to_post = 0;
  TaskPriority priority_to_use;
  {
    GumMutexLocker locker (&mutex);

    const size_t max_concurrency = CappedMaxConcurrency (active_workers);
    if (active_workers + pending_tasks < max_concurrency)
    {
      num_tasks_to_post = max_concurrency - active_workers - pending_tasks;
      pending_tasks += num_tasks_to_post;
    }

    priority_to_use = priority;
  }

  for (size_t i = 0; i != num_tasks_to_post; i++)
  {
    CallOnWorkerThread (priority_to_use, std::make_unique<GumV8JobWorker> (
        shared_from_this (), job_task.get ()));
  }
}

uint8_t
GumV8JobState::AcquireTaskId ()
{
  uint32_t task_ids = assigned_task_ids.load (std::memory_order_relaxed);
  uint32_t new_task_ids = 0;

  uint8_t task_id = 0;
  do
  {
    task_id = g_bit_nth_lsf (~task_ids, -1);
    new_task_ids = task_ids | (uint32_t (1) << task_id);
  }
  while (!assigned_task_ids.compare_exchange_weak (task_ids, new_task_ids,
      std::memory_order_acquire, std::memory_order_relaxed));

  return task_id;
}

void
GumV8JobState::ReleaseTaskId (uint8_t task_id)
{
  assigned_task_ids.fetch_and (~(uint32_t (1) << task_id),
      std::memory_order_release);
}

void
GumV8JobState::Join ()
{
  bool can_run = false;

  {
    GumMutexLocker locker (&mutex);

    priority = TaskPriority::kUserBlocking;
    num_worker_threads = platform->NumberOfWorkerThreads () + 1;
    active_workers++;

    can_run = WaitForParticipationOpportunityLocked ();
  }

  GumV8JobState::JobDelegate delegate (this, true);
  while (can_run)
  {
    {
      Locker locker (isolate);
      job_task->Run (&delegate);
    }

    GumMutexLocker locker (&mutex);
    can_run = WaitForParticipationOpportunityLocked ();
  }
}

void
GumV8JobState::CancelAndWait ()
{
  GumMutexLocker locker (&mutex);

  is_canceled.store (true, std::memory_order_relaxed);

  while (active_workers > 0)
    g_cond_wait (&worker_released_cond, &mutex);
}

void
GumV8JobState::CancelAndDetach ()
{
  GumMutexLocker locker (&mutex);

  is_canceled.store (true, std::memory_order_relaxed);
}

bool
GumV8JobState::IsActive ()
{
  GumMutexLocker locker (&mutex);

  return job_task->GetMaxConcurrency (active_workers) != 0 ||
      active_workers != 0;
}

void
GumV8JobState::UpdatePriority (TaskPriority new_priority)
{
  GumMutexLocker locker (&mutex);

  priority = new_priority;
}

bool
GumV8JobState::CanRunFirstTask ()
{
  GumMutexLocker locker (&mutex);

  pending_tasks--;

  if (is_canceled.load (std::memory_order_relaxed))
    return false;

  const size_t max_workers = std::min (
      job_task->GetMaxConcurrency (active_workers), num_worker_threads);
  if (active_workers >= max_workers)
    return false;

  active_workers++;
  return true;
}

bool
GumV8JobState::DidRunTask ()
{
  size_t num_tasks_to_post = 0;
  TaskPriority priority_to_use;
  {
    GumMutexLocker locker (&mutex);

    const size_t max_concurrency = CappedMaxConcurrency (active_workers - 1);
    if (is_canceled.load (std::memory_order_relaxed) ||
        active_workers > max_concurrency)
    {
      active_workers--;
      g_cond_signal (&worker_released_cond);
      return false;
    }

    if (active_workers + pending_tasks < max_concurrency)
    {
      num_tasks_to_post = max_concurrency - active_workers - pending_tasks;
      pending_tasks += num_tasks_to_post;
    }

    priority_to_use = priority;
  }

  for (size_t i = 0; i != num_tasks_to_post; i++)
  {
    CallOnWorkerThread (priority_to_use, std::make_unique<GumV8JobWorker> (
        shared_from_this (), job_task.get ()));
  }

  return true;
}

bool
GumV8JobState::WaitForParticipationOpportunityLocked ()
{
  size_t max_concurrency = CappedMaxConcurrency (active_workers - 1);
  while (active_workers > max_concurrency && active_workers > 1)
  {
    g_cond_wait (&worker_released_cond, &mutex);
    max_concurrency = CappedMaxConcurrency (active_workers - 1);
  }

  if (active_workers <= max_concurrency)
    return true;

  g_assert (active_workers == 1);
  g_assert (max_concurrency == 0);

  active_workers = 0;
  is_canceled.store (true, std::memory_order_relaxed);

  return false;
}

size_t
GumV8JobState::CappedMaxConcurrency (size_t worker_count) const
{
  return std::min (job_task->GetMaxConcurrency (worker_count),
      num_worker_threads);
}

void
GumV8JobState::CallOnWorkerThread (TaskPriority with_priority,
                                   std::unique_ptr<Task> task)
{
  std::shared_ptr<Task> t (std::move (task));
  Isolate * job_isolate = this->isolate;
  auto op = platform->ScheduleOnThreadPool ([=]()
      {
        Locker locker (job_isolate);
        t->Run ();
      });

  {
    GumV8PlatformLocker locker (platform);
    op->
```