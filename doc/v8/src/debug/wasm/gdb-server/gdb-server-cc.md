Response:
Let's break down the thought process for analyzing the `gdb-server.cc` code.

1. **Understand the Goal:** The first thing is to recognize the directory: `v8/src/debug/wasm/gdb-server`. This immediately tells us it's related to debugging WebAssembly code within the V8 JavaScript engine, specifically using a GDB-like protocol for remote debugging.

2. **High-Level Structure Scan:**  Quickly scan the file for key elements:
    * Includes: Note the headers, particularly those from the `src/debug` and `src/api` directories. This reinforces the debugging and V8 API connection. The `<inttypes.h>` and `<functional>` hints at low-level data handling and function objects.
    * Namespaces: See `v8::internal::wasm::gdb_server`. This confirms the location within V8's internal structure.
    * Classes: Identify the main classes: `TaskRunner` and `GdbServer`, and the nested `DebugDelegate`. This suggests a multi-threaded design with tasks and a delegate pattern for handling debugging events.
    * Static members/constants:  The `kMaxWasmCallStack` constant is interesting.

3. **Focus on Key Classes and their Responsibilities:**

    * **`TaskRunner`:**  The comments clearly explain its purpose: managing tasks on a specific thread. The internal `Task` class and the use of semaphores point to thread synchronization. The `Run()`, `Terminate()`, and `Append()` methods are crucial for understanding its lifecycle and how tasks are added. The use of a `LockedQueue` is also a significant detail indicating thread-safe task management.

    * **`GdbServer`:** This is the central class. Its constructor, `Create()`, destructor, and methods like `GetLoadedModules`, `AddBreakpoint`, `GetWasmMemory`, etc., suggest it handles the core logic of the GDB server. The `RunSyncTask` template function is a key mechanism for interacting with the `TaskRunner`. The presence of `GdbServerThread` as a member suggests a separate thread for GDB communication. The `isolate_delegates_` and `scripts_` members hint at managing multiple V8 isolates and loaded WASM modules.

    * **`GdbServer::DebugDelegate`:** The name "Delegate" is a strong hint. The methods like `ScriptCompiled`, `BreakProgramRequested`, and `ExceptionThrown` clearly indicate this class handles debugging events triggered by the V8 engine. Its connection to `GdbServer` is evident from the constructor.

4. **Analyze Key Methods in Detail:**

    * **`TaskRunner::Run()`:**  The `while` loop and the condition `nested_loop_count_ == loop_number` suggests support for nested message loops, which is common in event-driven systems.
    * **`TaskRunner::Append()` and `RunSyncTask()`:** Understand how tasks are added to the queue and how `RunSyncTask` uses semaphores to make calls synchronous. This is a critical pattern in the code.
    * **`GdbServer::Create()`:**  See how it instantiates `GdbServerThread`.
    * **Methods like `GetWasmGlobal`, `GetWasmMemory`, `AddBreakpoint`, etc.:** Notice the consistent pattern of using `RunSyncTask` to execute the core logic on the isolate's thread. This highlights the thread safety concerns and the need for synchronization.
    * **`GdbServer::AddIsolate` and `RemoveIsolate`:** Understand how the GDB server tracks V8 isolates.
    * **`GdbServer::DebugDelegate::ScriptCompiled`:**  See how it registers new WASM modules.
    * **`GdbServer::DebugDelegate::BreakProgramRequested` and `ExceptionThrown`:** Understand how these methods interact with `GdbServer` to handle breakpoints and exceptions.

5. **Infer Functionality from the Methods:** By looking at the methods' names and their parameters, we can deduce the functionalities provided by the GDB server:
    * Getting loaded modules and module information.
    * Accessing WASM globals, locals, and stack values.
    * Reading WASM memory and data segments.
    * Managing breakpoints.
    * Getting the WASM call stack.
    * Handling program breaks and exceptions.

6. **Address Specific Questions from the Prompt:**

    * **Functionality Listing:** Summarize the inferred functionalities.
    * **`.tq` extension:** Check the file extension and state it's `.cc`, not `.tq`.
    * **Relationship to JavaScript:**  Explain that it debugs WASM, which often interacts with JavaScript. Give a simple JavaScript example of loading and running WASM.
    * **Code Logic Reasoning:** Select a relatively straightforward method like `GetWasmGlobal` or `AddBreakpoint` and provide hypothetical input and expected output, focusing on the thread interaction and potential success/failure scenarios.
    * **Common Programming Errors:** Think about typical concurrency issues that might arise with a multi-threaded design like this (race conditions, deadlocks) and relate them to the use of semaphores and locked queues. Also, consider errors related to invalid input (e.g., out-of-bounds access).

7. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Make sure the JavaScript example is simple and relevant. Ensure the input/output examples are easy to understand. Double-check the explanation of potential errors.

This methodical approach, starting with the big picture and gradually diving into details, allows for a comprehensive understanding of the code and helps in answering the specific questions effectively. The focus on class responsibilities, thread synchronization mechanisms, and the interactions between different parts of the code is key to understanding its functionality.
`v8/src/debug/wasm/gdb-server/gdb-server.cc` 是一个 V8 源代码文件，它实现了用于调试 WebAssembly 代码的 GDB 远程调试服务器。

**功能列表:**

1. **GDB 远程协议支持:**  它实现了与 GDB 调试器通信所需的 GDB 远程串行协议（Remote Serial Protocol）。这允许开发者使用 GDB 连接到 V8 引擎并调试正在执行的 WebAssembly 代码。

2. **线程管理:**  它创建并管理一个单独的线程 (`GdbServerThread`) 来处理与 GDB 调试器的通信，从而避免阻塞 V8 的主执行线程。

3. **任务调度:**  它使用 `TaskRunner` 类来管理需要在 V8 主线程上执行的任务。由于 GDB 服务器的操作（例如访问 WASM 模块数据）需要访问 V8 内部状态，因此必须在拥有这些状态的 V8 主线程上执行。`TaskRunner` 使用锁定的队列和信号量来实现线程安全的消息传递。

4. **Isolate 管理:**  它跟踪连接到 GDB 服务器的 V8 `Isolate` 实例。一个 `Isolate` 代表一个独立的 JavaScript 和 WebAssembly 执行环境。

5. **WASM 模块管理:**  它维护一个已加载的 WASM 模块列表 (`scripts_`)，并为每个模块关联一个 `WasmModuleDebug` 对象，该对象提供了调试 WASM 模块所需的接口。

6. **断点管理:**  它允许添加和删除 WASM 代码中的断点。当执行到断点时，V8 引擎会暂停执行并将控制权交给 GDB 调试器。

7. **调用栈检索:**  它提供了获取当前 WASM 调用栈的功能，允许调试器查看函数调用链。

8. **内存和数据访问:**  它允许 GDB 调试器读取 WASM 模块的内存和数据段。

9. **全局变量、局部变量和栈值访问:**  它允许 GDB 调试器检查 WASM 函数的全局变量、局部变量和操作数栈上的值。

10. **单步执行支持:**  它支持单步执行 WASM 指令。

11. **暂停和恢复执行:**  它允许 GDB 调试器暂停和恢复 WASM 代码的执行。

12. **异常处理:**  当 WASM 代码抛出异常时，GDB 服务器可以捕获并通知调试器。

**关于文件扩展名和 Torque:**

`v8/src/debug/wasm/gdb-server/gdb-server.cc` 的文件扩展名是 `.cc`，这表示它是一个 C++ 源代码文件。因此，它不是一个 V8 Torque 源代码文件。Torque 文件的扩展名通常是 `.tq`。

**与 JavaScript 的关系及示例:**

`gdb-server.cc` 的功能与 JavaScript 有着密切的关系，因为它允许开发者调试在 V8 引擎中执行的 WebAssembly 代码。WebAssembly 经常被用作 JavaScript 的编译目标，以提高性能或使用其他语言编写代码。

以下是一个 JavaScript 示例，演示了如何加载和执行 WebAssembly 模块，而 `gdb-server.cc` 提供的 GDB 调试功能可以用于调试这个 WASM 模块：

```javascript
async function loadAndRunWasm() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);

  // 假设 WASM 模块导出一个名为 'add' 的函数
  const result = module.instance.exports.add(5, 3);
  console.log('WASM result:', result);
}

loadAndRunWasm();
```

当上述 JavaScript 代码执行时，如果启用了 V8 的 GDB 远程调试功能，并且 GDB 连接到了 V8 进程，开发者就可以在 `my_wasm_module.wasm` 的代码中设置断点，单步执行，查看变量等，就像调试本地 C/C++ 代码一样。`gdb-server.cc` 就是实现这种调试能力的关键组件。

**代码逻辑推理 (假设输入与输出):**

让我们以 `AddBreakpoint` 函数为例进行代码逻辑推理：

**假设输入:**

* `wasm_module_id`:  一个表示 WASM 模块 ID 的整数，例如 `123`。
* `offset`:  WASM 模块内的一个偏移量，表示要设置断点的指令地址，例如 `0x10`.

**代码逻辑:**

1. `AddBreakpoint` 函数被调用，传入 `wasm_module_id` 和 `offset`。
2. `RunSyncTask` 被调用，将一个 lambda 函数放入任务队列，该 lambda 函数将在 V8 主线程上执行。
3. 在 V8 主线程上，lambda 函数执行：
   - 它尝试通过 `GetModuleDebugHandler` 获取与 `wasm_module_id` 对应的 `WasmModuleDebug` 对象。
   - 如果找到了 `WasmModuleDebug` 对象，则调用其 `AddBreakpoint` 方法，传入 `offset` 和一个用于存储新断点 ID 的变量 `breakpoint_id`。
   - 如果 `module_debug->AddBreakpoint` 返回 `true` (表示成功添加断点)，则在 `breakpoints_` 映射中记录断点信息，键为 `wasm_addr_t(wasm_module_id, offset)`，值为 `breakpoint_id`。
   - 设置 `result` 为 `true`。

**预期输出:**

* 如果成功添加断点：`AddBreakpoint` 函数返回 `true`，并且 GDB 调试器会在指定的 WASM 模块和偏移量处命中该断点。
* 如果 `wasm_module_id` 无效或无法找到对应的 `WasmModuleDebug` 对象：`AddBreakpoint` 函数返回 `false`，断点不会被添加。

**用户常见的编程错误 (涉及多线程):**

由于 `gdb-server.cc` 涉及多线程编程，用户可能会遇到一些常见的并发错误：

1. **数据竞争 (Race Condition):**  当多个线程同时访问和修改共享数据，且没有适当的同步机制时，可能导致数据不一致。在 `gdb-server.cc` 中，`TaskRunner` 和 `RunSyncTask` 的使用就是为了避免在 GDB 服务器线程和 V8 主线程之间直接访问共享数据而导致的数据竞争。

   **示例错误 (假设没有 `TaskRunner`):**

   ```c++
   // 假设 GdbServer 有一个成员变量 `wasm_memory`
   class GdbServer {
    public:
     std::vector<uint8_t> wasm_memory;
   };

   // GDB 服务器线程尝试修改内存
   void GdbServerThread::HandleMemoryWrite(uint32_t offset, uint8_t value) {
     gdb_server_->wasm_memory[offset] = value; // 可能与主线程的读取操作冲突
   }

   // V8 主线程尝试读取内存
   void WasmExecution::ReadMemory(uint32_t offset) {
     uint8_t data = gdb_server_->wasm_memory[offset]; // 可能读取到不一致的数据
   }
   ```

   **修正:** 使用 `TaskRunner` 将内存修改操作放入 V8 主线程的任务队列，确保串行执行。

2. **死锁 (Deadlock):** 当两个或多个线程相互等待对方释放资源时，就会发生死锁。在 `gdb-server.cc` 中，虽然使用了锁，但设计上尽量避免了复杂的锁依赖关系。

   **示例错误 (假设不当的锁使用):**

   ```c++
   std::mutex mutex1, mutex2;

   // 线程 1
   void thread1_func() {
     std::lock_guard<std::mutex> lock1(mutex1);
     // ... 执行一些操作 ...
     std::lock_guard<std::mutex> lock2(mutex2); // 等待 mutex2
     // ...
   }

   // 线程 2
   void thread2_func() {
     std::lock_guard<std::mutex> lock2(mutex2);
     // ... 执行一些操作 ...
     std::lock_guard<std::mutex> lock1(mutex1); // 等待 mutex1，造成死锁
     // ...
   }
   ```

   **避免:**  保持锁的获取顺序一致，或者使用无锁数据结构和算法。`gdb-server.cc` 中 `TaskRunner` 使用的 `LockedQueue` 可以看作是一种轻量级的同步机制，避免了显式的多重锁。

3. **活锁 (Livelock):**  线程没有被阻塞，但由于某种条件不断变化，导致它们一直重复尝试相同的操作，而无法取得进展。这在 `gdb-server.cc` 的场景中不太常见，因为主要的同步机制是基于队列和信号量的阻塞等待。

4. **不正确的同步:**  使用了同步机制，但使用方式不当，导致仍然出现并发问题。例如，忘记在所有访问共享资源的地方加锁。

   **示例错误:**

   ```c++
   class SharedData {
    public:
     int counter = 0;
     std::mutex counter_mutex;
   };

   void increment(SharedData& data) {
     std::lock_guard<std::mutex> lock(data.counter_mutex);
     data.counter++; // 正确加锁
   }

   void read(SharedData& data) {
     // 忘记加锁直接读取
     int value = data.counter; // 可能读取到不一致的值
   }
   ```

   **修正:** 确保所有对共享状态的访问都受到适当的同步机制保护。

理解这些常见的并发错误对于开发和维护像 `gdb-server.cc` 这样的多线程代码至关重要。V8 的开发者通过使用 `TaskRunner` 和其他同步原语来小心地管理线程间的交互，以保证代码的正确性和效率。

Prompt: 
```
这是目录为v8/src/debug/wasm/gdb-server/gdb-server.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/debug/wasm/gdb-server/gdb-server.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/debug/wasm/gdb-server/gdb-server.h"

#include <inttypes.h>
#include <functional>
#include "src/api/api-inl.h"
#include "src/api/api.h"
#include "src/debug/debug.h"
#include "src/debug/wasm/gdb-server/gdb-server-thread.h"
#include "src/utils/locked-queue-inl.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace gdb_server {

static const uint32_t kMaxWasmCallStack = 20;

// A TaskRunner is an object that runs posted tasks (in the form of closure
// objects). Tasks are queued and run, in order, in the thread where the
// TaskRunner::RunMessageLoop() is called.
class TaskRunner {
 public:
  // Class Task wraps a std::function with a semaphore to signal its completion.
  // This logic would be neatly implemented with std::packaged_tasks but we
  // cannot use <future> in V8.
  class Task {
   public:
    Task(base::Semaphore* ready_semaphore, std::function<void()> func)
        : ready_semaphore_(ready_semaphore), func_(func) {}

    void Run() {
      func_();
      ready_semaphore_->Signal();
    }

    // A semaphore object passed by the thread that posts a task.
    // The sender can Wait on this semaphore to block until the task has
    // completed execution in the TaskRunner thread.
    base::Semaphore* ready_semaphore_;

    // The function to run.
    std::function<void()> func_;
  };

  TaskRunner()
      : process_queue_semaphore_(0),
        nested_loop_count_(0),
        is_terminated_(false) {}

  TaskRunner(const TaskRunner&) = delete;
  TaskRunner& operator=(const TaskRunner&) = delete;

  // Starts the task runner. All tasks posted are run, in order, in the thread
  // that calls this function.
  void Run() {
    is_terminated_ = false;
    int loop_number = ++nested_loop_count_;
    while (nested_loop_count_ == loop_number && !is_terminated_) {
      std::shared_ptr<Task> task = GetNext();
      if (task) {
        task->Run();
      }
    }
  }

  // Terminates the task runner. Tasks that are still pending in the queue are
  // not discarded and will be executed when the task runner is restarted.
  void Terminate() {
    DCHECK_LT(0, nested_loop_count_);
    --nested_loop_count_;

    is_terminated_ = true;
    process_queue_semaphore_.Signal();
  }

  // Posts a task to the task runner, to be executed in the task runner thread.
  template <typename Functor>
  auto Append(base::Semaphore* ready_semaphore, Functor&& task) {
    queue_.Enqueue(std::make_shared<Task>(ready_semaphore, task));
    process_queue_semaphore_.Signal();
  }

 private:
  std::shared_ptr<Task> GetNext() {
    while (!is_terminated_) {
      if (queue_.IsEmpty()) {
        process_queue_semaphore_.Wait();
      }

      std::shared_ptr<Task> task;
      if (queue_.Dequeue(&task)) {
        return task;
      }
    }
    return nullptr;
  }

  LockedQueue<std::shared_ptr<Task>> queue_;
  v8::base::Semaphore process_queue_semaphore_;
  int nested_loop_count_;
  std::atomic<bool> is_terminated_;
};

GdbServer::GdbServer() : has_module_list_changed_(false) {
  task_runner_ = std::make_unique<TaskRunner>();
}

template <typename Functor>
auto GdbServer::RunSyncTask(Functor&& callback) const {
  // Executed in the GDBServerThread.
  v8::base::Semaphore ready_semaphore(0);
  task_runner_->Append(&ready_semaphore, callback);
  ready_semaphore.Wait();
}

// static
std::unique_ptr<GdbServer> GdbServer::Create() {
  DCHECK(v8_flags.wasm_gdb_remote);

  std::unique_ptr<GdbServer> gdb_server(new GdbServer());

  // Spawns the GDB-stub thread where all the communication with the debugger
  // happens.
  gdb_server->thread_ = std::make_unique<GdbServerThread>(gdb_server.get());
  if (!gdb_server->thread_->StartAndInitialize()) {
    TRACE_GDB_REMOTE(
        "Cannot initialize thread, GDB-remote debugging will be disabled.\n");
    return nullptr;
  }
  return gdb_server;
}

GdbServer::~GdbServer() {
  // All Isolates have been deregistered.
  DCHECK(isolate_delegates_.empty());

  if (thread_) {
    // Waits for the GDB-stub thread to terminate.
    thread_->Stop();
    thread_->Join();
  }
}

void GdbServer::RunMessageLoopOnPause() { task_runner_->Run(); }

void GdbServer::QuitMessageLoopOnPause() { task_runner_->Terminate(); }

std::vector<GdbServer::WasmModuleInfo> GdbServer::GetLoadedModules(
    bool clear_module_list_changed_flag) {
  // Executed in the GDBServerThread.
  std::vector<GdbServer::WasmModuleInfo> modules;

  RunSyncTask([this, &modules, clear_module_list_changed_flag]() {
    // Executed in the isolate thread.
    for (const auto& pair : scripts_) {
      uint32_t module_id = pair.first;
      const WasmModuleDebug& module_debug = pair.second;
      modules.push_back({module_id, module_debug.GetModuleName()});
    }

    if (clear_module_list_changed_flag) has_module_list_changed_ = false;
  });
  return modules;
}

bool GdbServer::GetModuleDebugHandler(uint32_t module_id,
                                      WasmModuleDebug** wasm_module_debug) {
  // Always executed in the isolate thread.
  ScriptsMap::iterator scriptIterator = scripts_.find(module_id);
  if (scriptIterator != scripts_.end()) {
    *wasm_module_debug = &scriptIterator->second;
    return true;
  }
  wasm_module_debug = nullptr;
  return false;
}

bool GdbServer::GetWasmGlobal(uint32_t frame_index, uint32_t index,
                              uint8_t* buffer, uint32_t buffer_size,
                              uint32_t* size) {
  // Executed in the GDBServerThread.
  bool result = false;
  RunSyncTask([this, &result, frame_index, index, buffer, buffer_size, size]() {
    // Executed in the isolate thread.
    result = WasmModuleDebug::GetWasmGlobal(GetTarget().GetCurrentIsolate(),
                                            frame_index, index, buffer,
                                            buffer_size, size);
  });
  return result;
}

bool GdbServer::GetWasmLocal(uint32_t frame_index, uint32_t index,
                             uint8_t* buffer, uint32_t buffer_size,
                             uint32_t* size) {
  // Executed in the GDBServerThread.
  bool result = false;
  RunSyncTask([this, &result, frame_index, index, buffer, buffer_size, size]() {
    // Executed in the isolate thread.
    result = WasmModuleDebug::GetWasmLocal(GetTarget().GetCurrentIsolate(),
                                           frame_index, index, buffer,
                                           buffer_size, size);
  });
  return result;
}

bool GdbServer::GetWasmStackValue(uint32_t frame_index, uint32_t index,
                                  uint8_t* buffer, uint32_t buffer_size,
                                  uint32_t* size) {
  // Executed in the GDBServerThread.
  bool result = false;
  RunSyncTask([this, &result, frame_index, index, buffer, buffer_size, size]() {
    // Executed in the isolate thread.
    result = WasmModuleDebug::GetWasmStackValue(GetTarget().GetCurrentIsolate(),
                                                frame_index, index, buffer,
                                                buffer_size, size);
  });
  return result;
}

uint32_t GdbServer::GetWasmMemory(uint32_t module_id, uint32_t offset,
                                  uint8_t* buffer, uint32_t size) {
  // Executed in the GDBServerThread.
  uint32_t bytes_read = 0;
  RunSyncTask([this, &bytes_read, module_id, offset, buffer, size]() {
    // Executed in the isolate thread.
    WasmModuleDebug* module_debug = nullptr;
    if (GetModuleDebugHandler(module_id, &module_debug)) {
      bytes_read = module_debug->GetWasmMemory(GetTarget().GetCurrentIsolate(),
                                               offset, buffer, size);
    }
  });
  return bytes_read;
}

uint32_t GdbServer::GetWasmData(uint32_t module_id, uint32_t offset,
                                uint8_t* buffer, uint32_t size) {
  // Executed in the GDBServerThread.
  uint32_t bytes_read = 0;
  RunSyncTask([this, &bytes_read, module_id, offset, buffer, size]() {
    // Executed in the isolate thread.
    WasmModuleDebug* module_debug = nullptr;
    if (GetModuleDebugHandler(module_id, &module_debug)) {
      bytes_read = module_debug->GetWasmData(GetTarget().GetCurrentIsolate(),
                                             offset, buffer, size);
    }
  });
  return bytes_read;
}

uint32_t GdbServer::GetWasmModuleBytes(wasm_addr_t wasm_addr, uint8_t* buffer,
                                       uint32_t size) {
  // Executed in the GDBServerThread.
  uint32_t bytes_read = 0;
  RunSyncTask([this, &bytes_read, wasm_addr, buffer, size]() {
    // Executed in the isolate thread.
    WasmModuleDebug* module_debug;
    if (GetModuleDebugHandler(wasm_addr.ModuleId(), &module_debug)) {
      bytes_read = module_debug->GetWasmModuleBytes(wasm_addr, buffer, size);
    }
  });
  return bytes_read;
}

bool GdbServer::AddBreakpoint(uint32_t wasm_module_id, uint32_t offset) {
  // Executed in the GDBServerThread.
  bool result = false;
  RunSyncTask([this, &result, wasm_module_id, offset]() {
    // Executed in the isolate thread.
    WasmModuleDebug* module_debug;
    if (GetModuleDebugHandler(wasm_module_id, &module_debug)) {
      int breakpoint_id = 0;
      if (module_debug->AddBreakpoint(offset, &breakpoint_id)) {
        breakpoints_[wasm_addr_t(wasm_module_id, offset)] = breakpoint_id;
        result = true;
      }
    }
  });
  return result;
}

bool GdbServer::RemoveBreakpoint(uint32_t wasm_module_id, uint32_t offset) {
  // Executed in the GDBServerThread.
  bool result = false;
  RunSyncTask([this, &result, wasm_module_id, offset]() {
    // Executed in the isolate thread.
    BreakpointsMap::iterator it =
        breakpoints_.find(wasm_addr_t(wasm_module_id, offset));
    if (it != breakpoints_.end()) {
      int breakpoint_id = it->second;
      breakpoints_.erase(it);

      WasmModuleDebug* module_debug;
      if (GetModuleDebugHandler(wasm_module_id, &module_debug)) {
        module_debug->RemoveBreakpoint(offset, breakpoint_id);
        result = true;
      }
    }
  });
  return result;
}

std::vector<wasm_addr_t> GdbServer::GetWasmCallStack() const {
  // Executed in the GDBServerThread.
  std::vector<wasm_addr_t> result;
  RunSyncTask([this, &result]() {
    // Executed in the isolate thread.
    result = GetTarget().GetCallStack();
  });
  return result;
}

void GdbServer::AddIsolate(Isolate* isolate) {
  // Executed in the isolate thread.
  if (isolate_delegates_.find(isolate) == isolate_delegates_.end()) {
    isolate_delegates_[isolate] =
        std::make_unique<DebugDelegate>(isolate, this);
  }
}

void GdbServer::RemoveIsolate(Isolate* isolate) {
  // Executed in the isolate thread.
  auto it = isolate_delegates_.find(isolate);
  if (it != isolate_delegates_.end()) {
    for (auto it = scripts_.begin(); it != scripts_.end();) {
      if (it->second.GetIsolate() == isolate) {
        it = scripts_.erase(it);
        has_module_list_changed_ = true;
      } else {
        ++it;
      }
    }
    isolate_delegates_.erase(it);
  }
}

void GdbServer::Suspend() {
  // Executed in the GDBServerThread.
  auto it = isolate_delegates_.begin();
  if (it != isolate_delegates_.end()) {
    Isolate* isolate = it->first;
    v8::Isolate* v8Isolate = (v8::Isolate*)isolate;
    v8Isolate->RequestInterrupt(
        // Executed in the isolate thread.
        [](v8::Isolate* isolate, void*) {
          if (v8::debug::AllFramesOnStackAreBlackboxed(isolate)) {
            v8::debug::SetBreakOnNextFunctionCall(isolate);
          } else {
            v8::debug::BreakRightNow(isolate);
          }
        },
        this);
  }
}

void GdbServer::PrepareStep() {
  // Executed in the GDBServerThread.
  wasm_addr_t pc = GetTarget().GetCurrentPc();
  RunSyncTask([this, pc]() {
    // Executed in the isolate thread.
    WasmModuleDebug* module_debug;
    if (GetModuleDebugHandler(pc.ModuleId(), &module_debug)) {
      module_debug->PrepareStep();
    }
  });
}

void GdbServer::AddWasmModule(uint32_t module_id,
                              Local<debug::WasmScript> wasm_script) {
  // Executed in the isolate thread.
  DCHECK_EQ(Script::Type::kWasm, Utils::OpenHandle(*wasm_script)->type());
  v8::Isolate* isolate = wasm_script->GetIsolate();
  scripts_.insert(
      std::make_pair(module_id, WasmModuleDebug(isolate, wasm_script)));
  has_module_list_changed_ = true;

  if (v8_flags.wasm_pause_waiting_for_debugger && scripts_.size() == 1) {
    TRACE_GDB_REMOTE("Paused, waiting for a debugger to attach...\n");
    Suspend();
  }
}

Target& GdbServer::GetTarget() const { return thread_->GetTarget(); }

// static
std::atomic<uint32_t> GdbServer::DebugDelegate::id_s;

GdbServer::DebugDelegate::DebugDelegate(Isolate* isolate, GdbServer* gdb_server)
    : isolate_(isolate), id_(id_s++), gdb_server_(gdb_server) {
  isolate_->SetCaptureStackTraceForUncaughtExceptions(
      true, kMaxWasmCallStack, v8::StackTrace::kOverview);

  // Register the delegate
  isolate_->debug()->SetDebugDelegate(this);
  v8::debug::EnterDebuggingForIsolate((v8::Isolate*)isolate_);
  v8::debug::ChangeBreakOnException((v8::Isolate*)isolate_,
                                    v8::debug::BreakOnUncaughtException);
}

GdbServer::DebugDelegate::~DebugDelegate() {
  // Deregister the delegate
  isolate_->debug()->SetDebugDelegate(nullptr);
}

void GdbServer::DebugDelegate::ScriptCompiled(Local<debug::Script> script,
                                              bool is_live_edited,
                                              bool has_compile_error) {
  // Executed in the isolate thread.
  if (script->IsWasm()) {
    DCHECK_EQ(reinterpret_cast<v8::Isolate*>(isolate_), script->GetIsolate());
    gdb_server_->AddWasmModule(GetModuleId(script->Id()),
                               script.As<debug::WasmScript>());
  }
}

void GdbServer::DebugDelegate::BreakProgramRequested(
    // Executed in the isolate thread.
    Local<v8::Context> paused_context,
    const std::vector<debug::BreakpointId>& inspector_break_points_hit,
    v8::debug::BreakReasons break_reasons) {
  gdb_server_->GetTarget().OnProgramBreak(
      isolate_, WasmModuleDebug::GetCallStack(id_, isolate_));
  gdb_server_->RunMessageLoopOnPause();
}

void GdbServer::DebugDelegate::ExceptionThrown(
    // Executed in the isolate thread.
    Local<v8::Context> paused_context, Local<Value> exception,
    Local<Value> promise, bool is_uncaught,
    debug::ExceptionType exception_type) {
  if (exception_type == v8::debug::kException && is_uncaught) {
    gdb_server_->GetTarget().OnException(
        isolate_, WasmModuleDebug::GetCallStack(id_, isolate_));
    gdb_server_->RunMessageLoopOnPause();
  }
}

bool GdbServer::DebugDelegate::IsFunctionBlackboxed(
    // Executed in the isolate thread.
    Local<debug::Script> script, const debug::Location& start,
    const debug::Location& end) {
  return false;
}

}  // namespace gdb_server
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```