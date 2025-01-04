Response: Let's break down the thought process for summarizing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and a JavaScript example demonstrating its connection. This means I need to understand *what* the code does and *why* it exists in the context of V8 (the JavaScript engine).

2. **Initial Scan for Keywords:** I'd start by quickly scanning the code for significant keywords and patterns. Terms like "gdb-server," "wasm," "debug," "breakpoint," "stack," "isolate," "task," "thread" jump out. These immediately suggest a debugging component for WebAssembly within V8, interacting with the GDB debugger.

3. **Identify Core Components:** Based on the keywords, I can start identifying the key components and their roles:
    * **`GdbServer` Class:** This is clearly the central class. Its methods suggest it manages debugging sessions.
    * **`GdbServerThread`:** This indicates that debugging operations run in a separate thread, which is important for avoiding blocking the main JavaScript execution.
    * **`TaskRunner`:**  This class manages asynchronous tasks, likely used to marshal operations between the GDB server thread and the main V8 isolate thread.
    * **`DebugDelegate`:** This class seems to act as an interface between the V8 debugger and the GDB server, handling events like breakpoints and exceptions.
    * **`WasmModuleDebug`:**  Although not directly in this file, its usage implies it handles debugging information for individual WebAssembly modules.

4. **Trace the Execution Flow (Conceptual):** I'd try to mentally trace how a debugging session might work:
    * A user (likely via GDB) wants to debug WebAssembly.
    * The `GdbServer` is created and starts its thread.
    * When a WebAssembly module is loaded in V8, the `DebugDelegate` informs the `GdbServer`.
    * Breakpoints are set in GDB, which are translated into actions within the `GdbServer`.
    * When execution hits a breakpoint or an exception occurs, the `DebugDelegate` pauses execution and informs the `GdbServer`.
    * The `GdbServer` then communicates with GDB, providing information like the call stack, local variables, and memory.
    * The user can then step through code, inspect variables, etc., and the `GdbServer` updates V8 accordingly.

5. **Focus on Key Functionalities:** Now, I'd go through the methods of `GdbServer` to understand its specific responsibilities:
    * **Initialization and Thread Management:** `Create()`, the constructor, destructor, and the management of `GdbServerThread`.
    * **Task Management:** The `TaskRunner` and `RunSyncTask()` are crucial for thread safety.
    * **Module Handling:**  `AddWasmModule()`, `GetLoadedModules()`, `GetModuleDebugHandler()`.
    * **Breakpoint Management:** `AddBreakpoint()`, `RemoveBreakpoint()`.
    * **Inspection:** `GetWasmGlobal()`, `GetWasmLocal()`, `GetWasmStackValue()`, `GetWasmMemory()`, `GetWasmData()`, `GetWasmModuleBytes()`, `GetWasmCallStack()`.
    * **Isolate Management:** `AddIsolate()`, `RemoveIsolate()`.
    * **Pausing and Stepping:** `Suspend()`, `PrepareStep()`, `RunMessageLoopOnPause()`, `QuitMessageLoopOnPause()`.

6. **Identify the JavaScript Connection:** The code interacts with V8 internals. WebAssembly is executed within V8. The debugging information being extracted is directly related to the state of the running JavaScript/WebAssembly code. The key connection points are:
    * **`v8::Isolate`:**  The fundamental unit of execution in V8.
    * **`v8::debug::WasmScript`:** Represents a WebAssembly module within the debugger.
    * **Callbacks and Events:** The `DebugDelegate` receives callbacks from the V8 debugger, triggered by events in the JavaScript/WebAssembly execution.

7. **Craft the Summary:** Based on the above understanding, I can now write a concise summary, highlighting the key functions and their purpose. I'll emphasize the role of the `GdbServer` in facilitating GDB debugging of WebAssembly within V8.

8. **Develop the JavaScript Example:**  The goal here is to show *how* this C++ code enables debugging from a JavaScript perspective. I need to demonstrate:
    * Loading a WebAssembly module.
    * Setting a breakpoint (conceptually, as the C++ code handles the low-level interaction).
    * Triggering the breakpoint.
    * Inspecting the state (again, conceptually, as this is done via GDB).

    The `debugger;` statement is the most direct way to trigger a breakpoint in JavaScript/WebAssembly and thus connect to the underlying debugging infrastructure. Accessing WebAssembly memory via `WebAssembly.Memory` demonstrates the kind of inspection the C++ code supports.

9. **Refine and Explain:**  Finally, I'd review the summary and example for clarity and accuracy. I'd ensure the explanation clearly articulates the relationship between the C++ code and the JavaScript debugging experience. I'd emphasize that the C++ code is the *implementation* that makes the *JavaScript debugging* possible in this specific GDB scenario.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe the JavaScript example should involve directly interacting with some C++ API.
* **Correction:** The C++ code is an *internal* part of V8. The user doesn't directly call these C++ functions from JavaScript. The connection is at a lower level through the debugger interface. The `debugger;` statement is the appropriate JavaScript-level construct to demonstrate this.
* **Initial Thought:** Focus too much on the technical details of the `TaskRunner` implementation.
* **Correction:** The *purpose* of the `TaskRunner` (managing asynchronous tasks for thread safety) is more important for the summary than the specific implementation details with semaphores. Keep the summary high-level.
* **Initial Thought:**  Not clearly explain *why* this is useful.
* **Correction:**  Emphasize that this allows developers to use the powerful GDB debugger to understand the low-level execution of their WebAssembly code within a JavaScript environment.

By following these steps, combining keyword scanning, component identification, conceptual tracing, and focusing on the JavaScript connection, I can arrive at a comprehensive and accurate summary and illustrative example.
这个C++源代码文件 `gdb-server.cc` 是 V8 JavaScript 引擎中用于支持使用 GDB (GNU Debugger) 远程调试 WebAssembly 代码的功能的核心组件。它实现了一个 GDB 服务器，允许 GDB 连接到正在运行的 V8 实例并检查其内部状态，特别是与 WebAssembly 执行相关的部分。

以下是其主要功能归纳：

**核心功能：**

1. **GDB 远程调试支持:**  该文件实现了 V8 与 GDB 调试器进行通信的逻辑。这包括处理 GDB 发送的命令（例如，读取内存、读取寄存器、设置断点、继续执行）并向 GDB 返回必要的信息。

2. **WebAssembly 模块管理:** 它跟踪已加载的 WebAssembly 模块，并为每个模块维护调试信息 (`WasmModuleDebug`，虽然定义不在本文件中，但被广泛使用)。这允许 GDB 识别和操作特定的 WebAssembly 模块。

3. **断点管理:**  它允许 GDB 设置和移除 WebAssembly 代码中的断点。当执行到断点时，V8 会暂停执行并将控制权交给 GDB。

4. **调用栈检查:**  它提供了获取当前 WebAssembly 调用栈信息的能力，允许 GDB 用户查看函数调用链。

5. **内存和变量检查:**  它允许 GDB 读取 WebAssembly 实例的内存（线性内存和数据段）、全局变量、局部变量和栈上的值。

6. **单步执行:**  它支持单步执行 WebAssembly 代码，允许 GDB 用户逐指令地跟踪执行流程.

7. **线程管理:** 它使用 `GdbServerThread` 创建一个单独的线程来处理与 GDB 的通信，避免阻塞 V8 的主线程。

8. **异步任务处理 (`TaskRunner`):**  由于 GDB 服务器运行在单独的线程中，而 V8 的 JavaScript 执行在主线程中，因此需要一种机制来安全地在两个线程之间传递信息。`TaskRunner` 类提供了一种将任务（以闭包形式）提交到 V8 主线程执行的机制。这确保了对 V8 内部状态的访问是线程安全的。

9. **Isolate 管理:** V8 使用 isolates 来实现多个独立的 JavaScript 运行时。`GdbServer` 管理它所监控的 isolates，并为每个 isolate 创建一个 `DebugDelegate`。

10. **暂停和恢复执行:** 当遇到断点或需要检查状态时，`GdbServer` 可以暂停 V8 的执行，并在 GDB 操作完成后恢复执行。

**与 JavaScript 的关系及 JavaScript 示例:**

这个 C++ 代码直接支持了 JavaScript 开发者使用 GDB 调试 WebAssembly 代码的能力。虽然开发者不能直接调用这些 C++ 代码，但他们的行为会触发这些代码的执行。

**JavaScript 示例：**

假设我们有一个包含 WebAssembly 模块的 JavaScript 代码：

```javascript
// wasm.js
const response = await fetch('my_wasm_module.wasm');
const buffer = await response.arrayBuffer();
const module = await WebAssembly.compile(buffer);
const instance = await WebAssembly.instantiate(module);

instance.exports.add(5, 10); // 调用 WebAssembly 函数
```

当在启用了 GDB 远程调试的 V8 环境中运行这个 JavaScript 代码时，开发者可以使用 GDB 连接到 V8 进程，并对 `my_wasm_module.wasm` 中的代码进行调试。

**GDB 操作示例 (并非 JavaScript 代码，而是在 GDB 中执行的命令):**

1. **连接到 V8 进程:**
   ```gdb
   target remote :5005  // 假设 GDB 服务器监听在 5005 端口
   ```

2. **列出加载的 WebAssembly 模块:**  GDB 可以使用特定的命令（由 `gdb-server.cc` 实现）来获取加载的 WebAssembly 模块的信息。

3. **在 WebAssembly 函数中设置断点:**
   ```gdb
   break my_wasm_module.wasm:10 // 在 wasm 模块的偏移量 10 处设置断点
   ```

4. **继续执行:**
   ```gdb
   continue
   ```

当 JavaScript 代码执行到 `instance.exports.add(5, 10)` 并命中在 WebAssembly 代码中设置的断点时，V8 会暂停，GDB 可以检查：

* **调用栈:** 查看 WebAssembly 函数的调用链。
* **局部变量:**  查看 `add` 函数的参数值。
* **内存:**  查看 WebAssembly 模块的线性内存内容。
* **全局变量:** 查看 WebAssembly 模块的全局变量的值。

**总结:**

`gdb-server.cc` 是 V8 中一个关键的底层组件，它通过实现一个 GDB 远程服务器，使得开发者可以使用强大的 GDB 工具来调试在 V8 中运行的 WebAssembly 代码。它处理了与 GDB 的通信、WebAssembly 模块的管理、断点设置、状态检查等核心功能，从而桥接了 V8 内部的 WebAssembly 执行环境和外部的 GDB 调试器。  虽然 JavaScript 开发者不直接与此代码交互，但他们使用 GDB 调试 WebAssembly 的能力完全依赖于这个 C++ 文件的实现。

Prompt: 
```
这是目录为v8/src/debug/wasm/gdb-server/gdb-server.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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