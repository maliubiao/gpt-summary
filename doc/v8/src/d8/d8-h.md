Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan for Keywords and Structure:**  My first step is to quickly scan the file for common C++ constructs: `#ifndef`, `#define`, `#include`, `namespace`, `class`, `struct`, `enum`, function declarations, and comments. This gives me a high-level overview of the file's organization. I see it's a header file (`.h`), part of the `v8` namespace, and likely related to the `d8` component of V8.

2. **Identify the Core Purpose (Based on File Path and Content):** The file path `v8/src/d8/d8.h` strongly suggests this is the main header for the `d8` component. `d8` is known to be the V8 command-line shell. Therefore, the core purpose is likely to define the structure and functionality of this shell.

3. **Analyze Included Headers:** The `#include` directives are crucial for understanding dependencies and functionality. I note the inclusion of:
    * Standard C++ libraries (`<iterator>`, `<map>`, etc.): Indicates use of standard data structures and utilities.
    * V8 headers (`include/v8-*.h`):  Confirms interaction with the core V8 API for things like isolates, scripts, and values.
    * Internal V8 headers (`src/base/...`, `src/d8/...`, `src/handles/...`, `src/heap/...`):  Signals access to lower-level V8 internals, suggesting more direct control and interaction with the engine. The `async-hooks-wrapper.h` is a specific internal component I recognize.

4. **Examine Key Classes and Structs:** I focus on the defined classes and structs to understand the main building blocks of `d8`:
    * `Counter`, `CounterCollection`, `CounterMap`:  These clearly deal with collecting and managing performance counters, likely for debugging and profiling.
    * `SourceGroup`:  This suggests a way to group and execute JavaScript source code, possibly for running multiple scripts or parts of scripts. The threading aspects (`StartExecuteInThread`, `WaitForThread`) are noteworthy.
    * `SerializationData`, `SerializationDataQueue`:  These are about serializing and deserializing data, likely for communication between different parts of `d8` or with worker threads.
    * `Worker`: This is a significant class, clearly representing worker threads for parallel JavaScript execution. The methods (`PostMessage`, `GetMessage`, `Terminate`) point to an asynchronous messaging system.
    * `PerIsolateData`:  This is a common pattern in V8 to store per-isolate state and utilities. The `RealmScope` and `ExplicitRealmScope` are immediately recognizable as related to V8's Realm API for managing different global environments.
    * `ShellOptions`: This class is vital. It defines all the command-line flags and options that can be passed to the `d8` shell. The naming of the members provides significant clues about the shell's capabilities (e.g., `fuzzilli_coverage_statistics`, `enable_inspector`, `compile_options`).
    * `Shell`: This is the central class for the `d8` shell itself. Its methods represent the core functionalities the shell provides, such as executing code, loading files, interacting with the V8 API, and providing shell-specific commands (e.g., `quit`, `version`, `readFile`, `workerNew`).

5. **Analyze Enums and Typedefs:** These provide additional context:
    * `ModuleType`:  Indicates the different types of modules `d8` can handle (JavaScript, JSON, WebAssembly).
    * `Shell::CodeType`:  Specifies how code is provided to `d8` (filename, string, function).

6. **Look for Global Variables and Constants:** The presence of `check_d8_flag_contradictions` and `Shell::options`, `Shell::kPrompt`, etc., hints at global configuration and state management.

7. **Connect to JavaScript Functionality:**  As I analyze the `Shell` class methods, I actively think about how these map to JavaScript features. For example:
    * `ExecuteString`, `ExecuteModule`: Directly relate to executing JavaScript code.
    * `print`, `printErr`, `readFile`, `writeFile`: Correspond to common I/O operations in a shell environment.
    * `setTimeout`:  Maps directly to the JavaScript `setTimeout` function.
    * `WorkerNew`, `WorkerPostMessage`, `WorkerGetMessage`:  Clearly relate to the JavaScript `Worker` API for concurrency.
    * `RealmCreate`, `RealmSwitch`, `RealmEval`:  Correspond to the JavaScript Realms API for isolated execution environments.
    * `performance.now()`, `performance.mark()`, `performance.measure()`:  Match the standard Performance API.

8. **Consider Potential Programming Errors:** Based on the functionalities, I think about common errors users might encounter:
    * Incorrect file paths when loading scripts or modules.
    * Errors in worker communication (e.g., sending incompatible data).
    * Issues with Realms (e.g., trying to access variables across realms without proper mechanisms).
    * Misunderstanding command-line flags.

9. **Structure the Summary:** Finally, I organize my findings into a logical structure, starting with the high-level purpose and then detailing the key components and their functionalities. I also explicitly address the prompt's requirements about `.tq` files, JavaScript examples, code logic (simple cases), and common errors.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe `SourceGroup` is about managing source code for different isolates."  **Correction:**  The threading aspect and the `ExecuteInThread` method within `SourceGroup` suggest it's more about executing parts of a script in separate threads *within* a single isolate's execution.
* **Initial thought:** "The `SerializationData` might just be for internal data transfer." **Refinement:** Considering the `Worker` class and its messaging methods, it's clear this is also used for inter-worker communication, aligning with the JavaScript `postMessage` and message event.
* **Ensuring Alignment with Prompt:**  I constantly refer back to the prompt to ensure I'm addressing all the specific questions about file extensions, JavaScript examples, logic, and errors.

By following this iterative process of scanning, analyzing, connecting to known concepts, and refining my understanding, I can arrive at a comprehensive summary of the header file's functionality.
这是对 V8 源代码文件 `v8/src/d8/d8.h` 的第一部分分析。

**文件功能归纳:**

`v8/src/d8/d8.h` 是 V8 JavaScript 引擎的命令行工具 `d8` 的主要头文件。它定义了 `d8` 工具的核心数据结构、类和函数，涵盖了 `d8` 的各种功能，包括：

* **脚本执行和管理:**  定义了如何加载、解析和执行 JavaScript 代码，包括从文件或字符串执行。
* **控制台交互:** 提供了与用户进行交互的功能，例如读取输入、打印输出。
* **V8 API 访问:**  封装了部分 V8 的 C++ API，使得 `d8` 可以操作 V8 引擎的各种特性，例如创建和管理 Isolate、Context、Handle 等。
* **多线程和 Worker 支持:**  定义了 `Worker` 类，用于创建和管理 worker 线程，实现 JavaScript 的并发执行。
* **模块支持:**  支持 JavaScript 模块的加载和执行。
* **性能分析和调试:**  包含了用于性能测量、打点和调试的功能，例如 `PerformanceNow`, `PerformanceMark`, `PerformanceMeasure` 以及与 Profiler 相关的函数。
* **Realm (领域) 支持:**  定义了用于创建和管理 JavaScript Realm 的功能，允许在不同的全局环境中运行代码。
* **序列化和反序列化:**  提供了将 JavaScript 值序列化为二进制数据以及从二进制数据反序列化的功能，用于 worker 之间的消息传递。
* **命令行选项解析:**  通过 `ShellOptions` 类定义了 `d8` 工具可以接受的各种命令行选项。
* **系统调用:** 提供了执行操作系统命令的功能 (通过 `os` 对象)。
* **异常处理:**  定义了如何捕获和报告 JavaScript 异常。
* **计数器和性能指标:**  定义了用于收集和管理性能计数器的机制。

**关于文件扩展名 `.tq`:**

如果 `v8/src/d8/d8.h` 以 `.tq` 结尾，那么你的说法是正确的，它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的领域特定语言 (DSL)，用于生成高效的 C++ 代码，通常用于实现内置函数和运行时功能。  然而，根据你提供的代码片段，文件名为 `d8.h`，因此它是一个 C++ 头文件，而不是 Torque 文件。

**与 JavaScript 功能的关系及示例:**

`d8.h` 中定义的许多功能都直接对应或支持 JavaScript 的特性。以下是一些示例：

* **`Shell::ExecuteString` 和 `Shell::ExecuteFile`:**  对应 JavaScript 中执行代码的核心能力。

   ```javascript
   // 假设我们用 d8 运行这个代码
   console.log("Hello from JavaScript!"); // 这会调用 d8 中的 Print 函数
   ```

* **`Worker` 类和相关的 `WorkerNew`, `WorkerPostMessage`, `WorkerGetMessage` 等方法:**  对应 JavaScript 的 `Worker` API。

   ```javascript
   // 在 d8 中创建 worker
   const worker = new Worker('worker.js');

   worker.postMessage({ type: 'start', data: 10 });

   worker.onmessage = function(event) {
     console.log('Received from worker:', event.data);
   };
   ```

* **`RealmCreate`, `RealmSwitch`, `RealmEval` 等方法:** 对应 JavaScript 的 Realms API (虽然该 API 仍在发展中，但 V8 已经提供了支持)。

   ```javascript
   // d8 中使用 Realm (可能需要特定 flag 启用)
   const r = Realm.create();
   const global = r.global;
   Realm.eval(r, 'console.log("Hello from the realm!");');
   ```

* **`PerformanceNow`, `PerformanceMark`, `PerformanceMeasure`:**  对应 JavaScript 的 Performance API。

   ```javascript
   // d8 中使用 Performance API
   performance.mark('start');
   // 执行一些代码
   performance.mark('end');
   performance.measure('myOperation', 'start', 'end');
   console.log(performance.getEntriesByName('myOperation')[0].duration);
   ```

* **`Shell::ReadFile` 和 `Shell::WriteFile`:**  虽然 JavaScript 本身在浏览器环境中没有直接的文件系统访问权限，但在 Node.js 或 `d8` 这样的环境中，可以通过全局对象或内置模块实现文件操作。`d8` 提供了内置的 `readFile` 函数。

   ```javascript
   // d8 中读取文件
   const content = readFile('my_file.txt');
   console.log(content);
   ```

**代码逻辑推理 (简单示例):**

**假设输入:**  `d8` 命令行参数 `--stress-runs=5 my_script.js`

**推理:**

1. `ShellOptions` 类中的 `stress_runs` 成员会被解析为整数 `5`。
2. `Shell::Main` 函数会读取这些选项。
3. 脚本 `my_script.js` 会被加载和执行。
4. 由于 `stress_runs` 大于 1，`d8` 可能会重复执行 `my_script.js` 五次。 具体实现逻辑可能在 `Shell::RunMain` 或相关的执行循环中。

**输出:**  取决于 `my_script.js` 的内容。如果 `my_script.js` 打印一些信息到控制台，这些信息会被打印五次。

**用户常见的编程错误 (与 `d8` 相关):**

* **文件路径错误:**  在 `d8` 中使用 `load('file.js')` 或直接运行 `d8 file.js` 时，如果文件路径不正确，会导致 `d8` 找不到文件并报错。

   ```bash
   d8 non_existent_script.js // 常见错误：文件不存在
   ```

* **Worker 使用错误:**  不正确地使用 `postMessage` 传递不可序列化的数据，或者在主线程和 worker 线程之间出现竞争条件。

   ```javascript
   // worker.js
   onmessage = function(event) {
     // 假设主线程发送了一个无法序列化的对象
     console.log('Worker received:', event.data); // 可能报错
   };
   ```

* **Realm 使用错误:**  尝试在不同的 Realm 之间直接访问变量或对象，而没有使用 `globalThis` 或其他跨 Realm 访问机制。

   ```javascript
   // 假设创建了两个 Realm
   const realm1 = Realm.create();
   const realm2 = Realm.create();

   Realm.eval(realm1, 'globalThis.myVar = 10;');
   Realm.eval(realm2, 'console.log(myVar);'); // 错误：realm2 中没有 myVar
   ```

* **命令行选项使用错误:**  不理解或错误地使用了 `d8` 的命令行选项，例如错误的缓存配置或内存限制。

   ```bash
   d8 --cache=bogus_value my_script.js // 错误：错误的缓存选项
   ```

总而言之，`v8/src/d8/d8.h` 定义了 `d8` 工具的核心结构和功能，是理解 `d8` 如何运行 JavaScript 代码、与 V8 引擎交互以及支持各种高级特性的关键入口点。它为构建一个功能完善的 JavaScript 命令行环境奠定了基础。

### 提示词
```
这是目录为v8/src/d8/d8.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/d8/d8.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_D8_D8_H_
#define V8_D8_D8_H_

#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "include/v8-array-buffer.h"
#include "include/v8-isolate.h"
#include "include/v8-script.h"
#include "include/v8-value-serializer.h"
#include "src/base/once.h"
#include "src/base/platform/time.h"
#include "src/base/platform/wrappers.h"
#include "src/d8/async-hooks-wrapper.h"
#include "src/handles/global-handles.h"
#include "src/heap/parked-scope.h"

namespace v8 {

class BackingStore;
class CompiledWasmModule;
class D8Console;
class Message;
class TryCatch;

enum class ModuleType { kJavaScript, kJSON, kWebAssembly, kInvalid };

namespace internal {
class CancelableTaskManager;
}  // namespace internal

struct DynamicImportData;

// A single counter in a counter collection.
class Counter {
 public:
  static const int kMaxNameSize = 64;
  void Bind(const char* name, bool histogram);
  // TODO(12482): Return pointer to an atomic.
  int* ptr() {
    static_assert(sizeof(int) == sizeof(count_));
    return reinterpret_cast<int*>(&count_);
  }
  int count() const { return count_.load(std::memory_order_relaxed); }
  int sample_total() const {
    return sample_total_.load(std::memory_order_relaxed);
  }
  bool is_histogram() const { return is_histogram_; }
  void AddSample(int32_t sample);

 private:
  std::atomic<int> count_;
  std::atomic<int> sample_total_;
  bool is_histogram_;
  char name_[kMaxNameSize];
};

// A set of counters and associated information.  An instance of this
// class is stored directly in the memory-mapped counters file if
// the --map-counters options is used
class CounterCollection {
 public:
  CounterCollection();
  Counter* GetNextCounter();

 private:
  static const unsigned kMaxCounters = 512;
  uint32_t magic_number_;
  uint32_t max_counters_;
  uint32_t max_name_size_;
  uint32_t counters_in_use_;
  Counter counters_[kMaxCounters];
};

using CounterMap = std::unordered_map<std::string, Counter*>;

class SourceGroup {
 public:
  SourceGroup()
      : next_semaphore_(0),
        done_semaphore_(0),
        thread_(nullptr),
        argv_(nullptr),
        begin_offset_(0),
        end_offset_(0) {}

  ~SourceGroup();

  void Begin(char** argv, int offset) {
    argv_ = const_cast<const char**>(argv);
    begin_offset_ = offset;
  }

  void End(int offset) { end_offset_ = offset; }

  // Returns true on success, false if an uncaught exception was thrown.
  bool Execute(Isolate* isolate);

  void StartExecuteInThread();
  void WaitForThread(const i::ParkedScope& parked);
  void JoinThread(const i::ParkedScope& parked);

 private:
  class IsolateThread : public base::Thread {
   public:
    explicit IsolateThread(SourceGroup* group);

    void Run() override { group_->ExecuteInThread(); }

   private:
    SourceGroup* group_;
  };

  void ExecuteInThread();

  i::ParkingSemaphore next_semaphore_;
  i::ParkingSemaphore done_semaphore_;
  base::Thread* thread_;

  void ExitShell(int exit_code);

  const char** argv_;
  int begin_offset_;
  int end_offset_;
};

class SerializationData {
 public:
  SerializationData() = default;
  SerializationData(const SerializationData&) = delete;
  SerializationData& operator=(const SerializationData&) = delete;

  uint8_t* data() { return data_.get(); }
  size_t size() { return size_; }
  const std::vector<std::shared_ptr<v8::BackingStore>>& backing_stores() {
    return backing_stores_;
  }
  const std::vector<std::shared_ptr<v8::BackingStore>>& sab_backing_stores() {
    return sab_backing_stores_;
  }
  const std::vector<CompiledWasmModule>& compiled_wasm_modules() {
    return compiled_wasm_modules_;
  }
  const std::optional<v8::SharedValueConveyor>& shared_value_conveyor() {
    return shared_value_conveyor_;
  }

 private:
  struct DataDeleter {
    void operator()(uint8_t* p) const { base::Free(p); }
  };

  std::unique_ptr<uint8_t, DataDeleter> data_;
  size_t size_ = 0;
  std::vector<std::shared_ptr<v8::BackingStore>> backing_stores_;
  std::vector<std::shared_ptr<v8::BackingStore>> sab_backing_stores_;
  std::vector<CompiledWasmModule> compiled_wasm_modules_;
  std::optional<v8::SharedValueConveyor> shared_value_conveyor_;

 private:
  friend class Serializer;
};

class SerializationDataQueue {
 public:
  void Enqueue(std::unique_ptr<SerializationData> data);
  bool Dequeue(std::unique_ptr<SerializationData>* data);
  bool IsEmpty();
  void Clear();

 private:
  base::Mutex mutex_;
  std::vector<std::unique_ptr<SerializationData>> data_;
};

class Worker : public std::enable_shared_from_this<Worker> {
 public:
  static constexpr i::ExternalPointerTag kManagedTag = i::kGenericManagedTag;

  explicit Worker(Isolate* parent_isolate, const char* script);
  ~Worker();

  // Post a message to the worker. The worker will take ownership of the
  // SerializationData. This function should only be called by the thread that
  // created the Worker.
  void PostMessage(std::unique_ptr<SerializationData> data);
  // Synchronously retrieve messages from the worker's outgoing message queue.
  // If there is no message in the queue, block until a message is available.
  // If there are no messages in the queue and the worker is no longer running,
  // return nullptr.
  // This function should only be called by the thread that created the Worker.
  std::unique_ptr<SerializationData> GetMessage(Isolate* requester);
  // Synchronously retrieve messages from the worker's outgoing message queue.
  // If there is no message in the queue, or the worker is no longer running,
  // return nullptr.
  // This function should only be called by the thread that created the Worker.
  std::unique_ptr<SerializationData> TryGetMessage();
  // Terminate the worker's event loop. Messages from the worker that have been
  // queued can still be read via GetMessage().
  // This function can be called by any thread.
  void Terminate();
  // Terminate and join the thread.
  // This function can be called by any thread.
  void TerminateAndWaitForThread(const i::ParkedScope& parked);

  // Start running the given worker in another thread.
  static bool StartWorkerThread(Isolate* requester,
                                std::shared_ptr<Worker> worker,
                                base::Thread::Priority priority);

  // Enters State::kTerminated for the Worker and resets the task runner.
  void EnterTerminatedState();
  bool IsTerminated() const { return state_ == State::kTerminated; }

  // Returns the Worker instance for this thread.
  static Worker* GetCurrentWorker();

 private:
  friend class ProcessMessageTask;
  friend class TerminateTask;

  enum class State {
    kReady,
    kPrepareRunning,
    kRunning,
    kTerminating,
    kTerminated,
  };
  bool is_running() const;

  void ProcessMessage(std::unique_ptr<SerializationData> data);
  void ProcessMessages();

  class WorkerThread : public base::Thread {
   public:
    explicit WorkerThread(std::shared_ptr<Worker> worker,
                          base::Thread::Priority priority)
        : base::Thread(base::Thread::Options("WorkerThread", priority)),
          worker_(std::move(worker)) {}

    void Run() override;

   private:
    std::shared_ptr<Worker> worker_;
  };

  void ExecuteInThread();
  static void PostMessageOut(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void ImportScripts(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void Close(const v8::FunctionCallbackInfo<v8::Value>& info);

  static void SetCurrentWorker(Worker* worker);

  i::ParkingSemaphore out_semaphore_{0};
  SerializationDataQueue out_queue_;

  base::Thread* thread_ = nullptr;
  char* script_;
  std::atomic<State> state_;
  bool is_joined_ = false;
  // For signalling that the worker has started.
  i::ParkingSemaphore started_semaphore_{0};

  // For posting tasks to the worker
  std::shared_ptr<TaskRunner> task_runner_;
  i::CancelableTaskManager* task_manager_;

  // Protects reading / writing task_runner_. (The TaskRunner itself doesn't
  // need locking, but accessing the Worker's data member does.)
  base::Mutex worker_mutex_;

  // The isolate should only be accessed by the worker itself, or when holding
  // the worker_mutex_ and after checking the worker state.
  Isolate* isolate_ = nullptr;
  Isolate* parent_isolate_;

  // Only accessed by the worker thread.
  Global<Context> context_;
};

class PerIsolateData {
 public:
  explicit PerIsolateData(Isolate* isolate);

  ~PerIsolateData();

  inline static PerIsolateData* Get(Isolate* isolate) {
    return reinterpret_cast<PerIsolateData*>(isolate->GetData(0));
  }

  class V8_NODISCARD RealmScope {
   public:
    explicit RealmScope(Isolate* isolate, const Global<Context>& context);
    ~RealmScope();

   private:
    PerIsolateData* data_;
  };

  // Contrary to RealmScope (which creates a new Realm), ExplicitRealmScope
  // allows for entering an existing Realm, as specified by its index.
  class V8_NODISCARD ExplicitRealmScope {
   public:
    explicit ExplicitRealmScope(PerIsolateData* data, int index);
    ~ExplicitRealmScope();

    Local<Context> context() const;

   private:
    PerIsolateData* data_;
    Local<Context> realm_;
    int index_;
    int previous_index_;
  };

  AsyncHooks* GetAsyncHooks() { return async_hooks_wrapper_; }

  void RemoveUnhandledPromise(Local<Promise> promise);
  void AddUnhandledPromise(Local<Promise> promise, Local<Message> message,
                           Local<Value> exception);
  int HandleUnhandledPromiseRejections();

  // Keep track of DynamicImportData so we can properly free it on shutdown
  // when LEAK_SANITIZER is active.
  void AddDynamicImportData(DynamicImportData*);
  void DeleteDynamicImportData(DynamicImportData*);

  Local<FunctionTemplate> GetTestApiObjectCtor() const;
  void SetTestApiObjectCtor(Local<FunctionTemplate> ctor);

  Local<FunctionTemplate> GetDomNodeCtor() const;
  void SetDomNodeCtor(Local<FunctionTemplate> ctor);

  bool HasRunningSubscribedWorkers();
  void RegisterWorker(std::shared_ptr<Worker> worker);
  void SubscribeWorkerOnMessage(const std::shared_ptr<Worker>& worker,
                                Local<Context> context,
                                Local<Function> callback);
  std::pair<Local<Context>, Local<Function>> GetWorkerOnMessage(
      const std::shared_ptr<Worker>& worker) const;
  void UnregisterWorker(const std::shared_ptr<Worker>& worker);

 private:
  friend class Shell;
  friend class RealmScope;
  Isolate* isolate_;
  int realm_count_;
  int realm_current_;
  int realm_switch_;
  Global<Context>* realms_;
  Global<Value> realm_shared_;
  bool ignore_unhandled_promises_;
  std::vector<std::tuple<Global<Promise>, Global<Message>, Global<Value>>>
      unhandled_promises_;
  AsyncHooks* async_hooks_wrapper_;
#if defined(LEAK_SANITIZER)
  std::unordered_set<DynamicImportData*> import_data_;
#endif
  Global<FunctionTemplate> test_api_object_ctor_;
  Global<FunctionTemplate> dom_node_ctor_;
  // Track workers and their callbacks separately, so that we know both which
  // workers are still registered, and which of them have callbacks. We can't
  // rely on Shell::running_workers_ or worker.IsTerminated(), because these are
  // set concurrently and may race with callback subscription.
  std::set<std::shared_ptr<Worker>> registered_workers_;
  std::map<std::shared_ptr<Worker>,
           std::pair<Global<Context>, Global<Function>>>
      worker_message_callbacks_;

  int RealmIndexOrThrow(const v8::FunctionCallbackInfo<v8::Value>& info,
                        int arg_offset);
  int RealmFind(Local<Context> context);
};

extern bool check_d8_flag_contradictions;

class ShellOptions {
 public:
  enum CodeCacheOptions {
    kNoProduceCache,
    kProduceCache,
    kProduceCacheAfterExecute
  };

  ~ShellOptions() { delete[] isolate_sources; }

  // In analogy to Flag::CheckFlagChange() in src/flags/flag.cc, only allow
  // repeated flags for identical boolean values. We allow exceptions for flags
  // with enum-like arguments since their conflicts can also be specified
  // completely.
  template <class T,
            bool kAllowIdenticalAssignment = std::is_same<T, bool>::value>
  class DisallowReassignment {
   public:
    DisallowReassignment(const char* name, T value)
        : name_(name), value_(value) {}

    operator T() const { return value_; }
    T get() const { return value_; }
    DisallowReassignment& operator=(T value) {
      if (check_d8_flag_contradictions) {
        if (kAllowIdenticalAssignment) {
          if (specified_ && value_ != value) {
            FATAL("Contradictory values for d8 flag --%s", name_);
          }
        } else {
          if (specified_) {
            FATAL("Repeated specification of d8 flag --%s", name_);
          }
        }
      }
      value_ = value;
      specified_ = true;
      return *this;
    }
    void Overwrite(T value) { value_ = value; }

   private:
    const char* name_;
    T value_;
    bool specified_ = false;
  };

  DisallowReassignment<const char*> d8_path = {"d8-path", ""};
  DisallowReassignment<bool> fuzzilli_coverage_statistics = {
      "fuzzilli-coverage-statistics", false};
  DisallowReassignment<bool> fuzzilli_enable_builtins_coverage = {
      "fuzzilli-enable-builtins-coverage", false};
  DisallowReassignment<bool> send_idle_notification = {"send-idle-notification",
                                                       false};
  DisallowReassignment<bool> invoke_weak_callbacks = {"invoke-weak-callbacks",
                                                      false};
  DisallowReassignment<bool> omit_quit = {"omit-quit", false};
  DisallowReassignment<bool> wait_for_background_tasks = {
      "wait-for-background-tasks", true};
  DisallowReassignment<bool> simulate_errors = {"simulate-errors", false};
  DisallowReassignment<int> stress_runs = {"stress-runs", 1};
  DisallowReassignment<bool> interactive_shell = {"shell", false};
  bool test_shell = false;
  DisallowReassignment<bool> expected_to_throw = {"throws", false};
  DisallowReassignment<bool> no_fail = {"no-fail", false};
  DisallowReassignment<bool> dump_counters = {"dump-counters", false};
  DisallowReassignment<bool> dump_counters_nvp = {"dump-counters-nvp", false};
  DisallowReassignment<bool> dump_system_memory_stats = {
      "dump-system-memory-stats", false};
  DisallowReassignment<bool> ignore_unhandled_promises = {
      "ignore-unhandled-promises", false};
  DisallowReassignment<bool> mock_arraybuffer_allocator = {
      "mock-arraybuffer-allocator", false};
  DisallowReassignment<size_t> mock_arraybuffer_allocator_limit = {
      "mock-arraybuffer-allocator-limit", 0};
  DisallowReassignment<bool> multi_mapped_mock_allocator = {
      "multi-mapped-mock-allocator", false};
  DisallowReassignment<bool> enable_inspector = {"enable-inspector", false};
  int num_isolates = 1;
  DisallowReassignment<v8::ScriptCompiler::CompileOptions, true>
      compile_options = {"cache", v8::ScriptCompiler::kNoCompileOptions};
  DisallowReassignment<CodeCacheOptions, true> code_cache_options = {
      "cache", CodeCacheOptions::kNoProduceCache};
  DisallowReassignment<bool> streaming_compile = {"streaming-compile", false};
  DisallowReassignment<SourceGroup*> isolate_sources = {"isolate-sources",
                                                        nullptr};
  DisallowReassignment<const char*> icu_data_file = {"icu-data-file", nullptr};
  DisallowReassignment<const char*> icu_locale = {"icu-locale", nullptr};
  DisallowReassignment<const char*> snapshot_blob = {"snapshot_blob", nullptr};
  DisallowReassignment<bool> trace_enabled = {"trace-enabled", false};
  DisallowReassignment<const char*> trace_path = {"trace-path", nullptr};
  DisallowReassignment<const char*> trace_config = {"trace-config", nullptr};
  DisallowReassignment<const char*> lcov_file = {"lcov", nullptr};
#ifdef V8_OS_LINUX
  // Allow linux perf to be started and stopped by performance.mark and
  // performance.measure, respectively.
  DisallowReassignment<bool> scope_linux_perf_to_mark_measure = {
      "scope-linux-perf-to-mark-measure", false};
  DisallowReassignment<int> perf_ctl_fd = {"perf-ctl-fd", -1};
  DisallowReassignment<int> perf_ack_fd = {"perf-ack-fd", -1};
#endif
  DisallowReassignment<bool> disable_in_process_stack_traces = {
      "disable-in-process-stack-traces", false};
  DisallowReassignment<int> read_from_tcp_port = {"read-from-tcp-port", -1};
  DisallowReassignment<bool> enable_os_system = {"enable-os-system", false};
  DisallowReassignment<bool> quiet_load = {"quiet-load", false};
  DisallowReassignment<bool> apply_priority = {"apply-priority", true};
  DisallowReassignment<int> thread_pool_size = {"thread-pool-size", 0};
  DisallowReassignment<bool> stress_delay_tasks = {"stress-delay-tasks", false};
  std::vector<const char*> arguments;
  DisallowReassignment<bool> include_arguments = {"arguments", true};
  DisallowReassignment<bool> cpu_profiler = {"cpu-profiler", false};
  DisallowReassignment<bool> cpu_profiler_print = {"cpu-profiler-print", false};
  DisallowReassignment<bool> fuzzy_module_file_extensions = {
      "fuzzy-module-file-extensions", true};
  DisallowReassignment<bool> enable_system_instrumentation = {
      "enable-system-instrumentation", false};
  DisallowReassignment<bool> enable_etw_stack_walking = {
      "enable-etw-stack-walking", false};
  // Applies to JSON deserialization.
  DisallowReassignment<bool> stress_deserialize = {"stress-deserialize", false};
  DisallowReassignment<bool> compile_only = {"compile-only", false};
  DisallowReassignment<int> repeat_compile = {"repeat-compile", 1};
#if V8_ENABLE_WEBASSEMBLY
  DisallowReassignment<bool> wasm_trap_handler = {"wasm-trap-handler", true};
#endif  // V8_ENABLE_WEBASSEMBLY
  DisallowReassignment<bool> expose_fast_api = {"expose-fast-api", false};
  DisallowReassignment<size_t> max_serializer_memory = {"max-serializer-memory",
                                                        1 * i::MB};
};

class Shell : public i::AllStatic {
 public:
  enum PrintResult : bool { kPrintResult = true, kNoPrintResult = false };
  enum ReportExceptions : bool {
    kReportExceptions = true,
    kNoReportExceptions = false
  };
  enum ProcessMessageQueue : bool {
    kProcessMessageQueue = true,
    kNoProcessMessageQueue = false
  };
  enum class CodeType { kFileName, kString, kFunction, kInvalid, kNone };

  // Boolean return values (for any method below) typically denote "success".
  // We return `false` on uncaught exceptions, except for termination
  // exceptions.
  static bool ExecuteString(Isolate* isolate, Local<String> source,
                            Local<String> name,
                            ReportExceptions report_exceptions,
                            Global<Value>* out_result = nullptr);
  static bool ExecuteModule(Isolate* isolate, const char* file_name);
  static bool LoadJSON(Isolate* isolate, const char* file_name);
  static void ReportException(Isolate* isolate, Local<Message> message,
                              Local<Value> exception);
  static void ReportException(Isolate* isolate, const TryCatch& try_catch);
  static MaybeLocal<String> ReadFile(Isolate* isolate, const char* name,
                                     bool should_throw = true);
  static std::unique_ptr<base::OS::MemoryMappedFile> ReadFileData(
      Isolate* isolate, const char* name, bool should_throw = true);
  static Local<String> WasmLoadSourceMapCallback(Isolate* isolate,
                                                 const char* name);
  static MaybeLocal<Context> CreateEvaluationContext(Isolate* isolate);
  static int RunMain(Isolate* isolate, bool last_run);
  static int Main(int argc, char* argv[]);
  static void Exit(int exit_code);
  static void OnExit(Isolate* isolate, bool dispose);
  static void CollectGarbage(Isolate* isolate);
  static bool EmptyMessageQueues(Isolate* isolate);
  static bool CompleteMessageLoop(Isolate* isolate);
  static bool FinishExecuting(Isolate* isolate, const Global<Context>& context);

  static bool HandleUnhandledPromiseRejections(Isolate* isolate);

  static std::unique_ptr<SerializationData> SerializeValue(
      Isolate* isolate, Local<Value> value, Local<Value> transfer);
  static MaybeLocal<Value> DeserializeValue(
      Isolate* isolate, std::unique_ptr<SerializationData> data);
  static int* LookupCounter(const char* name);
  static void* CreateHistogram(const char* name, int min, int max,
                               size_t buckets);
  static void AddHistogramSample(void* histogram, int sample);
  static void MapCounters(v8::Isolate* isolate, const char* name);

  static double GetTimestamp();
  static uint64_t GetTracingTimestampFromPerformanceTimestamp(
      double performance_timestamp);

  static void PerformanceNow(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void PerformanceMark(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void PerformanceMeasure(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void PerformanceMeasureMemory(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  static void RealmCurrent(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmOwner(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmGlobal(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmCreate(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmNavigate(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmCreateAllowCrossRealmAccess(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmDetachGlobal(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmDispose(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmSwitch(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmEval(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RealmSharedGet(Local<Name> property,
                             const PropertyCallbackInfo<Value>& info);
  static void RealmSharedSet(Local<Name> property, Local<Value> value,
                             const PropertyCallbackInfo<void>& info);

  static void LogGetAndStop(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void TestVerifySourcePositions(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  static void InstallConditionalFeatures(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void EnableJSPI(const v8::FunctionCallbackInfo<v8::Value>& info);

  static void AsyncHooksCreateHook(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void AsyncHooksExecutionAsyncId(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void AsyncHooksTriggerAsyncId(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  static void SetPromiseHooks(const v8::FunctionCallbackInfo<v8::Value>& info);

  static void EnableDebugger(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void DisableDebugger(const v8::FunctionCallbackInfo<v8::Value>& info);

  static void SerializerSerialize(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void SerializerDeserialize(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  static void ProfilerSetOnProfileEndListener(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void ProfilerTriggerSample(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  static bool HasOnProfileEndListener(Isolate* isolate);

  static void TriggerOnProfileEndListener(Isolate* isolate,
                                          std::string profile);

  static void ResetOnProfileEndListener(Isolate* isolate);

  static void Print(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void PrintErr(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WriteStdout(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WaitUntilDone(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void NotifyDone(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void QuitOnce(v8::FunctionCallbackInfo<v8::Value>* info);
  static void Quit(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void Terminate(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void Version(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WriteFile(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void ReadFile(const v8::FunctionCallbackInfo<v8::Value>& info);
  static char* ReadChars(const char* name, int* size_out);
  static MaybeLocal<PrimitiveArray> ReadLines(Isolate* isolate,
                                              const char* name);
  static void ReadBuffer(const v8::FunctionCallbackInfo<v8::Value>& info);
  static Local<String> ReadFromStdin(Isolate* isolate);
  static void ReadLine(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WriteChars(const char* name, uint8_t* buffer, size_t buffer_size);
  static void ExecuteFile(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void SetTimeout(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void ReadCodeTypeAndArguments(
      const v8::FunctionCallbackInfo<v8::Value>& info, int index,
      CodeType* code_type, Local<Value>* arguments = nullptr);
  static bool FunctionAndArgumentsToString(Local<Function> function,
                                           Local<Value> arguments,
                                           Local<String>* source,
                                           Isolate* isolate);
  static MaybeLocal<String> ReadSource(
      const v8::FunctionCallbackInfo<v8::Value>& info, int index,
      CodeType default_type);
  static void WorkerNew(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WorkerPostMessage(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WorkerGetMessage(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WorkerOnMessageGetter(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WorkerOnMessageSetter(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WorkerTerminate(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void WorkerTerminateAndWait(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  // The OS object on the global object contains methods for performing
  // operating system calls:
  //
  // os.system("program_name", ["arg1", "arg2", ...], timeout1, timeout2) will
  // run the command, passing the arguments to the program.  The standard output
  // of the program will be picked up and returned as a multiline string.  If
  // timeout1 is present then it should be a number.  -1 indicates no timeout
  // and a positive number is used as a timeout in milliseconds that limits the
  // time spent waiting between receiving output characters from the program.
  // timeout2, if present, should be a number indicating the limit in
  // milliseconds on the total running time of the program.  Exceptions are
  // thrown on timeouts or other errors or if the exit status of the program
  // indicates an error.
  static void System(const v8::FunctionCallbackInfo<v8::Value>& info);

  // os.chdir(dir) changes directory to the given directory.  Throws an
  // exception/ on error.
  static void ChangeDirectory(const v8::FunctionCallbackInfo<v8::Value>& info);

  // os.setenv(variable, value) sets an environment variable.  Repeated calls to
  // this method leak memory due to the API of setenv in the standard C library.
  static void SetEnvironment(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void UnsetEnvironment(const v8::FunctionCallbackInfo<v8::Value>& info);

  // os.umask(alue) calls the umask system call and returns the old umask.
  static void SetUMask(const v8::FunctionCallbackInfo<v8::Value>& info);

  // os.mkdirp(name, mask) creates a directory.  The mask (if present) is anded
  // with the current umask.  Intermediate directories are created if necessary.
  // An exception is not thrown if the directory already exists.  Analogous to
  // the "mkdir -p" command.
  static void MakeDirectory(const v8::FunctionCallbackInfo<v8::Value>& info);
  static void RemoveDirectory(const v8::FunctionCallbackInfo<v8::Value>& info);

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  static void GetContinuationPreservedEmbedderData(
      const v8::FunctionCallbackInfo<v8::Value>& info);
#endif  // V8_ENABLE_CONTINUATION_PRESERVER_EMBEDDER_DATA

  static void GetExtrasBindingObject(
      const v8::FunctionCallbackInfo<v8::Value>& info);

  static MaybeLocal<Promise> HostImportModuleDynamically(
      Local<Context> context, Local<Data> host_defined_options,
      Local<Value> resource_name, Local<String> specifier,
      Local<FixedArray> import_attributes);
  static MaybeLocal<Promise> HostImportModuleWithPhaseDynamically(
      Local<Context> context, Local<Data> host_defined_options,
      Local<Value> resource_name, Local<String> specifier,
      ModuleImportPhase phase, Local<FixedArray> import_attributes);

  static void ModuleResolutionSuccessCallback(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void ModuleResolutionFailureCallback(
      const v8::FunctionCallbackInfo<v8::Value>& info);
  static void HostInitializeImportMetaObject(Local<Context> context,
                                             Local<Module> module,
                                             Local<Object> meta);
  static MaybeLocal<Context> HostCreateShadowRealmContext(
      Local<Context> initiator_context);

#ifdef V8_FUZZILLI
  static void Fuzzilli(const v8::FunctionCallbackInfo<v8::Value>& info);
#endif  // V8_FUZZILLI

  // Data is of type DynamicImportData*. We use void* here to be able
  // to conform with MicrotaskCallback interface and enqueue this
  // function in the microtask queue.
  static void DoHostImportModuleDynamically(void* data);
  static void AddOSMethods(v8::Isolate* isolate,
                           Local<ObjectTemplate> os_template);

  static const char* kPrompt;
  static ShellOptions options;
  static ArrayBuffer::Allocator* array_buffer_allocator;

  static void SetWaitUntilDone(Isolate* isolate, bool value);

  static char* ReadCharsFromTcpPort(const char* name, int* size_out);

  static void set_script_executed() { script_executed_.store(true); }
  static bool use_interactive_shell() {
    return (options.interactive_shell || !script_executed_.load()) &&
           !options.test_shell;
  }

  static void update_script_size(int size) {
    if (size > 0) valid_fuzz_script_.store(true);
  }
  static bool is_valid_fuzz_script() { return valid_fuzz_script_.load(); }

  static void WaitForRunningWorkers(const i::ParkedScope& parked);
  static void AddRunningWorker(std::shared_ptr<Worker> worker);
  static void RemoveRunningWorker(const std::shared_ptr<Worker>& worker);

  static void Initialize(Isolate* isolate, D8Console* console,
                         bool isOnMainThread = true);

  static void PromiseRejectCallback(v8::PromiseRejectMessage reject_message);

 private:
  static inline int DeserializationRunCount() {
    return options.stress_deserialize ? 1000 : 1;
  }

  static Global<Context> evaluation_context_;
  static base::OnceType quit_once_;
  static Global<Function> stringify_function_;

  static base::Mutex profiler_end_callback_lock_;
  static std::map<Isolate*, std::pair<Global<Function>, Global<Context>>>
      profiler_end_callback_;

  static const char* stringify_source_;
  static CounterMap* counter_map_;
  static base::SharedMutex counter_mutex_;
  // We statically allocate a set of local counters to be used if we
  // don't want to store the stats in a memory-mapped file
  static CounterCollection local_counters_;
  static CounterCollection* counters_;
  static base::OS::MemoryMappedFile* counters_file_;
  static base::LazyMutex context_mutex_;
  static const base::TimeTicks kInitialTicks;

  static base::LazyMutex workers_mutex_;  // Guards the following members.
  static bool allow_new_workers_;
  static std::unordered_set<std::shared_ptr<Worker>> running_workers_;

  // Multiple isolates may update these flags concurrently.
  static std::atomic<bool> script_executed_;
  static std::atomic<bool> valid_fuzz_script_;

  static void WriteIgnitionDispatchCountersFile(v8::Isolate* isolate);
  // Append LCOV coverage data to file.
  static void WriteLcovData(v8::Isolate* isolate, const char* file);
  static Coun
```