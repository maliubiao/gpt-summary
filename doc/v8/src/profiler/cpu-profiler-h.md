Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and Keyword Recognition:**

* **Copyright and License:** The header starts with standard copyright and licensing information. This immediately tells us it's part of a larger project with defined usage terms.
* **`#ifndef`, `#define`, `#include`:**  These are C++ preprocessor directives for include guards and including other header files. This is standard practice in C++.
* **`namespace v8`, `namespace internal`:**  Indicates this code belongs to the V8 JavaScript engine project and likely an internal implementation detail.
* **Class names like `CpuProfiler`, `ProfilerEventsProcessor`, `CodeEntry`, `TickSample`:** These are strong hints about the file's purpose. "Profiler" clearly suggests it's involved in performance analysis. "CPU" points to CPU usage analysis specifically. "CodeEntry" and "TickSample" suggest tracking code execution and capturing execution snapshots.
* **`V8_EXPORT_PRIVATE`:** This macro likely controls the visibility of classes and functions, making them accessible within the V8 internal implementation but not the external API.
* **Data Structures like `LockedQueue`, `CircularQueue`:**  These suggest asynchronous operations and the need for efficient data sharing between threads.
* **Platform-specific includes (`#if V8_OS_WIN`):**  Indicates cross-platform considerations.

**2. High-Level Functionality Guess (Based on Keywords):**

Based on the initial scan, a reasonable first guess would be: "This header file defines classes and data structures related to CPU profiling within the V8 JavaScript engine."

**3. Deeper Dive into Key Classes:**

* **`CodeEventRecord` and related classes (`CodeCreateEventRecord`, `CodeMoveEventRecord`, etc.):** The naming strongly suggests these classes track events related to code within the V8 engine. Creation, movement, optimization, deoptimization, and deletion are common lifecycle events for code in a dynamic environment like a JavaScript engine. The `UpdateCodeMap` method hints at maintaining a mapping of code addresses.
* **`TickSampleEventRecord`:**  This clearly represents a sample taken during profiling. The presence of a `TickSample` member reinforces this.
* **`ProfilerEventsProcessor`:** This class inherits from `base::Thread`, which strongly indicates it's responsible for processing profiling events in a separate thread. The methods like `CodeEventHandler`, `Enqueue`, `AddCurrentStack`, and `AddSample` confirm its role as a central event handler.
* **`SamplingEventsProcessor`:**  This likely handles the actual sampling of the CPU. The `Run()` method override and the presence of `SamplingCircularQueue` and `sampler::Sampler` support this. The `SetSamplingInterval` method is a key indicator of controlling the profiling granularity.
* **`ProfilerCodeObserver`:** This class acts as an observer for code-related events. The `CodeEventHandler` and the mention of `InstructionStreamMap` indicate its responsibility for tracking the state of code in the VM.
* **`CpuProfiler`:** This appears to be the main interface for interacting with the CPU profiler. The methods like `StartProfiling`, `StopProfiling`, `GetProfilesCount`, and `DeleteAllProfiles` clearly point to its role in controlling the profiling process and managing the collected data.

**4. Connecting the Dots (Workflow Inference):**

By examining the relationships between these classes, a likely workflow emerges:

1. **`CpuProfiler`** is the entry point. A user (or V8 itself) would likely use this class to start and stop profiling.
2. **`SamplingEventsProcessor`** (running in a separate thread) is responsible for periodically taking "tick samples" of the CPU's execution state.
3. These samples, represented by `TickSampleEventRecord`, are stored in a buffer (`ticks_buffer_`).
4. **`ProfilerEventsProcessor`** (also in a separate thread) consumes these samples and also processes code-related events.
5. **`ProfilerCodeObserver`** listens for code events (creation, movement, etc.) and maintains a mapping of code addresses (`InstructionStreamMap`). This mapping is crucial for symbolization (turning raw addresses into meaningful function names).
6. The `Symbolizer` class is likely responsible for the actual symbolization process.
7. The collected profiling data (samples and code information) is stored and managed by `CpuProfilesCollection`.

**5. Answering the Specific Questions:**

Now, with a good understanding of the file's purpose, addressing the specific questions becomes easier:

* **Functionality:** Summarize the roles of the key classes and how they interact.
* **`.tq` extension:**  Check for the file extension. In this case, it's `.h`, so it's C++ and not Torque.
* **Relationship to JavaScript:** Explain how CPU profiling helps understand JavaScript performance. Think about how it can reveal bottlenecks in user code or the engine itself.
* **JavaScript Example:**  Create a simple JavaScript snippet that could benefit from CPU profiling (e.g., a long-running loop or a function call that is suspected to be slow).
* **Code Logic Reasoning:** Identify a specific part of the code with clear input/output. The `CodeMoveEventRecord` and its `UpdateCodeMap` method are good candidates. Hypothesize an initial state of the `InstructionStreamMap` and show how it changes after a code move event.
* **Common Programming Errors:**  Think about typical JavaScript performance pitfalls that CPU profiling can help diagnose (e.g., excessive function calls, inefficient algorithms, synchronous operations blocking the main thread).

**Self-Correction/Refinement during the Process:**

* **Initial Over-simplification:**  Initially, I might have just thought "it's for profiling." But digging deeper into the class names reveals the different stages and components involved in the profiling process.
* **Understanding Asynchronous Operations:** Recognizing the use of threads and queues is important to grasp how profiling data is collected and processed without blocking the main JavaScript execution thread.
* **The Role of Symbolization:**  Understanding that raw memory addresses need to be translated into meaningful function names is a key part of the profiling process. The `Symbolizer` class highlights this.
* **Platform Differences:**  The `#if V8_OS_WIN` block reminds me that low-level system interactions can vary across operating systems.

By following this structured thought process, combining keyword recognition with a deeper analysis of class responsibilities and interactions, I can arrive at a comprehensive understanding of the provided C++ header file and address the specific questions accurately.
好的，让我们来分析一下 `v8/src/profiler/cpu-profiler.h` 这个 V8 源代码文件。

**功能概述**

`v8/src/profiler/cpu-profiler.h` 文件定义了 V8 JavaScript 引擎中用于 CPU 性能分析（profiling）的关键类和数据结构。 其主要功能是：

1. **收集 CPU 执行样本 (Sampling):**  定义了如何定期捕获 JavaScript 代码执行时的堆栈信息。这通常通过定时器和信号（或 Windows 上的线程挂起/恢复）来实现。
2. **记录代码事件:**  跟踪代码的创建、移动、优化、反优化和删除等事件。这对于理解性能变化以及将样本映射到具体的代码位置至关重要。
3. **后台处理:**  使用独立的线程 (`ProfilerEventsProcessor` 和 `SamplingEventsProcessor`) 来处理收集到的样本和代码事件，避免阻塞主 JavaScript 执行线程。
4. **符号化 (Symbolization):**  将内存地址转换为函数名和源代码位置，使得性能分析结果更易于理解。
5. **管理 Profiler 生命周期:**  提供启动、停止和管理 CPU profiler 的接口 (`CpuProfiler` 类)。
6. **存储和访问 Profile 数据:**  定义了存储 CPU profile 数据的结构 (`CpuProfilesCollection`) 和访问这些数据的接口。

**文件类型**

`v8/src/profiler/cpu-profiler.h` 的文件扩展名是 `.h`，这表明它是一个 C++ 头文件，包含了类、结构体、枚举和宏的声明，而不是 Torque 源代码。 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及示例**

CPU profiler 的主要目的是分析 JavaScript 代码的性能瓶颈。它可以帮助开发者识别哪些函数或代码段消耗了最多的 CPU 时间。

**JavaScript 示例**

假设我们有以下 JavaScript 代码：

```javascript
function heavyComputation() {
  let sum = 0;
  for (let i = 0; i < 1000000; i++) {
    sum += Math.sqrt(i);
  }
  return sum;
}

function main() {
  console.time("computation");
  heavyComputation();
  console.timeEnd("computation");
}

main();
```

如果我们怀疑 `heavyComputation` 函数是性能瓶颈，可以使用 V8 的 CPU profiler 来验证。 在 Node.js 环境中，可以使用内置的 `inspector` 模块：

```javascript
const inspector = require('inspector');
const fs = require('fs');

function heavyComputation() {
  let sum = 0;
  for (let i = 0; i < 1000000; i++) {
    sum += Math.sqrt(i);
  }
  return sum;
}

function main() {
  inspector.open(9229, 'localhost', true); // 启动 Inspector
  const session = new inspector.Session();
  session.connect();

  session.post('Profiler.enable', () => {
    session.post('Profiler.start', () => {
      console.time("computation");
      heavyComputation();
      console.timeEnd("computation");

      session.post('Profiler.stop', (err, { profile }) => {
        // 将 profile 数据保存到文件
        fs.writeFileSync('cpu.profile', JSON.stringify(profile));
        console.log('CPU profile saved to cpu.profile');
        session.disconnect();
      });
    });
  });
}

main();
```

运行这段代码后，会生成一个 `cpu.profile` 文件，其中包含了 CPU profiler 收集到的数据。我们可以使用 Chrome DevTools 或其他工具加载这个文件，查看火焰图等信息，从而清晰地看到 `heavyComputation` 函数占用了大量的 CPU 时间。

**代码逻辑推理（假设输入与输出）**

让我们关注 `CodeMoveEventRecord` 及其 `UpdateCodeMap` 方法。

**假设输入：**

* `instruction_stream_map`: 一个 `InstructionStreamMap` 对象，维护着代码起始地址到 `CodeEntry` 的映射。
* `CodeMoveEventRecord` 对象 `move_event`，其成员如下：
    * `from_instruction_start`: 代码移动前的起始地址，例如 `0x1000`.
    * `to_instruction_start`: 代码移动后的起始地址，例如 `0x2000`.

**操作：**

`move_event.UpdateCodeMap(instruction_stream_map)` 方法会被调用。

**代码逻辑（推测）：**

`UpdateCodeMap` 方法很可能在 `instruction_stream_map` 中执行以下操作：

1. **查找:**  根据 `move_event.from_instruction_start` 在 `instruction_stream_map` 中查找对应的 `CodeEntry`。
2. **更新:**  如果找到，将该 `CodeEntry` 与 `move_event.to_instruction_start` 关联起来。
3. **删除旧映射:**  删除 `move_event.from_instruction_start` 到该 `CodeEntry` 的映射。
4. **添加新映射:**  添加 `move_event.to_instruction_start` 到该 `CodeEntry` 的映射。

**假设输出：**

执行 `UpdateCodeMap` 后，`instruction_stream_map` 的状态会发生变化：

* 原来映射到 `0x1000` 的 `CodeEntry` 现在映射到 `0x2000`。
* `0x1000` 不再有对应的 `CodeEntry` 映射。

**用户常见的编程错误及示例**

CPU profiler 常常用于诊断以下 JavaScript 编程错误导致的性能问题：

1. **过度使用同步操作:**  在主线程中执行耗时的同步操作会阻塞 UI 渲染和用户交互。

   ```javascript
   // 错误示例：同步请求阻塞主线程
   function fetchDataBlocking() {
     const xhr = new XMLHttpRequest();
     xhr.open('GET', '/api/data', false); // 第三个参数为 false 表示同步
     xhr.send();
     if (xhr.status === 200) {
       return JSON.parse(xhr.responseText);
     }
     return null;
   }

   function main() {
     console.log("开始获取数据...");
     const data = fetchDataBlocking();
     console.log("数据获取完成:", data);
   }

   main();
   ```

   CPU profiler 会显示 `fetchDataBlocking` 函数占用了大量主线程时间。

2. **低效的算法或数据结构:** 使用不适合场景的算法或数据结构会导致不必要的计算开销。

   ```javascript
   // 错误示例：低效的数组查找
   function findElement(arr, target) {
     for (let i = 0; i < arr.length; i++) {
       if (arr[i] === target) {
         return i;
       }
     }
     return -1;
   }

   function main() {
     const largeArray = Array.from({ length: 100000 }, (_, i) => i);
     console.time("查找元素");
     findElement(largeArray, 99999);
     console.timeEnd("查找元素");
   }

   main();
   ```

   CPU profiler 会突出显示 `findElement` 函数中的循环是性能瓶颈。

3. **不必要的重复计算:**  在循环或频繁调用的函数中执行相同的计算多次。

   ```javascript
   // 错误示例：重复计算
   function processItems(items) {
     for (let i = 0; i < items.length; i++) {
       const item = items[i];
       const multiplier = Math.random() * 10; // 每次都重新计算
       const result = item * multiplier;
       console.log(result);
     }
   }

   function main() {
     const data = [1, 2, 3, 4, 5];
     processItems(data);
   }

   main();
   ```

   CPU profiler 可以帮助识别出 `Math.random() * 10` 的重复计算。

4. **过多的函数调用:**  在性能敏感的代码路径中进行过多的、小的函数调用会引入额外的开销。

   ```javascript
   // 错误示例：过度函数调用
   function add(a, b) { return a + b; }
   function multiply(a, b) { return a * b; }

   function calculate(x, y) {
     return multiply(add(x, 1), add(y, 2));
   }

   function main() {
     console.time("计算");
     for (let i = 0; i < 100000; i++) {
       calculate(i, i + 1);
     }
     console.timeEnd("计算");
   }

   main();
   ```

   CPU profiler 可以显示 `add` 和 `multiply` 这些小函数被频繁调用。

通过分析 CPU profiler 的结果，开发者可以定位这些性能问题，并采取相应的优化措施，例如使用异步操作、改进算法、缓存计算结果或内联函数等。

希望这个详细的解释能够帮助你理解 `v8/src/profiler/cpu-profiler.h` 文件的功能以及它在 JavaScript 性能分析中的作用。

### 提示词
```
这是目录为v8/src/profiler/cpu-profiler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/cpu-profiler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_PROFILER_CPU_PROFILER_H_
#define V8_PROFILER_CPU_PROFILER_H_

#include <atomic>
#include <memory>

#include "src/base/platform/condition-variable.h"
#include "src/base/platform/mutex.h"
#include "src/base/platform/time.h"
#include "src/profiler/circular-queue.h"
#include "src/profiler/profiler-listener.h"
#include "src/profiler/tick-sample.h"
#include "src/utils/locked-queue.h"

#if V8_OS_WIN
#include "src/base/platform/platform-win32.h"
#endif

namespace v8 {
namespace sampler {
class Sampler;
}  // namespace sampler
namespace internal {

// Forward declarations.
class CodeEntry;
class InstructionStreamMap;
class CpuProfilesCollection;
class Isolate;
class Symbolizer;

#define CODE_EVENTS_TYPE_LIST(V)                \
  V(kCodeCreation, CodeCreateEventRecord)       \
  V(kCodeMove, CodeMoveEventRecord)             \
  V(kCodeDisableOpt, CodeDisableOptEventRecord) \
  V(kCodeDeopt, CodeDeoptEventRecord)           \
  V(kReportBuiltin, ReportBuiltinEventRecord)   \
  V(kCodeDelete, CodeDeleteEventRecord)

#define VM_EVENTS_TYPE_LIST(V) \
  CODE_EVENTS_TYPE_LIST(V)     \
  V(kNativeContextMove, NativeContextMoveEventRecord)

class CodeEventRecord {
 public:
#define DECLARE_TYPE(type, ignore) type,
  enum class Type { kNoEvent = 0, VM_EVENTS_TYPE_LIST(DECLARE_TYPE) };
#undef DECLARE_TYPE

  Type type;
  mutable unsigned order;
};


class CodeCreateEventRecord : public CodeEventRecord {
 public:
  Address instruction_start;
  CodeEntry* entry;
  unsigned instruction_size;

  V8_INLINE void UpdateCodeMap(InstructionStreamMap* instruction_stream_map);
};


class CodeMoveEventRecord : public CodeEventRecord {
 public:
  Address from_instruction_start;
  Address to_instruction_start;

  V8_INLINE void UpdateCodeMap(InstructionStreamMap* instruction_stream_map);
};


class CodeDisableOptEventRecord : public CodeEventRecord {
 public:
  Address instruction_start;
  const char* bailout_reason;

  V8_INLINE void UpdateCodeMap(InstructionStreamMap* instruction_stream_map);
};


class CodeDeoptEventRecord : public CodeEventRecord {
 public:
  Address instruction_start;
  const char* deopt_reason;
  int deopt_id;
  Address pc;
  int fp_to_sp_delta;
  CpuProfileDeoptFrame* deopt_frames;
  int deopt_frame_count;

  V8_INLINE void UpdateCodeMap(InstructionStreamMap* instruction_stream_map);
};


class ReportBuiltinEventRecord : public CodeEventRecord {
 public:
  Address instruction_start;
  unsigned instruction_size;
  Builtin builtin;

  V8_INLINE void UpdateCodeMap(InstructionStreamMap* instruction_stream_map);
};

// Signals that a native context's address has changed.
class NativeContextMoveEventRecord : public CodeEventRecord {
 public:
  Address from_address;
  Address to_address;
};

// A record type for sending samples from the main thread/signal handler to the
// profiling thread.
class TickSampleEventRecord {
 public:
  // The parameterless constructor is used when we dequeue data from
  // the ticks buffer.
  TickSampleEventRecord() = default;
  explicit TickSampleEventRecord(unsigned order) : order(order) { }

  unsigned order;
  TickSample sample;
};

class CodeDeleteEventRecord : public CodeEventRecord {
 public:
  CodeEntry* entry;

  V8_INLINE void UpdateCodeMap(InstructionStreamMap* instruction_stream_map);
};

// A record type for sending code events (e.g. create, move, delete) to the
// profiling thread.
class CodeEventsContainer {
 public:
  explicit CodeEventsContainer(
      CodeEventRecord::Type type = CodeEventRecord::Type::kNoEvent) {
    generic.type = type;
  }
  union  {
    CodeEventRecord generic;
#define DECLARE_CLASS(ignore, type) type type##_;
    VM_EVENTS_TYPE_LIST(DECLARE_CLASS)
#undef DECLARE_CLASS
  };
};

// Maintains the number of active CPU profilers in an isolate, and routes
// logging to a given ProfilerListener.
class V8_NODISCARD ProfilingScope {
 public:
  ProfilingScope(Isolate* isolate, ProfilerListener* listener);
  ~ProfilingScope();

 private:
  Isolate* const isolate_;
  ProfilerListener* const listener_;
};

class ProfilerCodeObserver;

// This class implements both the profile events processor thread and
// methods called by event producers: VM and stack sampler threads.
class V8_EXPORT_PRIVATE ProfilerEventsProcessor : public base::Thread,
                                                  public CodeEventObserver {
 public:
  ~ProfilerEventsProcessor() override;

  void CodeEventHandler(const CodeEventsContainer& evt_rec) override;

  // Thread control.
  void Run() override = 0;
  void StopSynchronously();
  bool running() { return running_.load(std::memory_order_relaxed); }
  void Enqueue(const CodeEventsContainer& event);

  // Puts current stack into the tick sample events buffer.
  void AddCurrentStack(bool update_stats = false);
  void AddDeoptStack(Address from, int fp_to_sp_delta);
  // Add a sample into the tick sample events buffer. Used for testing.
  void AddSample(TickSample sample);

  virtual void SetSamplingInterval(base::TimeDelta) {}

 protected:
  ProfilerEventsProcessor(Isolate* isolate, Symbolizer* symbolizer,
                          ProfilerCodeObserver* code_observer,
                          CpuProfilesCollection* profiles);

  // Called from events processing thread (Run() method.)
  bool ProcessCodeEvent();

  enum SampleProcessingResult {
    OneSampleProcessed,
    FoundSampleForNextCodeEvent,
    NoSamplesInQueue
  };
  virtual SampleProcessingResult ProcessOneSample() = 0;

  Symbolizer* symbolizer_;
  ProfilerCodeObserver* code_observer_;
  CpuProfilesCollection* profiles_;
  std::atomic_bool running_{true};
  base::ConditionVariable running_cond_;
  base::Mutex running_mutex_;
  LockedQueue<CodeEventsContainer> events_buffer_;
  LockedQueue<TickSampleEventRecord> ticks_from_vm_buffer_;
  std::atomic<unsigned> last_code_event_id_;
  unsigned last_processed_code_event_id_;
  Isolate* isolate_;
};

class V8_EXPORT_PRIVATE SamplingEventsProcessor
    : public ProfilerEventsProcessor {
 public:
  SamplingEventsProcessor(Isolate* isolate, Symbolizer* symbolizer,
                          ProfilerCodeObserver* code_observer,
                          CpuProfilesCollection* profiles,
                          base::TimeDelta period, bool use_precise_sampling);
  ~SamplingEventsProcessor() override;

  // SamplingCircularQueue has stricter alignment requirements than a normal new
  // can fulfil, so we need to provide our own new/delete here.
  void* operator new(size_t size);
  void operator delete(void* ptr);

  void Run() override;

  void SetSamplingInterval(base::TimeDelta period) override;

  // Tick sample events are filled directly in the buffer of the circular
  // queue (because the structure is of fixed width, but usually not all
  // stack frame entries are filled.) This method returns a pointer to the
  // next record of the buffer.
  // These methods are not thread-safe and should only ever be called by one
  // producer (from CpuSampler::SampleStack()). For testing, use AddSample.
  inline TickSample* StartTickSample();
  inline void FinishTickSample();

  sampler::Sampler* sampler() { return sampler_.get(); }
  base::TimeDelta period() const { return period_; }

 private:
  SampleProcessingResult ProcessOneSample() override;
  void SymbolizeAndAddToProfiles(const TickSampleEventRecord* record);

  static const size_t kTickSampleBufferSize = 512 * KB;
  static const size_t kTickSampleQueueLength =
      kTickSampleBufferSize / sizeof(TickSampleEventRecord);
  SamplingCircularQueue<TickSampleEventRecord,
                        kTickSampleQueueLength> ticks_buffer_;
  std::unique_ptr<sampler::Sampler> sampler_;
  base::TimeDelta period_;           // Samples & code events processing period.
  const bool use_precise_sampling_;  // Whether or not busy-waiting is used for
                                     // low sampling intervals on Windows.
#if V8_OS_WIN
  base::PreciseSleepTimer precise_sleep_timer_;
#endif  // V8_OS_WIN
};

// Builds and maintains an InstructionStreamMap tracking code objects on the VM
// heap. While alive, logs generated code, callbacks, and builtins from the
// isolate. Redirects events to the profiler events processor when present.
// CodeEntry lifetime is associated with the given CodeEntryStorage.
class V8_EXPORT_PRIVATE ProfilerCodeObserver : public CodeEventObserver {
 public:
  explicit ProfilerCodeObserver(Isolate*, CodeEntryStorage&);

  void CodeEventHandler(const CodeEventsContainer& evt_rec) override;
  CodeEntryStorage* code_entries() { return &code_entries_; }
  InstructionStreamMap* instruction_stream_map() { return &code_map_; }
  WeakCodeRegistry* weak_code_registry() { return &weak_code_registry_; }
  size_t GetEstimatedMemoryUsage() const;

  void ClearCodeMap();

 private:
  friend class ProfilerEventsProcessor;

  void CodeEventHandlerInternal(const CodeEventsContainer& evt_rec);

  void CreateEntriesForRuntimeCallStats();
  void LogBuiltins();

  ProfilerEventsProcessor* processor() { return processor_; }

  // Redirects code events to be enqueued on the given events processor.
  void set_processor(ProfilerEventsProcessor* processor) {
    processor_ = processor;
  }

  // Stops redirection of code events onto an events processor.
  void clear_processor() { processor_ = nullptr; }

  Isolate* const isolate_;
  CodeEntryStorage& code_entries_;
  InstructionStreamMap code_map_;
  WeakCodeRegistry weak_code_registry_;
  ProfilerEventsProcessor* processor_;
};

// The CpuProfiler is a sampling CPU profiler for JS frames. It corresponds to
// v8::CpuProfiler at the API level. It spawns an additional thread which is
// responsible for triggering samples and then symbolizing the samples with
// function names. To symbolize on a background thread, the profiler copies
// metadata about generated code off-heap.
//
// Sampling is done using posix signals (except on Windows). The profiling
// thread sends a signal to the main thread, based on a timer. The signal
// handler can interrupt the main thread between any abitrary instructions.
// This means we are very careful about reading stack values during the signal
// handler as we could be in the middle of an operation that is modifying the
// stack.
//
// The story on Windows is similar except we use thread suspend and resume.
//
// Samples are passed to the profiling thread via a circular buffer. The
// profiling thread symbolizes the samples by looking up the code pointers
// against its own list of code objects. The profiling thread also listens for
// code creation/move/deletion events (from the GC), to maintain its list of
// code objects accurately.
class V8_EXPORT_PRIVATE CpuProfiler {
 public:
  explicit CpuProfiler(Isolate* isolate, CpuProfilingNamingMode = kDebugNaming,
                       CpuProfilingLoggingMode = kLazyLogging);

  CpuProfiler(Isolate* isolate, CpuProfilingNamingMode naming_mode,
              CpuProfilingLoggingMode logging_mode,
              CpuProfilesCollection* profiles, Symbolizer* test_symbolizer,
              ProfilerEventsProcessor* test_processor,
              ProfilerCodeObserver* test_code_observer);

  ~CpuProfiler();
  CpuProfiler(const CpuProfiler&) = delete;
  CpuProfiler& operator=(const CpuProfiler&) = delete;

  static void CollectSample(Isolate* isolate);
  static size_t GetAllProfilersMemorySize(Isolate* isolate);

  using ProfilingMode = v8::CpuProfilingMode;
  using CpuProfilingResult = v8::CpuProfilingResult;
  using NamingMode = v8::CpuProfilingNamingMode;
  using LoggingMode = v8::CpuProfilingLoggingMode;
  using StartProfilingStatus = CpuProfilingStatus;

  base::TimeDelta sampling_interval() const { return base_sampling_interval_; }
  void set_sampling_interval(base::TimeDelta value);
  void set_use_precise_sampling(bool);
  void CollectSample();
  size_t GetEstimatedMemoryUsage() const;
  CpuProfilingResult StartProfiling(
      CpuProfilingOptions options = {},
      std::unique_ptr<DiscardedSamplesDelegate> delegate = nullptr);
  CpuProfilingResult StartProfiling(
      const char* title, CpuProfilingOptions options = {},
      std::unique_ptr<DiscardedSamplesDelegate> delegate = nullptr);
  CpuProfilingResult StartProfiling(
      Tagged<String> title, CpuProfilingOptions options = {},
      std::unique_ptr<DiscardedSamplesDelegate> delegate = nullptr);

  CpuProfile* StopProfiling(const char* title);
  CpuProfile* StopProfiling(Tagged<String> title);
  CpuProfile* StopProfiling(ProfilerId id);

  int GetProfilesCount();
  CpuProfile* GetProfile(int index);
  void DeleteAllProfiles();
  void DeleteProfile(CpuProfile* profile);

  bool is_profiling() const { return is_profiling_; }

  Symbolizer* symbolizer() const { return symbolizer_.get(); }
  ProfilerEventsProcessor* processor() const { return processor_.get(); }
  Isolate* isolate() const { return isolate_; }
  CodeEntryStorage* code_entries() { return &code_entries_; }

  ProfilerListener* profiler_listener_for_test() const {
    return profiler_listener_.get();
  }
  InstructionStreamMap* code_map_for_test() {
    return code_observer_->instruction_stream_map();
  }

 private:
  void StartProcessorIfNotStarted();
  void StopProcessor();
  void ResetProfiles();

  void EnableLogging();
  void DisableLogging();

  // Computes a sampling interval sufficient to accomodate attached profiles.
  base::TimeDelta ComputeSamplingInterval();
  // Dynamically updates the sampler to use a sampling interval sufficient for
  // child profiles.
  void AdjustSamplingInterval();

  Isolate* const isolate_;
  const NamingMode naming_mode_;
  const LoggingMode logging_mode_;
  bool use_precise_sampling_ = true;
  // Sampling interval to which per-profile sampling intervals will be clamped
  // to a multiple of, or used as the default if unspecified.
  base::TimeDelta base_sampling_interval_;

  // Storage for CodeEntry objects allocated by the profiler. May live for
  // multiple profiling sessions, independent of heap listener state.
  CodeEntryStorage code_entries_;

  std::unique_ptr<ProfilerCodeObserver> code_observer_;
  std::unique_ptr<CpuProfilesCollection> profiles_;
  std::unique_ptr<Symbolizer> symbolizer_;
  std::unique_ptr<ProfilerEventsProcessor> processor_;
  std::unique_ptr<ProfilerListener> profiler_listener_;
  std::unique_ptr<ProfilingScope> profiling_scope_;
  bool is_profiling_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_PROFILER_CPU_PROFILER_H_
```