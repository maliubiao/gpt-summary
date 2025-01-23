Response:
Let's break down the thought process for analyzing the `sampler.cc` file.

1. **Initial Scan and Keywords:** I'd first scan the file for recognizable keywords and patterns. Things that jump out are:
    * `#include`: Indicates dependencies and what functionalities are being used (like `v8-isolate.h`, platform-specific headers like `<pthread.h>`, `<windows.h>`, etc.).
    * `// Copyright`: Standard header.
    * `namespace v8::sampler`:  Immediately tells us this code is part of V8's sampling mechanism.
    * `Sampler`, `SamplerManager`: These are clearly core classes.
    * `Start()`, `Stop()`, `DoSample()`: These look like lifecycle and core functionality methods.
    * `USE_SIGNALS`, `V8_OS_WIN`, `V8_OS_FUCHSIA`:  Preprocessor directives hinting at platform-specific implementations.
    * `RegisterState`: A struct likely holding CPU register information.
    * `AtomicGuard`, `AtomicMutex`:  Concurrency control mechanisms.
    * `sigaction`, `SIGPROF`, `pthread_kill`:  Signal handling related keywords.
    * `SuspendThread`, `GetThreadContext`, `ResumeThread`: Windows threading functions.
    * `zx_task_suspend_token`, `zx_thread_read_state`: Fuchsia system calls.
    * Lots of `#if` and `#elif`:  Confirms platform-specific behavior.

2. **High-Level Functionality (Deduction from Keywords):** Based on the initial scan, I can infer the primary purpose: *to sample the execution state of threads within the V8 JavaScript engine*. The platform-specific directives suggest different techniques are used depending on the operating system. The presence of `RegisterState` and code to fill it implies capturing CPU register values for analysis (e.g., stack tracing).

3. **Platform-Specific Analysis:** I'd then focus on the different platform blocks:

    * **`USE_SIGNALS`:**  This clearly uses signals (like `SIGPROF`) to interrupt the target thread and capture its state. The `SignalHandler` class manages the installation and handling of these signals.
    * **`V8_OS_WIN || V8_OS_CYGWIN`:**  This uses Windows-specific API calls like `SuspendThread`, `GetThreadContext`, and `ResumeThread` to pause the thread and get its context.
    * **`V8_OS_FUCHSIA`:** This uses Fuchsia-specific system calls for thread suspension and register state retrieval.

4. **Core Classes and Their Roles:**

    * **`Sampler`:**  Represents a sampler for a single thread. It has `Start()` and `Stop()` methods to control the sampling process, and `DoSample()` to trigger a sample. It stores platform-specific data (`PlatformData`).
    * **`SamplerManager`:** A singleton responsible for managing all active samplers across different threads. It keeps track of samplers in a map keyed by thread ID and provides a `DoSample()` method that's called when a signal arrives (or a platform-specific sampling event occurs). The use of `AtomicGuard` suggests thread-safety concerns.
    * **`PlatformData`:**  An abstract base (implicitly through platform-specific implementations) to hold data specific to how sampling is done on a given OS (e.g., the thread handle on Windows, or thread ID on POSIX).
    * **`RegisterState`:**  A simple struct to hold the program counter (PC), stack pointer (SP), frame pointer (FP), and sometimes link register (LR). This is the raw data captured during a sample.
    * **`SignalHandler`:** (Only for `USE_SIGNALS`) Manages the installation and handling of the `SIGPROF` signal, ensuring only one handler is active at a time.

5. **Code Logic and Data Flow (Signal Case):**

    * `Sampler::Start()`: Increments a global signal handler count and adds the sampler to `SamplerManager`. If it's the first sampler, it installs the signal handler.
    * `Sampler::Stop()`: Decrements the signal handler count and removes the sampler. If it's the last sampler, it uninstalls the signal handler.
    * `Sampler::DoSample()`:  Sets a flag to indicate a sample should be recorded and then sends a `SIGPROF` signal to the target thread.
    * `SignalHandler::HandleProfilerSignal()`:  Called when `SIGPROF` arrives. It extracts register values from the signal context and calls `SamplerManager::DoSample()`.
    * `SamplerManager::DoSample()`: Iterates through the samplers for the current thread and calls `SampleStack()` on each active sampler.

6. **JavaScript Relationship (Hypothesizing):**  Since this is V8 code, it's about profiling JavaScript execution. I'd think about how this sampling relates to what a developer sees:

    * **CPU Profiling:** The captured stack traces are used to identify performance bottlenecks in JavaScript code. By repeatedly sampling, we can statistically determine which parts of the code are consuming the most CPU time.
    * **Developer Tools:**  This data is likely used by Chrome DevTools or similar profiling tools to visualize call stacks and CPU usage.

7. **Common Programming Errors (Based on the Code):**

    * **Signal Handling Issues:** Incorrect signal mask configuration or not handling signals reentrantly are common problems in signal-based programming. The code seems to take care to install and restore the signal handler carefully.
    * **Thread Synchronization:** The use of `AtomicGuard` highlights the need for thread-safe access to shared data structures like `sampler_map_`. Forgetting proper locking can lead to race conditions.
    * **Platform Dependencies:** The extensive use of `#ifdef` shows how crucial it is to handle platform differences correctly when dealing with low-level system interactions. Incorrectly assuming a particular OS behavior can lead to bugs.
    * **Resource Management:**  The Windows implementation needs to correctly handle and close thread handles to avoid leaks.

8. **Torque Check:** The prompt asks about `.tq` files. I'd look for any indications that this C++ code is generated from Torque. In this case, there's no explicit mention of Torque or any patterns suggesting code generation. So, the conclusion would be that it's not a Torque file.

9. **Putting it all together:** Finally, I'd synthesize the information gathered into a coherent description of the file's functionality, addressing all the points raised in the prompt. This involves summarizing the core purpose, explaining the platform-specific implementations, outlining the code logic, illustrating the connection to JavaScript, giving examples of potential errors, and confirming whether it's a Torque file.
好的，让我们来分析一下 `v8/src/libsampler/sampler.cc` 这个文件。

**功能概述:**

`v8/src/libsampler/sampler.cc` 实现了 V8 引擎的**采样器 (Sampler)** 功能。其主要目的是**周期性地捕获 V8 引擎中正在运行的线程的执行状态**，特别是其调用堆栈信息。这些信息对于性能分析、CPU 性能剖析 (profiling) 以及调试等场景至关重要。

**具体功能点:**

1. **跨平台支持的采样机制:**  该文件根据不同的操作系统 (如 Linux, macOS, Windows, Fuchsia 等) 提供了不同的采样实现方式。
    * **基于信号 (Signals) 的采样 (USE_SIGNALS):** 在支持 POSIX 信号的系统上，它使用 `SIGPROF` 信号来中断目标线程，并在信号处理程序中读取线程的寄存器状态，从而获取调用堆栈信息。
    * **基于线程挂起/恢复的采样 (Windows/Cygwin):** 在 Windows 系统上，它使用 `SuspendThread` 挂起目标线程，然后使用 `GetThreadContext` 获取线程上下文 (包括寄存器状态)，最后使用 `ResumeThread` 恢复线程。
    * **基于系统调用的采样 (Fuchsia):** 在 Fuchsia 操作系统上，它使用特定的系统调用 (如 `zx_task_suspend_token` 和 `zx_thread_read_state`) 来挂起线程并读取其寄存器状态。

2. **`Sampler` 类:**  核心类，负责单个线程的采样。
    * `Start()`: 启动采样器，激活采样。
    * `Stop()`: 停止采样器，禁用采样。
    * `DoSample()`:  执行一次采样，获取当前线程的调用堆栈信息。具体的实现方式取决于操作系统。
    * `SampleStack()`:  抽象方法 (在其他地方实现，通常与平台无关的代码)，用于根据获取到的寄存器状态来解析和记录调用堆栈。
    * `PlatformData`: 一个内部类，用于存储特定于平台的采样数据 (例如，Windows 上的线程句柄)。

3. **`SamplerManager` 类:**  用于管理所有的 `Sampler` 实例，通常以单例模式存在。
    * `AddSampler()`: 添加一个活动的采样器。
    * `RemoveSampler()`: 移除一个活动的采样器。
    * `DoSample()`:  当收到采样事件 (例如，信号) 时，`SamplerManager` 会找到当前线程的所有活动采样器并调用它们的 `SampleStack()` 方法。

4. **信号处理 (`SignalHandler` 类，仅限 `USE_SIGNALS`):**
    * 负责安装和卸载 `SIGPROF` 信号处理程序。
    * `HandleProfilerSignal()`:  当 `SIGPROF` 信号到达时被调用，它会提取线程的寄存器状态，并调用 `SamplerManager::DoSample()`。
    * 使用互斥锁 (`base::LazyRecursiveMutex`) 来保护全局状态。

5. **寄存器状态 (`RegisterState` 结构体):**  一个简单的结构体，用于存储关键的 CPU 寄存器信息，例如程序计数器 (PC)、栈指针 (SP)、帧指针 (FP) 和链接寄存器 (LR)。这些寄存器的值用于回溯调用堆栈。

6. **线程安全的访问:**  使用 `AtomicGuard` 和 `AtomicMutex` 来确保对共享数据结构 (如 `sampler_map_` 在 `SamplerManager` 中) 的线程安全访问。

**关于 Torque:**

如果 `v8/src/libsampler/sampler.cc` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是在解释器和编译器等性能关键部分。

**然而，根据您提供的文件名 `v8/src/libsampler/sampler.cc`，它是一个 C++ 源文件，而不是 Torque 文件。**

**与 JavaScript 功能的关系 (CPU 性能剖析):**

`v8/src/libsampler/sampler.cc` 的核心功能是支持 JavaScript 代码的 **CPU 性能剖析 (Profiling)**。当开发者使用 Chrome DevTools 或 Node.js 的 `--cpu-profile` 等工具进行性能分析时，V8 内部就会使用这个采样器来收集 JavaScript 代码的执行信息。

**JavaScript 示例:**

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

当您对这段 JavaScript 代码进行 CPU 性能剖析时，`sampler.cc` 中的代码会被激活，定期捕获 JavaScript 代码执行时的调用堆栈。这些调用堆栈信息会显示哪些 JavaScript 函数占用了最多的 CPU 时间，帮助开发者识别性能瓶颈。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的 JavaScript 调用栈：

```
mainFunction -> helperFunction -> deeplyNestedFunction
```

并且采样器在 `deeplyNestedFunction` 正在执行时被触发。

**假设输入 (基于信号采样):**

* **触发信号:** `SIGPROF` 信号被发送到执行 JavaScript 的线程。
* **信号上下文 (`context` 参数在 `SignalHandler::HandleProfilerSignal` 中):** 包含当前线程的寄存器状态，例如：
    * `state->pc`: 指向 `deeplyNestedFunction` 内部的指令地址。
    * `state->sp`: 当前栈顶的地址。
    * `state->fp`: 当前帧指针的地址。

**输出 (简化):**

`SampleStack()` 函数 (未在此文件中实现) 会根据输入的寄存器状态，通过回溯栈帧，生成一个调用堆栈信息，大致如下：

```
[
  { function: "deeplyNestedFunction", address: "0x...", ... },
  { function: "helperFunction", address: "0x...", ... },
  { function: "mainFunction", address: "0x...", ... }
]
```

**涉及用户常见的编程错误 (与性能分析相关):**

虽然 `sampler.cc` 本身是 V8 内部的代码，但它揭示了用户在编写 JavaScript 代码时可能遇到的与性能分析相关的错误：

1. **过度使用同步操作导致线程阻塞:**  采样结果可能会显示大量时间花费在等待锁或其他同步操作上，这表明代码中存在不必要的同步瓶颈。

   **例子:**

   ```javascript
   let mutex = false;

   function criticalSection() {
     while (mutex) { /* Spin lock */ }
     mutex = true;
     // ... 执行一些需要互斥访问的代码 ...
     mutex = false;
   }

   function main() {
     for (let i = 0; i < 10000; i++) {
       criticalSection();
     }
   }

   main();
   ```

   性能分析可能会显示 `criticalSection` 函数及其内部的自旋锁循环占用大量 CPU 时间，但这实际上是浪费的，因为它只是在等待。

2. **在事件循环中执行耗时的同步操作:** Node.js 的事件循环是单线程的。如果 JavaScript 代码执行了长时间的同步操作，会导致事件循环阻塞，降低应用程序的响应性。性能分析会突出显示这些耗时操作。

   **例子:**

   ```javascript
   const fs = require('fs');

   function processFile() {
     const data = fs.readFileSync('/path/to/large/file.txt', 'utf8'); // 同步读取大文件
     // ... 处理文件内容 ...
   }

   function main() {
     console.log('Start');
     processFile();
     console.log('End');
   }

   main();
   ```

   性能分析会显示 `fs.readFileSync` 占用大量 CPU 时间，因为它是一个阻塞操作，会阻止事件循环处理其他事件。

3. **频繁的垃圾回收 (GC):** 虽然 `sampler.cc` 不直接涉及 GC，但 CPU 性能剖析可以揭示由于频繁的对象创建和销毁导致的 GC 开销。

   **例子:**

   ```javascript
   function createManyObjects() {
     for (let i = 0; i < 1000000; i++) {
       new Object(); // 频繁创建临时对象
     }
   }

   function main() {
     createManyObjects();
   }

   main();
   ```

   虽然代码本身可能看起来很简单，但性能分析可能会显示大量的 CPU 时间花费在垃圾回收上。

**总结:**

`v8/src/libsampler/sampler.cc` 是 V8 引擎中用于 CPU 性能剖析的关键组件，它提供了跨平台的采样机制来捕获线程的执行状态。虽然它本身不是 Torque 代码，但它支持了开发者对 JavaScript 代码进行性能分析，帮助他们识别和修复性能瓶颈。理解其工作原理有助于开发者更好地理解性能分析工具的输出，并避免常见的性能问题。

### 提示词
```
这是目录为v8/src/libsampler/sampler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/libsampler/sampler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/libsampler/sampler.h"

#include "include/v8-isolate.h"
#include "include/v8-platform.h"
#include "include/v8-unwinder.h"

#ifdef USE_SIGNALS

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <atomic>

#if !V8_OS_QNX && !V8_OS_AIX && !V8_OS_ZOS
#include <sys/syscall.h>
#endif

#if V8_OS_AIX || V8_TARGET_ARCH_S390X

#include "src/base/platform/time.h"

#elif V8_OS_DARWIN
#include <mach/mach.h>
// OpenBSD doesn't have <ucontext.h>. ucontext_t lives in <signal.h>
// and is a typedef for struct sigcontext. There is no uc_mcontext.
#elif !V8_OS_OPENBSD
#include <ucontext.h>
#endif

#include <unistd.h>

#elif V8_OS_WIN || V8_OS_CYGWIN

#include <windows.h>

#elif V8_OS_FUCHSIA

#include <zircon/process.h>
#include <zircon/syscalls.h>
#include <zircon/syscalls/debug.h>
#include <zircon/types.h>

// TODO(wez): Remove this once the Fuchsia SDK has rolled.
#if defined(ZX_THREAD_STATE_REGSET0)
#define ZX_THREAD_STATE_GENERAL_REGS ZX_THREAD_STATE_REGSET0
zx_status_t zx_thread_read_state(zx_handle_t h, uint32_t k, void* b, size_t l) {
  uint32_t dummy_out_len = 0;
  return zx_thread_read_state(h, k, b, static_cast<uint32_t>(l),
                              &dummy_out_len);
}
#if defined(__x86_64__)
using zx_thread_state_general_regs_t = zx_x86_64_general_regs_t;
#else
using zx_thread_state_general_regs_t = zx_arm64_general_regs_t;
#endif
#endif  // !defined(ZX_THREAD_STATE_GENERAL_REGS)

#endif

#include <algorithm>
#include <vector>

#include "src/base/atomic-utils.h"
#include "src/base/platform/platform.h"

#if V8_OS_ZOS
// Header from zoslib, for __mcontext_t_:
#include "edcwccwi.h"
#endif

#if V8_OS_ANDROID && !defined(__BIONIC_HAVE_UCONTEXT_T)

// Not all versions of Android's C library provide ucontext_t.
// Detect this and provide custom but compatible definitions. Note that these
// follow the GLibc naming convention to access register values from
// mcontext_t.
//
// See http://code.google.com/p/android/issues/detail?id=34784

#if defined(__arm__)

using mcontext_t = struct sigcontext;

struct ucontext_t {
  uint32_t uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  // Other fields are not used by V8, don't define them here.
};

#elif defined(__aarch64__)

using mcontext_t = struct sigcontext;

struct ucontext_t {
  uint64_t uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  // Other fields are not used by V8, don't define them here.
};

#elif defined(__mips__)
// MIPS version of sigcontext, for Android bionic.
struct mcontext_t {
  uint32_t regmask;
  uint32_t status;
  uint64_t pc;
  uint64_t gregs[32];
  uint64_t fpregs[32];
  uint32_t acx;
  uint32_t fpc_csr;
  uint32_t fpc_eir;
  uint32_t used_math;
  uint32_t dsp;
  uint64_t mdhi;
  uint64_t mdlo;
  uint32_t hi1;
  uint32_t lo1;
  uint32_t hi2;
  uint32_t lo2;
  uint32_t hi3;
  uint32_t lo3;
};

struct ucontext_t {
  uint32_t uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  // Other fields are not used by V8, don't define them here.
};

#elif defined(__i386__)
// x86 version for Android.
struct mcontext_t {
  uint32_t gregs[19];
  void* fpregs;
  uint32_t oldmask;
  uint32_t cr2;
};

using kernel_sigset_t = uint32_t[2];  // x86 kernel uses 64-bit signal masks
struct ucontext_t {
  uint32_t uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  // Other fields are not used by V8, don't define them here.
};
enum { REG_EBP = 6, REG_ESP = 7, REG_EIP = 14 };

#elif defined(__x86_64__)
// x64 version for Android.
struct mcontext_t {
  uint64_t gregs[23];
  void* fpregs;
  uint64_t __reserved1[8];
};

struct ucontext_t {
  uint64_t uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  // Other fields are not used by V8, don't define them here.
};
enum { REG_RBP = 10, REG_RSP = 15, REG_RIP = 16 };
#endif

#endif  // V8_OS_ANDROID && !defined(__BIONIC_HAVE_UCONTEXT_T)

namespace v8 {
namespace sampler {

#if defined(USE_SIGNALS)

AtomicGuard::AtomicGuard(AtomicMutex* atomic, bool is_blocking)
    : atomic_(atomic), is_success_(false) {
  do {
    bool expected = false;
    // We have to use the strong version here for the case where is_blocking
    // is false, and we will only attempt the exchange once.
    is_success_ = atomic->compare_exchange_strong(expected, true);
  } while (is_blocking && !is_success_);
}

AtomicGuard::~AtomicGuard() {
  if (!is_success_) return;
  atomic_->store(false);
}

bool AtomicGuard::is_success() const { return is_success_; }

class Sampler::PlatformData {
 public:
  PlatformData()
      : vm_tid_(base::OS::GetCurrentThreadId()), vm_tself_(pthread_self()) {}
  int vm_tid() const { return vm_tid_; }
  pthread_t vm_tself() const { return vm_tself_; }

 private:
  int vm_tid_;
  pthread_t vm_tself_;
};

void SamplerManager::AddSampler(Sampler* sampler) {
  AtomicGuard atomic_guard(&samplers_access_counter_);
  DCHECK(sampler->IsActive());
  int thread_id = sampler->platform_data()->vm_tid();
  auto it = sampler_map_.find(thread_id);
  if (it == sampler_map_.end()) {
    SamplerList samplers;
    samplers.push_back(sampler);
    sampler_map_.emplace(thread_id, std::move(samplers));
  } else {
    SamplerList& samplers = it->second;
    auto sampler_it = std::find(samplers.begin(), samplers.end(), sampler);
    if (sampler_it == samplers.end()) samplers.push_back(sampler);
  }
}

void SamplerManager::RemoveSampler(Sampler* sampler) {
  AtomicGuard atomic_guard(&samplers_access_counter_);
  DCHECK(sampler->IsActive());
  int thread_id = sampler->platform_data()->vm_tid();
  auto it = sampler_map_.find(thread_id);
  DCHECK_NE(it, sampler_map_.end());
  SamplerList& samplers = it->second;
  samplers.erase(std::remove(samplers.begin(), samplers.end(), sampler),
                 samplers.end());
  if (samplers.empty()) {
    sampler_map_.erase(it);
  }
}

void SamplerManager::DoSample(const v8::RegisterState& state) {
  AtomicGuard atomic_guard(&samplers_access_counter_, false);
  // TODO(petermarshall): Add stat counters for the bailouts here.
  if (!atomic_guard.is_success()) return;
  int thread_id = base::OS::GetCurrentThreadId();
  auto it = sampler_map_.find(thread_id);
  if (it == sampler_map_.end()) return;
  SamplerList& samplers = it->second;

  for (Sampler* sampler : samplers) {
    if (!sampler->ShouldRecordSample()) continue;
    Isolate* isolate = sampler->isolate();
    // We require a fully initialized and entered isolate.
    if (isolate == nullptr || !isolate->IsInUse()) continue;
    sampler->SampleStack(state);
  }
}

SamplerManager* SamplerManager::instance() {
  static base::LeakyObject<SamplerManager> instance;
  return instance.get();
}

#elif V8_OS_WIN || V8_OS_CYGWIN

// ----------------------------------------------------------------------------
// Win32 profiler support. On Cygwin we use the same sampler implementation as
// on Win32.

class Sampler::PlatformData {
 public:
  // Get a handle to the calling thread. This is the thread that we are
  // going to profile. We need to make a copy of the handle because we are
  // going to use it in the sampler thread.
  PlatformData() {
    HANDLE current_process = GetCurrentProcess();
    BOOL result = DuplicateHandle(
        current_process, GetCurrentThread(), current_process, &profiled_thread_,
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        FALSE, 0);
    DCHECK(result);
    USE(result);
  }

  ~PlatformData() {
    if (profiled_thread_ != nullptr) {
      CloseHandle(profiled_thread_);
      profiled_thread_ = nullptr;
    }
  }

  HANDLE profiled_thread() { return profiled_thread_; }

 private:
  HANDLE profiled_thread_;
};

#elif V8_OS_FUCHSIA

class Sampler::PlatformData {
 public:
  PlatformData() {
    zx_handle_duplicate(zx_thread_self(), ZX_RIGHT_SAME_RIGHTS,
                        &profiled_thread_);
  }
  ~PlatformData() {
    if (profiled_thread_ != ZX_HANDLE_INVALID) {
      zx_handle_close(profiled_thread_);
      profiled_thread_ = ZX_HANDLE_INVALID;
    }
  }

  zx_handle_t profiled_thread() { return profiled_thread_; }

 private:
  zx_handle_t profiled_thread_ = ZX_HANDLE_INVALID;
};

#endif  // USE_SIGNALS

#if defined(USE_SIGNALS)
class SignalHandler {
 public:
  static void IncreaseSamplerCount() {
    base::RecursiveMutexGuard lock_guard(mutex_.Pointer());
    if (++client_count_ == 1) Install();
  }

  static void DecreaseSamplerCount() {
    base::RecursiveMutexGuard lock_guard(mutex_.Pointer());
    if (--client_count_ == 0) Restore();
  }

  static bool Installed() {
    // mutex_ will also be used in Sampler::DoSample to guard the state below.
    base::RecursiveMutexGuard lock_guard(mutex_.Pointer());
    return signal_handler_installed_;
  }

  static v8::base::RecursiveMutex* mutex() { return mutex_.Pointer(); }

 private:
  static void Install() {
    struct sigaction sa;
    sa.sa_sigaction = &HandleProfilerSignal;
    sigemptyset(&sa.sa_mask);
#if V8_OS_QNX
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
#else
    sa.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
#endif
    signal_handler_installed_ =
        (sigaction(SIGPROF, &sa, &old_signal_handler_) == 0);
  }

  static void Restore() {
    if (signal_handler_installed_) {
      signal_handler_installed_ = false;
#if V8_OS_AIX || V8_TARGET_ARCH_S390X
      // On Aix, IBMi & zLinux SIGPROF can sometimes arrive after the
      // default signal handler is restored, resulting in intermittent test
      // failure when profiling is enabled (https://crbug.com/v8/12952)
      base::OS::Sleep(base::TimeDelta::FromMicroseconds(10));
#endif
      sigaction(SIGPROF, &old_signal_handler_, nullptr);
    }
  }

  static void FillRegisterState(void* context, RegisterState* regs);
  static void HandleProfilerSignal(int signal, siginfo_t* info, void* context);

  // Protects the process wide state below.
  static base::LazyRecursiveMutex mutex_;
  static int client_count_;
  static bool signal_handler_installed_;
  static struct sigaction old_signal_handler_;
};

base::LazyRecursiveMutex SignalHandler::mutex_ =
    LAZY_RECURSIVE_MUTEX_INITIALIZER;

int SignalHandler::client_count_ = 0;
struct sigaction SignalHandler::old_signal_handler_;
bool SignalHandler::signal_handler_installed_ = false;

void SignalHandler::HandleProfilerSignal(int signal, siginfo_t* info,
                                         void* context) {
  v8::ThreadIsolatedAllocator::SetDefaultPermissionsForSignalHandler();
  USE(info);
  if (signal != SIGPROF) return;
  v8::RegisterState state;
  FillRegisterState(context, &state);
  SamplerManager::instance()->DoSample(state);
}

void SignalHandler::FillRegisterState(void* context, RegisterState* state) {
  // Extracting the sample from the context is extremely machine dependent.
  ucontext_t* ucontext = reinterpret_cast<ucontext_t*>(context);
#if !(V8_OS_OPENBSD || V8_OS_ZOS || \
      (V8_OS_LINUX && (V8_HOST_ARCH_S390X || V8_HOST_ARCH_PPC64)))
  mcontext_t& mcontext = ucontext->uc_mcontext;
#elif V8_OS_ZOS
  __mcontext_t_* mcontext = reinterpret_cast<__mcontext_t_*>(context);
#endif
#if V8_OS_LINUX
#if V8_HOST_ARCH_IA32
  state->pc = reinterpret_cast<void*>(mcontext.gregs[REG_EIP]);
  state->sp = reinterpret_cast<void*>(mcontext.gregs[REG_ESP]);
  state->fp = reinterpret_cast<void*>(mcontext.gregs[REG_EBP]);
#elif V8_HOST_ARCH_X64
  state->pc = reinterpret_cast<void*>(mcontext.gregs[REG_RIP]);
  state->sp = reinterpret_cast<void*>(mcontext.gregs[REG_RSP]);
  state->fp = reinterpret_cast<void*>(mcontext.gregs[REG_RBP]);
#elif V8_HOST_ARCH_ARM
#if V8_LIBC_GLIBC && !V8_GLIBC_PREREQ(2, 4)
  // Old GLibc ARM versions used a gregs[] array to access the register
  // values from mcontext_t.
  state->pc = reinterpret_cast<void*>(mcontext.gregs[R15]);
  state->sp = reinterpret_cast<void*>(mcontext.gregs[R13]);
  state->fp = reinterpret_cast<void*>(mcontext.gregs[R11]);
  state->lr = reinterpret_cast<void*>(mcontext.gregs[R14]);
#else
  state->pc = reinterpret_cast<void*>(mcontext.arm_pc);
  state->sp = reinterpret_cast<void*>(mcontext.arm_sp);
  state->fp = reinterpret_cast<void*>(mcontext.arm_fp);
  state->lr = reinterpret_cast<void*>(mcontext.arm_lr);
#endif  // V8_LIBC_GLIBC && !V8_GLIBC_PREREQ(2, 4)
#elif V8_HOST_ARCH_ARM64
  state->pc = reinterpret_cast<void*>(mcontext.pc);
  state->sp = reinterpret_cast<void*>(mcontext.sp);
  // FP is an alias for x29.
  state->fp = reinterpret_cast<void*>(mcontext.regs[29]);
  // LR is an alias for x30.
  state->lr = reinterpret_cast<void*>(mcontext.regs[30]);
#elif V8_HOST_ARCH_MIPS64
  state->pc = reinterpret_cast<void*>(mcontext.pc);
  state->sp = reinterpret_cast<void*>(mcontext.gregs[29]);
  state->fp = reinterpret_cast<void*>(mcontext.gregs[30]);
#elif V8_HOST_ARCH_LOONG64
  state->pc = reinterpret_cast<void*>(mcontext.__pc);
  state->sp = reinterpret_cast<void*>(mcontext.__gregs[3]);
  state->fp = reinterpret_cast<void*>(mcontext.__gregs[22]);
#elif V8_HOST_ARCH_PPC64
#if V8_LIBC_GLIBC
  state->pc = reinterpret_cast<void*>(ucontext->uc_mcontext.regs->nip);
  state->sp = reinterpret_cast<void*>(ucontext->uc_mcontext.regs->gpr[PT_R1]);
  state->fp = reinterpret_cast<void*>(ucontext->uc_mcontext.regs->gpr[PT_R31]);
  state->lr = reinterpret_cast<void*>(ucontext->uc_mcontext.regs->link);
#else
  // Some C libraries, notably Musl, define the regs member as a void pointer
  state->pc = reinterpret_cast<void*>(ucontext->uc_mcontext.gp_regs[32]);
  state->sp = reinterpret_cast<void*>(ucontext->uc_mcontext.gp_regs[1]);
  state->fp = reinterpret_cast<void*>(ucontext->uc_mcontext.gp_regs[31]);
  state->lr = reinterpret_cast<void*>(ucontext->uc_mcontext.gp_regs[36]);
#endif
#elif V8_HOST_ARCH_S390X
  state->pc = reinterpret_cast<void*>(ucontext->uc_mcontext.psw.addr);
  state->sp = reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[15]);
  state->fp = reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[11]);
  state->lr = reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[14]);
#elif V8_HOST_ARCH_RISCV64 || V8_HOST_ARCH_RISCV32
  // Spec CH.25 RISC-V Assembly Programmer’s Handbook
  state->pc = reinterpret_cast<void*>(mcontext.__gregs[REG_PC]);
  state->sp = reinterpret_cast<void*>(mcontext.__gregs[REG_SP]);
  state->fp = reinterpret_cast<void*>(mcontext.__gregs[REG_S0]);
  state->lr = reinterpret_cast<void*>(mcontext.__gregs[REG_RA]);
#endif  // V8_HOST_ARCH_*

#elif V8_OS_ZOS
  state->pc = reinterpret_cast<void*>(mcontext->__mc_psw);
  state->sp = reinterpret_cast<void*>(mcontext->__mc_gr[15]);
  state->fp = reinterpret_cast<void*>(mcontext->__mc_gr[11]);
  state->lr = reinterpret_cast<void*>(mcontext->__mc_gr[14]);
#elif V8_OS_IOS

#if V8_TARGET_ARCH_ARM64
  // Building for the iOS device.
  state->pc = reinterpret_cast<void*>(mcontext->__ss.__pc);
  state->sp = reinterpret_cast<void*>(mcontext->__ss.__sp);
  state->fp = reinterpret_cast<void*>(mcontext->__ss.__fp);
#elif V8_TARGET_ARCH_X64
  // Building for the iOS simulator.
  state->pc = reinterpret_cast<void*>(mcontext->__ss.__rip);
  state->sp = reinterpret_cast<void*>(mcontext->__ss.__rsp);
  state->fp = reinterpret_cast<void*>(mcontext->__ss.__rbp);
#else
#error Unexpected iOS target architecture.
#endif  // V8_TARGET_ARCH_ARM64

#elif V8_OS_DARWIN
#if V8_HOST_ARCH_X64
  state->pc = reinterpret_cast<void*>(mcontext->__ss.__rip);
  state->sp = reinterpret_cast<void*>(mcontext->__ss.__rsp);
  state->fp = reinterpret_cast<void*>(mcontext->__ss.__rbp);
#elif V8_HOST_ARCH_IA32
  state->pc = reinterpret_cast<void*>(mcontext->__ss.__eip);
  state->sp = reinterpret_cast<void*>(mcontext->__ss.__esp);
  state->fp = reinterpret_cast<void*>(mcontext->__ss.__ebp);
#elif V8_HOST_ARCH_ARM64
  state->pc =
      reinterpret_cast<void*>(arm_thread_state64_get_pc(mcontext->__ss));
  state->sp =
      reinterpret_cast<void*>(arm_thread_state64_get_sp(mcontext->__ss));
  state->fp =
      reinterpret_cast<void*>(arm_thread_state64_get_fp(mcontext->__ss));
#endif  // V8_HOST_ARCH_*
#elif V8_OS_FREEBSD
#if V8_HOST_ARCH_IA32
  state->pc = reinterpret_cast<void*>(mcontext.mc_eip);
  state->sp = reinterpret_cast<void*>(mcontext.mc_esp);
  state->fp = reinterpret_cast<void*>(mcontext.mc_ebp);
#elif V8_HOST_ARCH_X64
  state->pc = reinterpret_cast<void*>(mcontext.mc_rip);
  state->sp = reinterpret_cast<void*>(mcontext.mc_rsp);
  state->fp = reinterpret_cast<void*>(mcontext.mc_rbp);
#elif V8_HOST_ARCH_ARM
  state->pc = reinterpret_cast<void*>(mcontext.__gregs[_REG_PC]);
  state->sp = reinterpret_cast<void*>(mcontext.__gregs[_REG_SP]);
  state->fp = reinterpret_cast<void*>(mcontext.__gregs[_REG_FP]);
#endif  // V8_HOST_ARCH_*
#elif V8_OS_NETBSD
#if V8_HOST_ARCH_IA32
  state->pc = reinterpret_cast<void*>(mcontext.__gregs[_REG_EIP]);
  state->sp = reinterpret_cast<void*>(mcontext.__gregs[_REG_ESP]);
  state->fp = reinterpret_cast<void*>(mcontext.__gregs[_REG_EBP]);
#elif V8_HOST_ARCH_X64
  state->pc = reinterpret_cast<void*>(mcontext.__gregs[_REG_RIP]);
  state->sp = reinterpret_cast<void*>(mcontext.__gregs[_REG_RSP]);
  state->fp = reinterpret_cast<void*>(mcontext.__gregs[_REG_RBP]);
#endif  // V8_HOST_ARCH_*
#elif V8_OS_OPENBSD
#if V8_HOST_ARCH_IA32
  state->pc = reinterpret_cast<void*>(ucontext->sc_eip);
  state->sp = reinterpret_cast<void*>(ucontext->sc_esp);
  state->fp = reinterpret_cast<void*>(ucontext->sc_ebp);
#elif V8_HOST_ARCH_X64
  state->pc = reinterpret_cast<void*>(ucontext->sc_rip);
  state->sp = reinterpret_cast<void*>(ucontext->sc_rsp);
  state->fp = reinterpret_cast<void*>(ucontext->sc_rbp);
#endif  // V8_HOST_ARCH_*
#elif V8_OS_SOLARIS
  state->pc = reinterpret_cast<void*>(mcontext.gregs[REG_PC]);
  state->sp = reinterpret_cast<void*>(mcontext.gregs[REG_SP]);
  state->fp = reinterpret_cast<void*>(mcontext.gregs[REG_FP]);
#elif V8_OS_QNX
#if V8_HOST_ARCH_IA32
  state->pc = reinterpret_cast<void*>(mcontext.cpu.eip);
  state->sp = reinterpret_cast<void*>(mcontext.cpu.esp);
  state->fp = reinterpret_cast<void*>(mcontext.cpu.ebp);
#elif V8_HOST_ARCH_ARM
  state->pc = reinterpret_cast<void*>(mcontext.cpu.gpr[ARM_REG_PC]);
  state->sp = reinterpret_cast<void*>(mcontext.cpu.gpr[ARM_REG_SP]);
  state->fp = reinterpret_cast<void*>(mcontext.cpu.gpr[ARM_REG_FP]);
#endif  // V8_HOST_ARCH_*
#elif V8_OS_AIX
  state->pc = reinterpret_cast<void*>(mcontext.jmp_context.iar);
  state->sp = reinterpret_cast<void*>(mcontext.jmp_context.gpr[1]);
  state->fp = reinterpret_cast<void*>(mcontext.jmp_context.gpr[31]);
  state->lr = reinterpret_cast<void*>(mcontext.jmp_context.lr);
#endif  // V8_OS_AIX
}

#endif  // USE_SIGNALS

Sampler::Sampler(Isolate* isolate)
    : isolate_(isolate), data_(std::make_unique<PlatformData>()) {}

Sampler::~Sampler() { DCHECK(!IsActive()); }

void Sampler::Start() {
  DCHECK(!IsActive());
  SetActive(true);
#if defined(USE_SIGNALS)
  SignalHandler::IncreaseSamplerCount();
  SamplerManager::instance()->AddSampler(this);
#endif
}

void Sampler::Stop() {
#if defined(USE_SIGNALS)
  SamplerManager::instance()->RemoveSampler(this);
  SignalHandler::DecreaseSamplerCount();
#endif
  DCHECK(IsActive());
  SetActive(false);
}

#if defined(USE_SIGNALS)

void Sampler::DoSample() {
  base::RecursiveMutexGuard lock_guard(SignalHandler::mutex());
  if (!SignalHandler::Installed()) return;
  SetShouldRecordSample();
  pthread_kill(platform_data()->vm_tself(), SIGPROF);
}

#elif V8_OS_WIN || V8_OS_CYGWIN

void Sampler::DoSample() {
  HANDLE profiled_thread = platform_data()->profiled_thread();
  if (profiled_thread == nullptr) return;

  const DWORD kSuspendFailed = static_cast<DWORD>(-1);
  if (SuspendThread(profiled_thread) == kSuspendFailed) return;

  // Context used for sampling the register state of the profiled thread.
  CONTEXT context;
  memset(&context, 0, sizeof(context));
  context.ContextFlags = CONTEXT_FULL;
  if (GetThreadContext(profiled_thread, &context) != 0) {
    v8::RegisterState state;
#if V8_HOST_ARCH_X64
    state.pc = reinterpret_cast<void*>(context.Rip);
    state.sp = reinterpret_cast<void*>(context.Rsp);
    state.fp = reinterpret_cast<void*>(context.Rbp);
#elif V8_HOST_ARCH_ARM64
    state.pc = reinterpret_cast<void*>(context.Pc);
    state.sp = reinterpret_cast<void*>(context.Sp);
    state.fp = reinterpret_cast<void*>(context.Fp);
#else
    state.pc = reinterpret_cast<void*>(context.Eip);
    state.sp = reinterpret_cast<void*>(context.Esp);
    state.fp = reinterpret_cast<void*>(context.Ebp);
#endif
    SampleStack(state);
  }
  ResumeThread(profiled_thread);
}

#elif V8_OS_FUCHSIA

void Sampler::DoSample() {
  zx_handle_t profiled_thread = platform_data()->profiled_thread();
  if (profiled_thread == ZX_HANDLE_INVALID) return;

  zx_handle_t suspend_token = ZX_HANDLE_INVALID;
  if (zx_task_suspend_token(profiled_thread, &suspend_token) != ZX_OK) return;

  // Wait for the target thread to become suspended, or to exit.
  // TODO(wez): There is currently no suspension count for threads, so there
  // is a risk that some other caller resumes the thread in-between our suspend
  // and wait calls, causing us to miss the SUSPENDED signal. We apply a 100ms
  // deadline to protect against hanging the sampler thread in this case.
  zx_signals_t signals = 0;
  zx_status_t suspended = zx_object_wait_one(
      profiled_thread, ZX_THREAD_SUSPENDED | ZX_THREAD_TERMINATED,
      zx_deadline_after(ZX_MSEC(100)), &signals);
  if (suspended != ZX_OK || (signals & ZX_THREAD_SUSPENDED) == 0) {
    zx_handle_close(suspend_token);
    return;
  }

  // Fetch a copy of its "general register" states.
  zx_thread_state_general_regs_t thread_state = {};
  if (zx_thread_read_state(profiled_thread, ZX_THREAD_STATE_GENERAL_REGS,
                           &thread_state, sizeof(thread_state)) == ZX_OK) {
    v8::RegisterState state;
#if V8_HOST_ARCH_X64
    state.pc = reinterpret_cast<void*>(thread_state.rip);
    state.sp = reinterpret_cast<void*>(thread_state.rsp);
    state.fp = reinterpret_cast<void*>(thread_state.rbp);
#elif V8_HOST_ARCH_ARM64
    state.pc = reinterpret_cast<void*>(thread_state.pc);
    state.sp = reinterpret_cast<void*>(thread_state.sp);
    state.fp = reinterpret_cast<void*>(thread_state.r[29]);
#endif
    SampleStack(state);
  }

  zx_handle_close(suspend_token);
}

// TODO(wez): Remove this once the Fuchsia SDK has rolled.
#if defined(ZX_THREAD_STATE_REGSET0)
#undef ZX_THREAD_STATE_GENERAL_REGS
#endif

#endif  // USE_SIGNALS

}  // namespace sampler
}  // namespace v8
```