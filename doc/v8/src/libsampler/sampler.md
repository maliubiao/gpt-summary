Response: The user wants to understand the functionality of the C++ code in `v8/src/libsampler/sampler.cc`. I need to analyze the code and summarize its purpose. Since the user specifically asked about its relation to JavaScript, I should look for clues about how this code interacts with the V8 JavaScript engine. The filename and the inclusion of `include/v8-isolate.h` strongly suggest it's related to sampling execution within V8 isolates.

Here's a breakdown of how I'll approach this:

1. **Identify the core class:** The `Sampler` class appears to be central.
2. **Analyze the `Sampler` class:**  Look at its methods (Start, Stop, DoSample, SampleStack) and member variables. Pay attention to platform-specific implementations (using `#ifdef`).
3. **Examine the `SamplerManager` class:**  This seems to manage multiple `Sampler` instances.
4. **Investigate the platform-specific sections:**  Understand how sampling is implemented on different operating systems (using signals on POSIX-like systems, thread suspension on Windows, etc.).
5. **Focus on the interaction with V8:** Look for references to `v8::Isolate` and how the sampled data is used. The `SampleStack` method is likely key.
6. **Relate to JavaScript:**  Think about how this sampling mechanism could be used in the context of JavaScript execution within V8. Profiling and performance analysis are the most likely connections.
7. **Construct a JavaScript example:** Create a simple JavaScript code snippet that demonstrates the kind of scenario where this sampler might be active and collect data. Focus on code with potential performance implications or long execution times.
这个C++源代码文件 `v8/src/libsampler/sampler.cc` 的主要功能是 **实现了一个用于对V8 JavaScript引擎进行采样的机制**。  简单来说，它允许在V8执行JavaScript代码时，定期获取程序执行状态的快照，用于性能分析和调试。

以下是更详细的功能归纳：

**核心功能：**

* **线程采样:**  该文件定义了一个 `Sampler` 类，其核心功能是定期对指定线程的执行状态进行采样。采样内容通常包括程序计数器 (PC)、栈指针 (SP) 和帧指针 (FP) 等寄存器的值，这些信息可以用来重建函数调用栈。
* **平台适配:**  `Sampler` 类的实现包含了大量的平台特定代码（通过 `#ifdef` 区分），以适应不同的操作系统 (Windows, Linux, macOS, Fuchsia 等) 和架构。不同的平台使用不同的机制来获取线程的执行状态：
    * **基于信号 (USE_SIGNALS):** 在大多数类 Unix 系统上，它使用 `SIGPROF` 信号来中断目标线程并获取其上下文。
    * **线程挂起 (V8_OS_WIN/V8_OS_CYGWIN):** 在 Windows 上，它使用 `SuspendThread` 和 `GetThreadContext` API 来挂起线程并获取上下文。
    * **Fuchsia 特定 API (V8_OS_FUCHSIA):** 在 Fuchsia 操作系统上，使用 Fuchsia 提供的线程挂起和状态读取 API。
* **采样管理:**  `SamplerManager` 类负责管理多个 `Sampler` 实例。它可以添加和移除 `Sampler`，并在收到采样事件时通知相应的 `Sampler` 对象。
* **与V8 Isolate 关联:**  每个 `Sampler` 对象都与一个 `v8::Isolate` 关联。`Isolate` 是 V8 引擎中一个独立的执行上下文。这表明采样是针对特定的 JavaScript 执行环境进行的。
* **控制采样频率 (隐式):**  虽然代码本身没有直接控制采样频率的机制，但采样动作通常由外部驱动，例如定时器或者操作系统级别的性能分析工具。
* **提供寄存器状态:** `RegisterState` 结构体用于存储采样时获取的寄存器值。

**与 JavaScript 的关系及 JavaScript 示例：**

这个采样器直接服务于 V8 JavaScript 引擎，用于分析 JavaScript 代码的执行情况。  它可以帮助开发者识别性能瓶颈，例如哪些函数被调用得最频繁，哪些代码段占用了大量的执行时间。

**JavaScript 示例：**

假设我们有以下 JavaScript 代码：

```javascript
function slowFunction() {
  let sum = 0;
  for (let i = 0; i < 1000000; i++) {
    sum += i;
  }
  return sum;
}

function fastFunction() {
  return 1 + 1;
}

function main() {
  console.time("slow");
  slowFunction();
  console.timeEnd("slow");

  console.time("fast");
  fastFunction();
  console.timeEnd("fast");
}

main();
```

当 V8 引擎执行这段代码时，`sampler.cc` 中的采样器可能会在以下时刻捕获到程序状态：

1. **在 `slowFunction` 的循环内部:**  多次采样可能会指向 `slowFunction` 内部的循环代码，表明该函数执行时间较长。
2. **在 `fastFunction` 内部:**  采样可能会指向 `fastFunction`，但由于其执行速度很快，采样到的次数可能较少。
3. **在 `main` 函数内部:**  采样可能会指向 `console.time` 或 `console.timeEnd` 等内置函数。

通过对这些采样点进行统计分析，性能分析工具可以得出以下结论：

* `slowFunction` 是性能瓶颈，因为它被采样到的次数最多。
* `fastFunction` 执行速度很快，被采样到的次数很少。

**在 V8 内部，这个采样器可能被用于以下场景：**

* **Profiler 工具:** V8 的内置或外部的 Profiler 工具可以使用这个采样器来收集 JavaScript 代码的性能数据。
* **开发者工具:**  浏览器开发者工具中的性能分析面板通常会利用类似的采样机制来帮助开发者理解 JavaScript 代码的执行情况。
* **JIT 优化:**  V8 的 Just-In-Time (JIT) 编译器可能会利用采样数据来识别热点代码，并对其进行更积极的优化。

**总结:**

`v8/src/libsampler/sampler.cc` 是 V8 引擎中一个重要的组成部分，它提供了一种低开销的机制来采样 JavaScript 代码的执行状态。这些采样数据对于性能分析、调试和 JIT 优化至关重要，帮助开发者和 V8 引擎自身更好地理解和优化 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/src/libsampler/sampler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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