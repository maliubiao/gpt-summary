Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is the `malloc_debug.cpp` file from Android's Bionic library. I need to extract the core purpose of this file.

Based on the includes and the function names (like `debug_malloc`, `debug_free`, `debug_dump_heap`), it seems this file implements a debugging layer around the standard memory allocation functions. This layer likely adds features to detect memory errors.

Therefore, the core functionality is providing a debuggable version of the standard memory allocation functions.
这是 `bionic/libc/malloc_debug/malloc_debug.cpp` 文件的第一部分，主要功能是实现一个用于调试内存分配的层。它包装了标准的内存分配函数（如 `malloc`, `free`, `realloc` 等），并在这些操作前后添加了额外的检查和记录，以帮助开发者发现内存相关的错误。

以下是该部分代码的主要功能归纳：

1. **内存分配和释放的包装：**  该代码定义了一系列以 `debug_` 开头的函数，如 `debug_malloc`, `debug_free`, `debug_realloc`, `debug_calloc`, `debug_memalign` 等。这些函数作为标准 C 内存分配函数的包装器。

2. **调试信息的存储和管理：**  引入了全局变量 `g_debug`，它是一个指向 `DebugData` 对象的指针。`DebugData` 类（在其他文件中定义）很可能用于存储和管理内存分配的调试信息，例如分配的大小、分配时的调用栈、已释放的内存信息等。

3. **配置管理：** 通过 `Config.h` 和 `DebugData.h` 引入了配置机制，允许用户通过选项（通过 `debug_initialize` 传入）来控制调试行为，例如是否记录分配、是否检查越界访问、是否在错误时中止等。

4. **调用栈记录：**  使用 `unwindstack` 库和 `backtrace` 函数来获取内存分配和释放时的调用栈信息。这对于追踪内存泄漏和错误发生的地点至关重要。

5. **错误检测和报告：**  实现了诸如检查指针是否已被释放 (`VerifyPointer`)、检测堆溢出（通过 guard 机制，如 `FRONT_GUARD` 和 `REAR_GUARD` 选项）等功能。当检测到错误时，会打印错误日志，并可以选择中止程序。

6. **并发控制：** 使用读写锁 (`ScopedConcurrentLock`) 来保护内部数据结构，以支持多线程环境下的安全访问。

7. **信号处理：**  实现了 `ScopedBacktraceSignalBlocker` 类，用于在执行某些调试操作时屏蔽特定的信号，以防止死锁。

8. **`atfork` 处理：**  使用 `pthread_atfork` 来注册在 `fork` 系统调用前后需要执行的回调函数，以确保在多进程环境下内存调试的正确性。

9. **内存泄漏检测：**  通过 `LEAK_TRACK` 选项，可以追踪未释放的内存，并在程序退出时报告内存泄漏。

10. **已释放内存追踪：** 通过 `FREE_TRACK` 选项，可以记录已释放的内存信息，用于检测 use-after-free 错误。

11. **性能测量：**  使用 `ScopedTimer` 来测量内存分配和释放操作的耗时（通过 `RECORD_ALLOCS` 选项启用）。

**与 Android 功能的关系和举例：**

* **Zygote 进程支持：** `g_zygote_child` 变量表明该代码考虑了 Android 的 Zygote 进程模型。Zygote 是 Android 中用于快速启动新应用程序的进程，内存调试的行为在 Zygote 子进程和普通应用进程中可能有所不同。
* **属性系统集成：**  使用了 `android-base/properties.h`，说明可以通过 Android 的属性系统来配置内存调试的行为。例如，可以通过设置某个属性来启用或禁用特定的调试选项。
* **NDK 开发支持：** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的一部分。`malloc_debug` 提供的功能可以帮助 NDK 开发者调试 native 代码中的内存问题。例如，当 native 代码发生内存泄漏时，`malloc_debug` 可以记录分配时的调用栈，帮助开发者定位泄漏的根源。
* **Framework 调试：** Android Framework 的某些部分也是用 C/C++ 编写的，`malloc_debug` 可以用于调试 Framework 层的内存问题。

**libc 函数的实现：**

该代码本身并没有直接实现底层的 libc 函数，而是作为一层包装，调用了真正的内存分配器（通过 `g_dispatch` 指向的 `MallocDispatch` 结构体）。`MallocDispatch` 定义了一组函数指针，指向底层的内存分配实现。  `malloc_debug` 通过在调用底层分配器前后插入调试逻辑来实现其功能。

**Dynamic Linker 功能：**

该代码本身没有直接涉及 Dynamic Linker 的核心功能。但是，内存分配器是 Dynamic Linker 自身运行和加载共享库时所依赖的基础设施。  当启用内存调试时，Dynamic Linker 的内存分配也会受到 `malloc_debug` 的监控。

**SO 布局样本和链接处理过程：**

由于该代码片段主要是内存调试的实现，没有直接涉及 SO 布局和链接过程。

**逻辑推理、假设输入与输出：**

例如，假设开启了 `BACKTRACE` 选项，并且代码中调用了 `debug_malloc(100)`。

* **假设输入：** 调用 `debug_malloc(100)`。
* **逻辑推理：**
    1. `debug_malloc` 会调用 `InternalMalloc`。
    2. `InternalMalloc` 会调用底层的 `g_dispatch->memalign` 或 `g_dispatch->malloc` 分配实际的内存。
    3. 如果配置了 `BACKTRACE`，`InternalMalloc` 可能会在分配前后记录调用栈。
    4. 如果配置了 header，则会初始化 header 信息。
    5. 如果配置了 `TRACK_POINTERS`，则会将分配的指针信息添加到 `PointerData` 中。
* **假设输出：**  返回一个指向分配的 100 字节内存的指针。如果配置了日志，可能会在 logcat 中看到分配时的调用栈信息。

**用户或编程常见的使用错误：**

* **忘记 `free` 分配的内存：**  `malloc_debug` 可以通过 `LEAK_TRACK` 选项检测到这种情况，并在程序退出时报告泄漏的内存地址和分配时的调用栈。
* **重复 `free` 同一块内存：**  `malloc_debug` 可以通过 `FREE_TRACK` 选项检测到这种情况，并在第二次 `free` 时报告错误，并提供两次 `free` 的调用栈信息。
* **访问已释放的内存 (use-after-free)：**  `malloc_debug` 可以通过 `FREE_TRACK` 选项和 header 中的 tag 信息检测到这种情况，并在访问时报告错误和调用栈。
* **堆溢出 (heap overflow)：**  通过 `FRONT_GUARD` 和 `REAR_GUARD` 选项，`malloc_debug` 可以在分配的内存前后设置 guard 区域。如果程序写入这些 guard 区域，`malloc_debug` 会检测到并报告错误。

**Android Framework 或 NDK 如何到达这里，给出 Frida Hook 示例调试这些步骤：**

1. **Framework 调用：** Android Framework 的某些组件（如 SurfaceFlinger, MediaServer 等）使用 C/C++ 编写，它们会直接或间接地调用 `libc.so` 中的 `malloc`, `free` 等函数。如果启用了内存调试，这些调用会被 `malloc_debug.cpp` 中的包装函数拦截。

2. **NDK 调用：** NDK 开发的应用直接调用 `libc.so` 中的内存分配函数。当应用启动时，Dynamic Linker 会加载 `libc.so`，如果启用了内存调试，`malloc_debug.cpp` 中的包装函数会被使用。

**Frida Hook 示例：**

假设你想 hook `debug_malloc` 函数，查看其参数和返回值：

```javascript
if (Process.arch === "arm64" || Process.arch === "arm") {
    const debug_malloc = Module.findExportByName("libc.so", "debug_malloc");
    if (debug_malloc) {
        Interceptor.attach(debug_malloc, {
            onEnter: function (args) {
                console.log("debug_malloc called with size:", args[0].toInt());
            },
            onLeave: function (retval) {
                console.log("debug_malloc returned pointer:", retval);
            }
        });
    } else {
        console.log("debug_malloc not found");
    }
} else {
    console.log("Frida hook example is for ARM/ARM64");
}
```

这个 Frida 脚本会找到 `libc.so` 中的 `debug_malloc` 函数，并在其调用前后打印参数（分配大小）和返回值（分配的指针）。

要调试 Framework 的调用，你可能需要在 Framework 进程启动时注入 Frida。对于 NDK 应用，你可以在应用启动后注入。

总而言之，`bionic/libc/malloc_debug/malloc_debug.cpp` 的第一部分定义了内存调试框架的核心结构和入口点，通过包装标准的内存分配函数，并利用各种调试选项和辅助数据结构，为开发者提供了强大的内存错误检测和分析能力。

Prompt: 
```
这是目录为bionic/libc/malloc_debug/malloc_debug.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2012 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <mutex>
#include <vector>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <bionic/malloc_tagged_pointers.h>
#include <platform/bionic/reserved_signals.h>
#include <private/MallocXmlElem.h>
#include <private/bionic_malloc_dispatch.h>
#include <unwindstack/Unwinder.h>

#include "Config.h"
#include "DebugData.h"
#include "LogAllocatorStats.h"
#include "Nanotime.h"
#include "Unreachable.h"
#include "UnwindBacktrace.h"
#include "backtrace.h"
#include "debug_disable.h"
#include "debug_log.h"
#include "malloc_debug.h"

// ------------------------------------------------------------------------
// Global Data
// ------------------------------------------------------------------------
DebugData* g_debug;

bool* g_zygote_child;

const MallocDispatch* g_dispatch;

namespace {
// A TimedResult contains the result of from malloc end_ns al. functions and the
// start/end timestamps.
struct TimedResult {
  uint64_t start_ns = 0;
  uint64_t end_ns = 0;
  union {
    size_t s;
    int i;
    void* p;
  } v;

  uint64_t GetStartTimeNS() const { return start_ns; }
  uint64_t GetEndTimeNS() const { return end_ns; }
  void SetStartTimeNS(uint64_t t) { start_ns = t; }
  void SetEndTimeNS(uint64_t t) { end_ns = t; }

  template <typename T>
  void setValue(T);
  template <>
  void setValue(size_t s) {
    v.s = s;
  }
  template <>
  void setValue(int i) {
    v.i = i;
  }
  template <>
  void setValue(void* p) {
    v.p = p;
  }

  template <typename T>
  T getValue() const;
  template <>
  size_t getValue<size_t>() const {
    return v.s;
  }
  template <>
  int getValue<int>() const {
    return v.i;
  }
  template <>
  void* getValue<void*>() const {
    return v.p;
  }
};

class ScopedTimer {
 public:
  ScopedTimer(TimedResult& res) : res_(res) { res_.start_ns = Nanotime(); }

  ~ScopedTimer() { res_.end_ns = Nanotime(); }

 private:
  TimedResult& res_;
};

}  // namespace

template <typename MallocFn, typename... Args>
static TimedResult TimerCall(MallocFn fn, Args... args) {
  TimedResult ret;
  decltype((g_dispatch->*fn)(args...)) r;
  if (g_debug->config().options() & RECORD_ALLOCS) {
    ScopedTimer t(ret);
    r = (g_dispatch->*fn)(args...);
  } else {
    r = (g_dispatch->*fn)(args...);
  }
  ret.setValue<decltype(r)>(r);
  return ret;
}

template <typename MallocFn, typename... Args>
static TimedResult TimerCallVoid(MallocFn fn, Args... args) {
  TimedResult ret;
  {
    ScopedTimer t(ret);
    (g_dispatch->*fn)(args...);
  }
  return ret;
}

#define TCALL(FUNC, ...) TimerCall(&MallocDispatch::FUNC, __VA_ARGS__);
#define TCALLVOID(FUNC, ...) TimerCallVoid(&MallocDispatch::FUNC, __VA_ARGS__);

// ------------------------------------------------------------------------

// ------------------------------------------------------------------------
// Use C style prototypes for all exported functions. This makes it easy
// to do dlsym lookups during libc initialization when malloc debug
// is enabled.
// ------------------------------------------------------------------------
__BEGIN_DECLS

bool debug_initialize(const MallocDispatch* malloc_dispatch, bool* malloc_zygote_child,
                      const char* options);
void debug_finalize();
void debug_dump_heap(const char* file_name);
void debug_get_malloc_leak_info(uint8_t** info, size_t* overall_size, size_t* info_size,
                                size_t* total_memory, size_t* backtrace_size);
bool debug_write_malloc_leak_info(FILE* fp);
ssize_t debug_malloc_backtrace(void* pointer, uintptr_t* frames, size_t frame_count);
void debug_free_malloc_leak_info(uint8_t* info);
size_t debug_malloc_usable_size(void* pointer);
void* debug_malloc(size_t size);
void debug_free(void* pointer);
void* debug_aligned_alloc(size_t alignment, size_t size);
void* debug_memalign(size_t alignment, size_t bytes);
void* debug_realloc(void* pointer, size_t bytes);
void* debug_calloc(size_t nmemb, size_t bytes);
struct mallinfo debug_mallinfo();
int debug_mallopt(int param, int value);
int debug_malloc_info(int options, FILE* fp);
int debug_posix_memalign(void** memptr, size_t alignment, size_t size);
int debug_malloc_iterate(uintptr_t base, size_t size,
                         void (*callback)(uintptr_t base, size_t size, void* arg), void* arg);
void debug_malloc_disable();
void debug_malloc_enable();

#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
void* debug_pvalloc(size_t bytes);
void* debug_valloc(size_t size);
#endif

__END_DECLS
// ------------------------------------------------------------------------

class ScopedConcurrentLock {
 public:
  ScopedConcurrentLock() {
    pthread_rwlock_rdlock(&lock_);
  }
  ~ScopedConcurrentLock() {
    pthread_rwlock_unlock(&lock_);
  }

  static void Init() {
    pthread_rwlockattr_t attr;
    // Set the attribute so that when a write lock is pending, read locks are no
    // longer granted.
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    pthread_rwlock_init(&lock_, &attr);
  }

  static void BlockAllOperations() {
    pthread_rwlock_wrlock(&lock_);
  }

 private:
  static pthread_rwlock_t lock_;
};
pthread_rwlock_t ScopedConcurrentLock::lock_;

// Use this because the sigprocmask* functions filter out the reserved bionic
// signals including the signal this code blocks.
static inline int __rt_sigprocmask(int how, const sigset64_t* new_set, sigset64_t* old_set,
                                   size_t sigset_size) {
  return syscall(SYS_rt_sigprocmask, how, new_set, old_set, sigset_size);
}

// Need to block the backtrace signal while in malloc debug routines
// otherwise there is a chance of a deadlock and timeout when unwinding.
// This can occur if a thread is paused while owning a malloc debug
// internal lock.
class ScopedBacktraceSignalBlocker {
 public:
  ScopedBacktraceSignalBlocker() {
    sigemptyset64(&backtrace_set_);
    sigaddset64(&backtrace_set_, BIONIC_SIGNAL_BACKTRACE);
    sigset64_t old_set;
    __rt_sigprocmask(SIG_BLOCK, &backtrace_set_, &old_set, sizeof(backtrace_set_));
    if (sigismember64(&old_set, BIONIC_SIGNAL_BACKTRACE)) {
      unblock_ = false;
    }
  }

  ~ScopedBacktraceSignalBlocker() {
    if (unblock_) {
      __rt_sigprocmask(SIG_UNBLOCK, &backtrace_set_, nullptr, sizeof(backtrace_set_));
    }
  }

 private:
  bool unblock_ = true;
  sigset64_t backtrace_set_;
};

static void InitAtfork() {
  static pthread_once_t atfork_init = PTHREAD_ONCE_INIT;
  pthread_once(&atfork_init, []() {
    pthread_atfork(
        []() {
          if (g_debug != nullptr) {
            g_debug->PrepareFork();
          }
        },
        []() {
          if (g_debug != nullptr) {
            g_debug->PostForkParent();
          }
        },
        []() {
          if (g_debug != nullptr) {
            g_debug->PostForkChild();
          }
        });
  });
}

void BacktraceAndLog() {
  if (g_debug->config().options() & BACKTRACE_FULL) {
    std::vector<uintptr_t> frames;
    std::vector<unwindstack::FrameData> frames_info;
    if (!Unwind(&frames, &frames_info, 256)) {
      error_log("  Backtrace failed to get any frames.");
    } else {
      UnwindLog(frames_info);
    }
  } else {
    std::vector<uintptr_t> frames(256);
    size_t num_frames = backtrace_get(frames.data(), frames.size());
    if (num_frames == 0) {
      error_log("  Backtrace failed to get any frames.");
    } else {
      backtrace_log(frames.data(), num_frames);
    }
  }
}

static void LogError(const void* pointer, const char* error_str) {
  error_log(LOG_DIVIDER);
  error_log("+++ ALLOCATION %p %s", pointer, error_str);

  // If we are tracking already freed pointers, check to see if this is
  // one so we can print extra information.
  if (g_debug->config().options() & FREE_TRACK) {
    PointerData::LogFreeBacktrace(pointer);
  }

  error_log("Backtrace at time of failure:");
  BacktraceAndLog();
  error_log(LOG_DIVIDER);
  if (g_debug->config().options() & ABORT_ON_ERROR) {
    abort();
  }
}

static bool VerifyPointer(const void* pointer, const char* function_name) {
  if (g_debug->HeaderEnabled()) {
    Header* header = g_debug->GetHeader(pointer);
    if (header->tag != DEBUG_TAG) {
      std::string error_str;
      if (header->tag == DEBUG_FREE_TAG) {
        error_str = std::string("USED AFTER FREE (") + function_name + ")";
      } else {
        error_str = android::base::StringPrintf("HAS INVALID TAG %" PRIx32 " (%s)", header->tag,
                                                function_name);
      }
      LogError(pointer, error_str.c_str());
      return false;
    }
  }

  if (g_debug->TrackPointers()) {
    if (!PointerData::Exists(pointer)) {
      std::string error_str(std::string("UNKNOWN POINTER (") + function_name + ")");
      LogError(pointer, error_str.c_str());
      return false;
    }
  }
  return true;
}

static size_t InternalMallocUsableSize(void* pointer) {
  if (g_debug->HeaderEnabled()) {
    return g_debug->GetHeader(pointer)->usable_size;
  } else {
    return g_dispatch->malloc_usable_size(pointer);
  }
}

static void* InitHeader(Header* header, void* orig_pointer, size_t size) {
  header->tag = DEBUG_TAG;
  header->orig_pointer = orig_pointer;
  header->size = size;
  header->usable_size = g_dispatch->malloc_usable_size(orig_pointer);
  if (header->usable_size == 0) {
    g_dispatch->free(orig_pointer);
    return nullptr;
  }
  header->usable_size -= g_debug->pointer_offset() + reinterpret_cast<uintptr_t>(header) -
                         reinterpret_cast<uintptr_t>(orig_pointer);

  if (g_debug->config().options() & FRONT_GUARD) {
    uint8_t* guard = g_debug->GetFrontGuard(header);
    memset(guard, g_debug->config().front_guard_value(), g_debug->config().front_guard_bytes());
  }

  if (g_debug->config().options() & REAR_GUARD) {
    uint8_t* guard = g_debug->GetRearGuard(header);
    memset(guard, g_debug->config().rear_guard_value(), g_debug->config().rear_guard_bytes());
    // If the rear guard is enabled, set the usable size to the exact size
    // of the allocation.
    header->usable_size = header->size;
  }

  return g_debug->GetPointer(header);
}

extern "C" void __asan_init() __attribute__((weak));

bool debug_initialize(const MallocDispatch* malloc_dispatch, bool* zygote_child,
                      const char* options) {
  if (zygote_child == nullptr || options == nullptr) {
    return false;
  }

  if (__asan_init != 0) {
    error_log("malloc debug cannot be enabled alongside ASAN");
    return false;
  }

  InitAtfork();

  g_zygote_child = zygote_child;

  g_dispatch = malloc_dispatch;

  if (!DebugDisableInitialize()) {
    return false;
  }

  DebugData* debug = new DebugData();
  if (!debug->Initialize(options) || !Unreachable::Initialize(debug->config())) {
    delete debug;
    DebugDisableFinalize();
    return false;
  }
  g_debug = debug;

  // Always enable the backtrace code since we will use it in a number
  // of different error cases.
  backtrace_startup();

  if (g_debug->config().options() & VERBOSE) {
    info_log("%s: malloc debug enabled", getprogname());
  }

  ScopedConcurrentLock::Init();

  return true;
}

void debug_finalize() {
  if (g_debug == nullptr) {
    return;
  }

  // Make sure that there are no other threads doing debug allocations
  // before we kill everything.
  ScopedConcurrentLock::BlockAllOperations();

  // Turn off capturing allocations calls.
  DebugDisableSet(true);

  if (g_debug->config().options() & FREE_TRACK) {
    PointerData::VerifyAllFreed();
  }

  if (g_debug->config().options() & LEAK_TRACK) {
    PointerData::LogLeaks();
  }

  if ((g_debug->config().options() & RECORD_ALLOCS) && g_debug->config().record_allocs_on_exit()) {
    RecordData::WriteEntriesOnExit();
  }

  if ((g_debug->config().options() & BACKTRACE) && g_debug->config().backtrace_dump_on_exit()) {
    debug_dump_heap(android::base::StringPrintf("%s.%d.exit.txt",
                                                g_debug->config().backtrace_dump_prefix().c_str(),
                                                getpid()).c_str());
  }

  if (g_debug->config().options() & LOG_ALLOCATOR_STATS_ON_EXIT) {
    LogAllocatorStats::Log();
  }

  backtrace_shutdown();

  // In order to prevent any issues of threads freeing previous pointers
  // after the main thread calls this code, simply leak the g_debug pointer
  // and do not destroy the debug disable pthread key.
}

void debug_get_malloc_leak_info(uint8_t** info, size_t* overall_size, size_t* info_size,
                                size_t* total_memory, size_t* backtrace_size) {
  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  // Verify the arguments.
  if (info == nullptr || overall_size == nullptr || info_size == nullptr || total_memory == nullptr ||
      backtrace_size == nullptr) {
    error_log("get_malloc_leak_info: At least one invalid parameter.");
    return;
  }

  *info = nullptr;
  *overall_size = 0;
  *info_size = 0;
  *total_memory = 0;
  *backtrace_size = 0;

  if (!(g_debug->config().options() & BACKTRACE)) {
    error_log(
        "get_malloc_leak_info: Allocations not being tracked, to enable "
        "set the option 'backtrace'.");
    return;
  }

  PointerData::GetInfo(info, overall_size, info_size, total_memory, backtrace_size);
}

void debug_free_malloc_leak_info(uint8_t* info) {
  g_dispatch->free(info);
  // Purge the memory that was freed since a significant amount of
  // memory could have been allocated and freed.
  g_dispatch->mallopt(M_PURGE_ALL, 0);
}

size_t debug_malloc_usable_size(void* pointer) {
  Unreachable::CheckIfRequested(g_debug->config());

  if (DebugCallsDisabled() || pointer == nullptr) {
    return g_dispatch->malloc_usable_size(pointer);
  }
  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  if (!VerifyPointer(pointer, "malloc_usable_size")) {
    return 0;
  }

  return InternalMallocUsableSize(pointer);
}

static TimedResult InternalMalloc(size_t size) {
  uint64_t options = g_debug->config().options();
  if ((options & BACKTRACE) && g_debug->pointer->ShouldDumpAndReset()) {
    debug_dump_heap(android::base::StringPrintf(
                        "%s.%d.txt", g_debug->config().backtrace_dump_prefix().c_str(), getpid())
                        .c_str());
  }
  if (options & LOG_ALLOCATOR_STATS_ON_SIGNAL) {
    LogAllocatorStats::CheckIfShouldLog();
  }

  if (size == 0) {
    size = 1;
  }

  TimedResult result;

  size_t real_size = size + g_debug->extra_bytes();
  if (real_size < size) {
    // Overflow.
    errno = ENOMEM;
    result.setValue<void*>(nullptr);
    return result;
  }

  if (size > PointerInfoType::MaxSize()) {
    errno = ENOMEM;
    result.setValue<void*>(nullptr);
    return result;
  }

  if (g_debug->HeaderEnabled()) {
    result = TCALL(memalign, MINIMUM_ALIGNMENT_BYTES, real_size);
    Header* header = reinterpret_cast<Header*>(result.getValue<void*>());
    if (header == nullptr) {
      return result;
    }
    result.setValue<void*>(InitHeader(header, header, size));
  } else {
    result = TCALL(malloc, real_size);
  }

  void* pointer = result.getValue<void*>();

  if (pointer != nullptr) {
    if (g_debug->TrackPointers()) {
      PointerData::Add(pointer, size);
    }

    if (g_debug->config().options() & FILL_ON_ALLOC) {
      size_t bytes = InternalMallocUsableSize(pointer);
      size_t fill_bytes = g_debug->config().fill_on_alloc_bytes();
      bytes = (bytes < fill_bytes) ? bytes : fill_bytes;
      memset(pointer, g_debug->config().fill_alloc_value(), bytes);
    }
  }

  return result;
}

void* debug_malloc(size_t size) {
  Unreachable::CheckIfRequested(g_debug->config());

  if (DebugCallsDisabled()) {
    return g_dispatch->malloc(size);
  }
  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  memory_trace::Entry* entry = nullptr;
  if (g_debug->config().options() & RECORD_ALLOCS) {
    // In order to preserve the order of operations, reserve the entry before
    // performing the operation.
    entry = g_debug->record->ReserveEntry();
  }

  TimedResult result = InternalMalloc(size);

  if (entry != nullptr) {
    *entry = memory_trace::Entry{.tid = gettid(),
                                 .type = memory_trace::MALLOC,
                                 .ptr = reinterpret_cast<uint64_t>(result.getValue<void*>()),
                                 .size = size,
                                 .start_ns = result.GetStartTimeNS(),
                                 .end_ns = result.GetEndTimeNS()};
  }

  return result.getValue<void*>();
}

static TimedResult InternalFree(void* pointer) {
  uint64_t options = g_debug->config().options();
  if ((options & BACKTRACE) && g_debug->pointer->ShouldDumpAndReset()) {
    debug_dump_heap(android::base::StringPrintf(
                        "%s.%d.txt", g_debug->config().backtrace_dump_prefix().c_str(), getpid())
                        .c_str());
  }
  if (options & LOG_ALLOCATOR_STATS_ON_SIGNAL) {
    LogAllocatorStats::CheckIfShouldLog();
  }

  void* free_pointer = pointer;
  size_t bytes;
  Header* header;
  if (g_debug->HeaderEnabled()) {
    header = g_debug->GetHeader(pointer);
    free_pointer = header->orig_pointer;

    if (g_debug->config().options() & FRONT_GUARD) {
      if (!g_debug->front_guard->Valid(header)) {
        g_debug->front_guard->LogFailure(header);
      }
    }
    if (g_debug->config().options() & REAR_GUARD) {
      if (!g_debug->rear_guard->Valid(header)) {
        g_debug->rear_guard->LogFailure(header);
      }
    }

    header->tag = DEBUG_FREE_TAG;

    bytes = header->usable_size;
  } else {
    bytes = g_dispatch->malloc_usable_size(pointer);
  }

  if (g_debug->config().options() & FILL_ON_FREE) {
    size_t fill_bytes = g_debug->config().fill_on_free_bytes();
    fill_bytes = (bytes < fill_bytes) ? bytes : fill_bytes;
    memset(pointer, g_debug->config().fill_free_value(), fill_bytes);
  }

  if (g_debug->TrackPointers()) {
    PointerData::Remove(pointer);
  }

  TimedResult result;
  if (g_debug->config().options() & FREE_TRACK) {
    // Do not add the allocation until we are done modifying the pointer
    // itself. This avoids a race if a lot of threads are all doing
    // frees at the same time and we wind up trying to really free this
    // pointer from another thread, while still trying to free it in
    // this function.
    pointer = PointerData::AddFreed(pointer, bytes);
    if (pointer != nullptr && g_debug->HeaderEnabled()) {
      pointer = g_debug->GetHeader(pointer)->orig_pointer;
    }
    result = TCALLVOID(free, pointer);
  } else {
    result = TCALLVOID(free, free_pointer);
  }

  return result;
}

void debug_free(void* pointer) {
  Unreachable::CheckIfRequested(g_debug->config());

  if (DebugCallsDisabled() || pointer == nullptr) {
    return g_dispatch->free(pointer);
  }
  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  if (!VerifyPointer(pointer, "free")) {
    return;
  }

  memory_trace::Entry* entry = nullptr;
  if (g_debug->config().options() & RECORD_ALLOCS) {
    // In order to preserve the order of operations, reserve the entry before
    // performing the operation.
    entry = g_debug->record->ReserveEntry();
  }

  TimedResult result = InternalFree(pointer);

  if (entry != nullptr) {
    *entry = memory_trace::Entry{.tid = gettid(),
                                 .type = memory_trace::FREE,
                                 .ptr = reinterpret_cast<uint64_t>(pointer),
                                 .start_ns = result.GetStartTimeNS(),
                                 .end_ns = result.GetEndTimeNS()};
  }
}

void* debug_memalign(size_t alignment, size_t bytes) {
  Unreachable::CheckIfRequested(g_debug->config());

  if (DebugCallsDisabled()) {
    return g_dispatch->memalign(alignment, bytes);
  }
  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  if (bytes == 0) {
    bytes = 1;
  }

  if (bytes > PointerInfoType::MaxSize()) {
    errno = ENOMEM;
    return nullptr;
  }

  memory_trace::Entry* entry = nullptr;
  if (g_debug->config().options() & RECORD_ALLOCS) {
    // In order to preserve the order of operations, reserve the entry before
    // performing the operation.
    entry = g_debug->record->ReserveEntry();
  }

  TimedResult result;
  void* pointer;
  if (g_debug->HeaderEnabled()) {
    // Make the alignment a power of two.
    if (!powerof2(alignment)) {
      alignment = BIONIC_ROUND_UP_POWER_OF_2(alignment);
    }
    // Force the alignment to at least MINIMUM_ALIGNMENT_BYTES to guarantee
    // that the header is aligned properly.
    if (alignment < MINIMUM_ALIGNMENT_BYTES) {
      alignment = MINIMUM_ALIGNMENT_BYTES;
    }

    // We don't have any idea what the natural alignment of
    // the underlying native allocator is, so we always need to
    // over allocate.
    size_t real_size = alignment + bytes + g_debug->extra_bytes();
    if (real_size < bytes) {
      // Overflow.
      errno = ENOMEM;
      return nullptr;
    }

    result = TCALL(malloc, real_size);
    pointer = result.getValue<void*>();
    if (pointer == nullptr) {
      return nullptr;
    }

    uintptr_t value = reinterpret_cast<uintptr_t>(pointer) + g_debug->pointer_offset();
    // Now align the pointer.
    value += (-value % alignment);

    Header* header = g_debug->GetHeader(reinterpret_cast<void*>(value));
    // Don't need to update `result` here because we only need the timestamps.
    pointer = InitHeader(header, pointer, bytes);
  } else {
    size_t real_size = bytes + g_debug->extra_bytes();
    if (real_size < bytes) {
      // Overflow.
      errno = ENOMEM;
      return nullptr;
    }
    result = TCALL(memalign, alignment, real_size);
    pointer = result.getValue<void*>();
  }

  if (pointer == nullptr) {
    return nullptr;
  }

  if (g_debug->TrackPointers()) {
    PointerData::Add(pointer, bytes);
  }

  if (g_debug->config().options() & FILL_ON_ALLOC) {
    size_t bytes = InternalMallocUsableSize(pointer);
    size_t fill_bytes = g_debug->config().fill_on_alloc_bytes();
    bytes = (bytes < fill_bytes) ? bytes : fill_bytes;
    memset(pointer, g_debug->config().fill_alloc_value(), bytes);
  }

  if (entry != nullptr) {
    *entry = memory_trace::Entry{.tid = gettid(),
                                 .type = memory_trace::MEMALIGN,
                                 .ptr = reinterpret_cast<uint64_t>(pointer),
                                 .size = bytes,
                                 .u.align = alignment,
                                 .start_ns = result.GetStartTimeNS(),
                                 .end_ns = result.GetEndTimeNS()};
  }

  return pointer;
}

void* debug_realloc(void* pointer, size_t bytes) {
  Unreachable::CheckIfRequested(g_debug->config());

  if (DebugCallsDisabled()) {
    return g_dispatch->realloc(pointer, bytes);
  }
  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  memory_trace::Entry* entry = nullptr;
  if (g_debug->config().options() & RECORD_ALLOCS) {
    // In order to preserve the order of operations, reserve the entry before
    // performing the operation.
    entry = g_debug->record->ReserveEntry();
  }

  if (pointer == nullptr) {
    TimedResult result = InternalMalloc(bytes);
    pointer = result.getValue<void*>();
    if (entry != nullptr) {
      *entry = memory_trace::Entry{.tid = gettid(),
                                   .type = memory_trace::REALLOC,
                                   .ptr = reinterpret_cast<uint64_t>(pointer),
                                   .size = bytes,
                                   .u.old_ptr = 0,
                                   .start_ns = result.GetStartTimeNS(),
                                   .end_ns = result.GetEndTimeNS()};
    }
    return pointer;
  }

  if (!VerifyPointer(pointer, "realloc")) {
    return nullptr;
  }

  if (bytes == 0) {
    TimedResult result = InternalFree(pointer);

    if (entry != nullptr) {
      *entry = memory_trace::Entry{.tid = gettid(),
                                   .type = memory_trace::REALLOC,
                                   .ptr = 0,
                                   .size = 0,
                                   .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
                                   .start_ns = result.GetStartTimeNS(),
                                   .end_ns = result.GetEndTimeNS()};
    }

    return nullptr;
  }

  size_t real_size = bytes;
  if (g_debug->config().options() & EXPAND_ALLOC) {
    real_size += g_debug->config().expand_alloc_bytes();
    if (real_size < bytes) {
      // Overflow.
      errno = ENOMEM;
      return nullptr;
    }
  }

  if (bytes > PointerInfoType::MaxSize()) {
    errno = ENOMEM;
    return nullptr;
  }

  TimedResult result;
  void* new_pointer;
  size_t prev_size;
  if (g_debug->HeaderEnabled()) {
    // Same size, do nothing.
    Header* header = g_debug->GetHeader(pointer);
    if (real_size == header->size) {
      if (g_debug->TrackPointers()) {
        // Remove and re-add so that the backtrace is updated.
        PointerData::Remove(pointer);
        PointerData::Add(pointer, real_size);
      }
      return pointer;
    }

    // Allocation is shrinking.
    if (real_size < header->usable_size) {
      header->size = real_size;
      if (g_debug->config().options() & REAR_GUARD) {
        // Don't bother allocating a smaller pointer in this case, simply
        // change the header usable_size and reset the rear guard.
        header->usable_size = header->size;
        memset(g_debug->GetRearGuard(header), g_debug->config().rear_guard_value(),
               g_debug->config().rear_guard_bytes());
      }
      if (g_debug->TrackPointers()) {
        // Remove and re-add so that the backtrace is updated.
        PointerData::Remove(pointer);
        PointerData::Add(pointer, real_size);
      }
      return pointer;
    }

    // Allocate the new size.
    result = InternalMalloc(bytes);
    new_pointer = result.getValue<void*>();
    if (new_pointer == nullptr) {
      errno = ENOMEM;
      return nullptr;
    }

    prev_size = header->usable_size;
    memcpy(new_pointer, pointer, prev_size);
    TimedResult free_time = InternalFree(pointer);
    // `realloc` is split into two steps, update the end time to the finish time
    // of the second operation.
    result.SetEndTimeNS(free_time.GetEndTimeNS());
  } else {
    if (g_debug->TrackPointers()) {
      PointerData::Remove(pointer);
    }

    prev_size = g_dispatch->malloc_usable_size(pointer);
    result = TCALL(realloc, pointer, real_size);
    new_pointer = result.getValue<void*>();
    if (new_pointer == nullptr) {
      return nullptr;
    }

    if (g_debug->TrackPointers()) {
      PointerData::Add(new_pointer, real_size);
    }
  }

  if (g_debug->config().options() & FILL_ON_ALLOC) {
    size_t bytes = InternalMallocUsableSize(new_pointer);
    if (bytes > g_debug->config().fill_on_alloc_bytes()) {
      bytes = g_debug->config().fill_on_alloc_bytes();
    }
    if (bytes > prev_size) {
      memset(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(new_pointer) + prev_size),
             g_debug->config().fill_alloc_value(), bytes - prev_size);
    }
  }

  if (entry != nullptr) {
    *entry = memory_trace::Entry{.tid = gettid(),
                                 .type = memory_trace::REALLOC,
                                 .ptr = reinterpret_cast<uint64_t>(new_pointer),
                                 .size = bytes,
                                 .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
                                 .start_ns = result.GetStartTimeNS(),
                                 .end_ns = result.GetEndTimeNS()};
  }

  return new_pointer;
}

void* debug_calloc(size_t nmemb, size_t bytes) {
  Unreachable::CheckIfRequested(g_debug->config());

  if (DebugCallsDisabled()) {
    return g_dispatch->calloc(nmemb, bytes);
  }
  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  size_t size;
  if (__builtin_mul_overflow(nmemb, bytes, &size)) {
    // Overflow
    errno = ENOMEM;
    return nullptr;
  }

  if (size == 0) {
    size = 1;
  }

  size_t real_size;
  if (__builtin_add_overflow(size, g_debug->extra_bytes(), &real_size)) {
    // Overflow.
    errno = ENOMEM;
    return nullptr;
  }

  if (real_size > PointerInfoType::MaxSize()) {
    errno = ENOMEM;
    return nullptr;
  }

  memory_trace::Entry* entry = nullptr;
  if (g_debug->config().options() & RECORD_ALLOCS) {
    // In order to preserve the order of operations, reserve the entry before
    // performing the operation.
    entry = g_debug->record->ReserveEntry();
  }

  void* pointer;
  TimedResult result;
  if (g_debug->HeaderEnabled()) {
    // Need to guarantee the alignment of the header.
    result = TCALL(memalign, MINIMUM_ALIGNMENT_BYTES, real_size);
    Header* header = reinterpret_cast<Header*>(result.getValue<void*>());
    if (header == nullptr) {
      return nullptr;
    }
    memset(header, 0, g_dispatch->malloc_usable_size(header));
    pointer = InitHeader(header, header, size);
  } else {
    result = TCALL(calloc, 1, real_size);
    pointer = result.getValue<void*>();
  }

  if (entry != nullptr) {
    *entry = memory_trace::Entry{.tid = gettid(),
                                 .type = memory_trace::CALLOC,
                                 .ptr = reinterpret_cast<uint64_t>(pointer),
                                 .size = bytes,
                                 .u.n_elements = nmemb,
                                 .start_ns = result.GetStartTimeNS(),
                                 .end_ns = result.GetEndTimeNS()};
  }

  if (pointer != nullptr && g_debug->TrackPointers()) {
    PointerData::Add(pointer, size);
  }
  return pointer;
}

struct mallinfo debug_mallinfo() {
  return g_dispatch->mallinfo();
}

int debug_mallopt(int param, int value) {
  return g_dispatch->mallopt(param, value);
}

int debug_malloc_info(int options, FILE* fp) {
  if (DebugCallsDisabled() || !g_debug->TrackPointers()) {
    return g_dispatch->malloc_info(options, fp);
  }

  // Make sure any pending output is written to the file.
  fflush(fp);

  ScopedConcurrentLock lock;
  ScopedDisableDebugCalls disable;
  ScopedBacktraceSignalBlocker blocked;

  // Avoid any issues where allocations are made that will be freed
  // in the fclose.
  int fd = fileno(fp);
  MallocXmlElem root(fd, "malloc", "version=\"debug-malloc-1\"");
  std::vector<ListInfoType> list;
  PointerData::GetAllocList(&list);

  size_t alloc_num = 0;
  for (size_t i = 0; i < list.size(); i++) {
    MallocXmlElem alloc(fd, "allocation", "nr=\"%zu\"", alloc_num);

    size_t total = 1;
    size_t size = list[i].size;
    while (i < list.size() - 1 && list[i + 1].size == size) {
      i++;
      total++;
    }

"""


```