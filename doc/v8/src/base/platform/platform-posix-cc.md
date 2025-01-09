Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Scan and Keywords:**

My first step is to quickly scan the code for recognizable keywords and patterns. I see:

* `#include`:  Indicates inclusion of header files, suggesting dependencies and functionalities.
* `// Copyright`: Standard copyright notice, not directly functional but good to note.
* `Platform-specific code for POSIX`:  This is a crucial piece of information. It immediately tells me this code deals with operating system interactions for POSIX-compliant systems.
* `Linux, MacOS, FreeBSD, OpenBSD, NetBSD and QNX`:  Specific POSIX-like operating systems are listed, reinforcing the platform-specific nature.
* `src/base/platform/platform-posix.h`:  Inclusion of a related header file suggests a modular structure.
* `namespace v8::base`:  This confirms the code belongs to the V8 JavaScript engine project.
* `mmap`, `munmap`, `mprotect`, `pthread`, `sysconf`, `getpid`, `getrusage`, `time`, `fopen`, `fclose`, `remove`, `printf`, etc.: These are all standard POSIX system calls and library functions. Their presence strongly indicates the code interacts directly with the operating system.

**2. Identifying Core Functionality Areas:**

Based on the included headers and the system calls used, I can start grouping the code's functionality into logical areas:

* **Memory Management:** `mmap`, `munmap`, `mprotect`, `Allocate`, `Free`, `AllocateShared`, `FreeShared`, `SetPermissions`, `RecommitPages`, `DiscardSystemPages`, `DecommitPages`, `SealPages`, `AddressSpaceReservation`. These functions clearly deal with allocating, freeing, and managing memory at a low level.
* **Threading:** `pthread_self`, `pthread_set_name_np`, `kNoThread`. This indicates support for multi-threading.
* **Time:** `sys/time.h`, `time.h`, `TimeCurrentMillis`, `DaylightSavingsOffset`. Functions for getting the current time and dealing with timezones.
* **Process and Thread Information:** `getpid`, `gettid`, `GetCurrentProcessId`, `GetCurrentThreadId`. Functions to retrieve process and thread IDs.
* **File System Operations:** `fcntl.h`, `sys/stat.h`, `unistd.h`, `fopen`, `fclose`, `remove`, `MemoryMappedFile`. Functions for file manipulation and memory-mapped files.
* **Error Handling:** `errno`, `GetLastError`. Mechanisms for accessing and retrieving error codes.
* **Logging/Printing:** `stdio.h`, `printf`, `fprintf`, `PrintError`, Android logging (`android/log.h`).
* **Randomness:** `cstdlib`, `RandomNumberGenerator`, `GetRandomMmapAddr`, `SetRandomMmapSeed`.
* **System Configuration:** `sysctl.h`, `sysconf`. Getting system-level information.
* **Debugging/Aborting:** `Abort`, `DebugBreak`, `AbortMode`. Mechanisms for handling errors and debugging.
* **Shared Memory:** `AllocateShared`, `FreeShared`, `CreateSharedMemoryHandleForTesting`, `DestroySharedMemoryHandle`.

**3. Analyzing Specific Code Blocks:**

Now I look at specific code blocks and try to understand their purpose:

* **Conditional Compilation (`#if defined(...)`)**:  Lots of these!  This confirms the platform-specific nature of the code. Different code paths are taken depending on the operating system or architecture. I note which OS/architecture combinations are targeted.
* **`namespace { ... }`**:  This indicates anonymous namespaces, used for internal implementation details not meant to be exposed directly. The `Allocate` function within this namespace is interesting, as it uses `mmap` directly with specific flags.
* **`DEFINE_LAZY_LEAKY_OBJECT_GETTER` and `LazyMutex`**: These suggest a mechanism for lazy initialization of a singleton (the random number generator) and thread-safe access.
* **`GetProtectionFromMemoryPermission`**: This function translates V8's internal `MemoryPermission` enum to POSIX `PROT_*` flags for `mprotect`.
* **`GetFlagsForMemoryPermission`**:  This translates `MemoryPermission` and a `PageType` enum to POSIX `MAP_*` flags for `mmap`. The `MAP_JIT` flag is particularly noteworthy, related to just-in-time compilation.
* **`OS::Allocate` (outside the anonymous namespace):** This higher-level `Allocate` function uses the lower-level one in the anonymous namespace and adds alignment handling using `mmap` and `munmap`.
* **`OS::SetRandomMmapSeed` and `OS::GetRandomMmapAddr`**: These are clearly about implementing Address Space Layout Randomization (ASLR) for security. The code includes logic to avoid conflicts with sanitizer address ranges.

**4. Addressing Specific Prompts:**

* **Functionality Listing:**  Based on the identified core areas, I can create a structured list of functionalities.
* **`.tq` Extension:** The code does *not* end in `.tq`, so it's not Torque code.
* **JavaScript Relationship:** Since this code deals with low-level OS interactions *for* V8, it directly supports JavaScript's execution. I think of examples where JavaScript needs memory, time, file access, etc., and connect those to the underlying C++ functions.
* **Code Logic Inference:** I look for functions with clear input-output relationships. The `GetProtectionFromMemoryPermission` function is a good example for demonstrating this with a table.
* **Common Programming Errors:** I consider common mistakes related to memory management (leaks, dangling pointers), incorrect permissions, and file handling.
* **Summarization:** I synthesize the key findings into a concise summary, highlighting the core purpose and responsibilities of the file.

**5. Structuring the Output:**

Finally, I organize the information in a clear and structured manner, using headings, bullet points, code blocks (for examples), and tables (for logic inference) as appropriate. I make sure to address all the specific questions raised in the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like just basic OS wrappers."  **Correction:** While it provides wrappers, there's also logic for alignment, ASLR, JIT support, and platform-specific handling, making it more than just simple wrappers.
* **Overlooking details:**  Initially, I might just skim over the conditional compilation. **Correction:** I need to pay closer attention to *why* these conditions exist and what specific platform behaviors they address.
* **Insufficient JavaScript examples:**  My first examples might be too generic. **Correction:** I should try to provide more concrete examples that directly relate to V8's use cases.

By following this systematic process, I can effectively analyze the C++ code snippet and generate a comprehensive and accurate summary of its functionality.
```javascript
// 假设 JavaScript 需要分配一块内存用于存储数据
const buffer = new ArrayBuffer(1024); // 相当于 C++ 中的 malloc 或 mmap

// 假设 JavaScript 需要获取当前时间
const startTime = Date.now(); // 相当于 C++ 中的 gettimeofday 或 clock_gettime

// 假设 JavaScript 需要创建一个文件并写入数据
const fs = require('fs');
fs.writeFileSync('temp.txt', 'Hello from JavaScript!'); // 相当于 C++ 中的 fopen 和 fwrite

// 假设 JavaScript 需要获取进程 ID
const processId = process.pid; // 相当于 C++ 中的 getpid()

// 假设 JavaScript 需要设置定时器
setTimeout(() => {
  console.log('定时器触发');
}, 1000); // 相当于 C++ 中使用 sleep 或 usleep
```

## 功能归纳 (第 1 部分)

`v8/src/base/platform/platform-posix.cc` 文件是 V8 JavaScript 引擎中用于处理 **POSIX 兼容操作系统**（如 Linux、macOS、FreeBSD 等）底层平台相关功能的源代码。它提供了 V8 引擎与操作系统交互的抽象层，使得 V8 的核心代码可以不依赖于具体的操作系统实现。

**主要功能可以归纳为:**

1. **内存管理:**
   - 提供跨 POSIX 系统的内存分配 (`Allocate`) 和释放 (`Free`) 接口，包括对齐分配、共享内存分配等。
   - 管理内存权限 (`SetPermissions`)，例如设置内存页为只读、可执行等。
   - 支持内存页的重新提交 (`RecommitPages`)、丢弃 (`DiscardSystemPages`) 和反提交 (`DecommitPages`)，用于优化内存使用。
   - 支持地址空间预留 (`CreateAddressSpaceReservation`, `FreeAddressSpaceReservation`)。
   - 提供内存映射文件的操作 (`MemoryMappedFile::open`, `MemoryMappedFile::create`)。
   - 实现内存保护，例如通过 `mseal` 系统调用密封内存页。

2. **线程支持:**
   - 提供获取当前线程 ID 的接口 (`GetCurrentThreadId`)。

3. **时间和日期:**
   - 提供获取当前时间戳 (`TimeCurrentMillis`) 和用户 CPU 时间 (`GetUserTime`) 的接口。
   - 提供处理时区偏移的函数 (`DaylightSavingsOffset`)。

4. **进程和系统信息:**
   - 提供获取当前进程 ID 的接口 (`GetCurrentProcessId`)。
   - 提供获取峰值内存使用量 (`GetPeakMemoryUsageKb`) 的接口。
   - 提供获取系统页大小 (`AllocatePageSize`, `CommitPageSize`) 的接口。

5. **文件系统操作:**
   - 提供打开 (`FOpen`)、创建、删除文件 (`Remove`) 的接口。
   - 提供创建临时文件的接口 (`OpenTemporaryFile`)。
   - 定义日志文件的打开模式 (`LogFileOpenMode`)。
   - 提供获取目录分隔符 (`DirectorySeparator`) 的接口。

6. **输入/输出:**
   - 提供格式化打印到标准输出 (`Print`, `VPrint`)、文件 (`FPrint`, `VFPrint`) 和标准错误 (`PrintError`, `VPrintError`) 的接口。
   - 提供格式化字符串输出 (`SNPrintF`, `VSNPrintF`) 的接口。

7. **错误处理:**
   - 提供获取最后错误代码 (`GetLastError`) 的接口。

8. **随机数生成:**
   - 提供设置随机数生成器种子 (`SetRandomMmapSeed`) 和获取随机内存映射地址 (`GetRandomMmapAddr`) 的功能，用于地址空间布局随机化 (ASLR)。

9. **调试和异常处理:**
   - 提供程序中止 (`Abort`) 和断点 (`DebugBreak`) 的功能。

10. **睡眠:**
    - 提供线程睡眠功能 (`Sleep`).

**关于 .tq 结尾的文件:**

`v8/src/base/platform/platform-posix.cc` **没有**以 `.tq` 结尾，因此它不是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的类型化的中间语言，用于编写性能关键的代码。

**代码逻辑推理示例:**

**假设输入:** `OS::MemoryPermission::kReadWriteExecute`

**输出:** `GetProtectionFromMemoryPermission` 函数将返回 `PROT_READ | PROT_WRITE | PROT_EXEC`。

**推理:** `GetProtectionFromMemoryPermission` 函数根据传入的 V8 内存权限枚举值，返回对应的 POSIX 系统调用 `mprotect` 所需的权限宏定义。`kReadWriteExecute` 表示读、写和执行权限，对应 `PROT_READ`, `PROT_WRITE`, 和 `PROT_EXEC` 的按位或。

**用户常见的编程错误示例:**

一个常见的编程错误是在使用 `mmap` 或类似的内存分配函数后，**忘记调用 `munmap` 释放内存**，导致内存泄漏。

```c++
// C++ 代码示例 (可能导致内存泄漏)
void* my_memory = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
if (my_memory == MAP_FAILED) {
  // 处理错误
}

// ... 使用 my_memory ...

// 忘记调用 munmap(my_memory, 4096);
```

在 JavaScript 中，虽然有垃圾回收机制，但如果涉及到与操作系统直接交互的模块（例如使用 Node.js 的 `Buffer` 或 `fs` 模块处理大量数据），不当的操作仍然可能导致资源泄漏。例如，在处理完文件句柄后忘记关闭，或者创建了大量未被引用的 `Buffer` 对象。

总结来说，`v8/src/base/platform/platform-posix.cc` 是 V8 引擎在 POSIX 系统上的一个关键组成部分，它负责处理与操作系统底层的交互，为 V8 的高级功能提供基础支持。它不是 Torque 代码，并且其功能与 JavaScript 的底层执行环境密切相关。

Prompt: 
```
这是目录为v8/src/base/platform/platform-posix.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/platform/platform-posix.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Platform-specific code for POSIX goes here. This is not a platform on its
// own, but contains the parts which are the same across the POSIX platforms
// Linux, MacOS, FreeBSD, OpenBSD, NetBSD and QNX.

#include <errno.h>
#include <limits.h>
#include <pthread.h>

#include "src/base/logging.h"
#if defined(__DragonFly__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <pthread_np.h>  // for pthread_set_name_np
#endif
#include <fcntl.h>
#include <sched.h>  // for sched_yield
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) || \
    defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>  // for sysctl
#endif

#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
#define LOG_TAG "v8"
#include <android/log.h>
#endif

#include <cmath>
#include <cstdlib>
#include <optional>

#include "src/base/lazy-instance.h"
#include "src/base/macros.h"
#include "src/base/platform/platform-posix.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/base/utils/random-number-generator.h"

#ifdef V8_FAST_TLS_SUPPORTED
#include <atomic>
#endif

#if V8_OS_DARWIN || V8_OS_LINUX
#include <dlfcn.h>  // for dlsym
#endif

#if V8_OS_DARWIN
#include <mach/mach.h>
#include <malloc/malloc.h>
#elif V8_OS_OPENBSD
#include <sys/malloc.h>
#elif !V8_OS_ZOS
#include <malloc.h>
#endif

#if V8_OS_LINUX
#include <sys/prctl.h>  // for prctl
#endif

#if defined(V8_OS_FUCHSIA)
#include <zircon/process.h>
#else
#include <sys/resource.h>
#endif

#if !defined(_AIX) && !defined(V8_OS_FUCHSIA) && !V8_OS_ZOS
#include <sys/syscall.h>
#endif

#if V8_OS_FREEBSD || V8_OS_DARWIN || V8_OS_OPENBSD || V8_OS_SOLARIS
#define MAP_ANONYMOUS MAP_ANON
#endif

#if defined(V8_OS_SOLARIS)
#if (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE > 2) || defined(__EXTENSIONS__)
extern "C" int madvise(caddr_t, size_t, int);
#else
extern int madvise(caddr_t, size_t, int);
#endif
#endif

#ifndef MADV_FREE
#define MADV_FREE MADV_DONTNEED
#endif

#if defined(V8_LIBC_GLIBC)
extern "C" void* __libc_stack_end;
#endif

namespace v8 {
namespace base {

namespace {

// 0 is never a valid thread id.
#if V8_OS_ZOS
const pthread_t kNoThread = {0};  // pthread_t is a struct on z/OS
#else
const pthread_t kNoThread = static_cast<pthread_t>(0);
#endif

const char* g_gc_fake_mmap = nullptr;

DEFINE_LAZY_LEAKY_OBJECT_GETTER(RandomNumberGenerator,
                                GetPlatformRandomNumberGenerator)
static LazyMutex rng_mutex = LAZY_MUTEX_INITIALIZER;

#if !V8_OS_FUCHSIA && !V8_OS_ZOS
#if V8_OS_DARWIN
// kMmapFd is used to pass vm_alloc flags to tag the region with the user
// defined tag 255 This helps identify V8-allocated regions in memory analysis
// tools like vmmap(1).
const int kMmapFd = VM_MAKE_TAG(255);
#else   // !V8_OS_DARWIN
const int kMmapFd = -1;
#endif  // !V8_OS_DARWIN

#if defined(V8_TARGET_OS_MACOS) && V8_HOST_ARCH_ARM64
// During snapshot generation in cross builds, sysconf() runs on the Intel
// host and returns host page size, while the snapshot needs to use the
// target page size.
constexpr int kAppleArmPageSize = 1 << 14;
#endif

const int kMmapFdOffset = 0;

enum class PageType { kShared, kPrivate };

int GetFlagsForMemoryPermission(OS::MemoryPermission access,
                                PageType page_type) {
  int flags = MAP_ANONYMOUS;
  flags |= (page_type == PageType::kShared) ? MAP_SHARED : MAP_PRIVATE;
  if (access == OS::MemoryPermission::kNoAccess ||
      access == OS::MemoryPermission::kNoAccessWillJitLater) {
#if !V8_OS_AIX && !V8_OS_FREEBSD && !V8_OS_QNX
    flags |= MAP_NORESERVE;
#endif  // !V8_OS_AIX && !V8_OS_FREEBSD && !V8_OS_QNX
#if V8_OS_QNX
    flags |= MAP_LAZY;
#endif  // V8_OS_QNX
  }
#if V8_OS_DARWIN
  // MAP_JIT is required to obtain writable and executable pages when the
  // hardened runtime/memory protection is enabled, which is optional (via code
  // signing) on Intel-based Macs but mandatory on Apple silicon ones. See also
  // https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon.
  if (access == OS::MemoryPermission::kNoAccessWillJitLater ||
      access == OS::MemoryPermission::kReadWriteExecute) {
    flags |= MAP_JIT;
  }
#endif  // V8_OS_DARWIN
  return flags;
}

void* Allocate(void* hint, size_t size, OS::MemoryPermission access,
               PageType page_type) {
  int prot = GetProtectionFromMemoryPermission(access);
  int flags = GetFlagsForMemoryPermission(access, page_type);
  void* result = mmap(hint, size, prot, flags, kMmapFd, kMmapFdOffset);
  if (result == MAP_FAILED) return nullptr;

#if V8_OS_LINUX && V8_ENABLE_PRIVATE_MAPPING_FORK_OPTIMIZATION
  // This is advisory, so we ignore errors.
  madvise(result, size, MADV_DONTFORK);
#endif

#if ENABLE_HUGEPAGE
  if (result != nullptr && size >= kHugePageSize) {
    const uintptr_t huge_start =
        RoundUp(reinterpret_cast<uintptr_t>(result), kHugePageSize);
    const uintptr_t huge_end =
        RoundDown(reinterpret_cast<uintptr_t>(result) + size, kHugePageSize);
    if (huge_end > huge_start) {
      // Bail out in case the aligned addresses do not provide a block of at
      // least kHugePageSize size.
      madvise(reinterpret_cast<void*>(huge_start), huge_end - huge_start,
              MADV_HUGEPAGE);
    }
  }
#endif

  return result;
}

#endif  // !V8_OS_FUCHSIA && !V8_OS_ZOS

}  // namespace

// TODO(v8:10026): Add the right permission flag to make executable pages
// guarded.
int GetProtectionFromMemoryPermission(OS::MemoryPermission access) {
  switch (access) {
    case OS::MemoryPermission::kNoAccess:
    case OS::MemoryPermission::kNoAccessWillJitLater:
      return PROT_NONE;
    case OS::MemoryPermission::kRead:
      return PROT_READ;
    case OS::MemoryPermission::kReadWrite:
      return PROT_READ | PROT_WRITE;
    case OS::MemoryPermission::kReadWriteExecute:
      return PROT_READ | PROT_WRITE | PROT_EXEC;
    case OS::MemoryPermission::kReadExecute:
      return PROT_READ | PROT_EXEC;
  }
  UNREACHABLE();
}

#if V8_OS_LINUX || V8_OS_FREEBSD
#ifdef __arm__

bool OS::ArmUsingHardFloat() {
  // GCC versions 4.6 and above define __ARM_PCS or __ARM_PCS_VFP to specify
  // the Floating Point ABI used (PCS stands for Procedure Call Standard).
  // We use these as well as a couple of other defines to statically determine
  // what FP ABI used.
  // GCC versions 4.4 and below don't support hard-fp.
  // GCC versions 4.5 may support hard-fp without defining __ARM_PCS or
  // __ARM_PCS_VFP.

#define GCC_VERSION \
  (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40600 && !defined(__clang__)
#if defined(__ARM_PCS_VFP)
  return true;
#else
  return false;
#endif

#elif GCC_VERSION < 40500 && !defined(__clang__)
  return false;

#else
#if defined(__ARM_PCS_VFP)
  return true;
#elif defined(__ARM_PCS) || defined(__SOFTFP__) || defined(__SOFTFP) || \
    !defined(__VFP_FP__)
  return false;
#else
#error \
    "Your version of compiler does not report the FP ABI compiled for."     \
       "Please report it on this issue"                                        \
       "http://code.google.com/p/v8/issues/detail?id=2140"

#endif
#endif
#undef GCC_VERSION
}

#endif  // def __arm__
#endif

void PosixInitializeCommon(AbortMode abort_mode,
                           const char* const gc_fake_mmap) {
  g_abort_mode = abort_mode;
  g_gc_fake_mmap = gc_fake_mmap;
}

#if !V8_OS_FUCHSIA
void OS::Initialize(AbortMode abort_mode, const char* const gc_fake_mmap) {
  PosixInitializeCommon(abort_mode, gc_fake_mmap);
}
#endif  // !V8_OS_FUCHSIA

bool OS::IsHardwareEnforcedShadowStacksEnabled() { return false; }

int OS::ActivationFrameAlignment() {
#if V8_TARGET_ARCH_ARM
  // On EABI ARM targets this is required for fp correctness in the
  // runtime system.
  return 8;
#elif V8_TARGET_ARCH_MIPS
  return 8;
#elif V8_TARGET_ARCH_S390X
  return 8;
#else
  // Otherwise we just assume 16 byte alignment, i.e.:
  // - With gcc 4.4 the tree vectorization optimizer can generate code
  //   that requires 16 byte alignment such as movdqa on x86.
  // - Mac OS X, PPC and Solaris (64-bit) activation frames must
  //   be 16 byte-aligned;  see "Mac OS X ABI Function Call Guide"
  return 16;
#endif
}

// static
size_t OS::AllocatePageSize() {
#if defined(V8_TARGET_OS_MACOS) && V8_HOST_ARCH_ARM64
  return kAppleArmPageSize;
#else
  static size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  return page_size;
#endif
}

// static
size_t OS::CommitPageSize() {
  // Commit and allocate page size are the same on posix.
  return OS::AllocatePageSize();
}

// static
void OS::SetRandomMmapSeed(int64_t seed) {
  if (seed) {
    MutexGuard guard(rng_mutex.Pointer());
    GetPlatformRandomNumberGenerator()->SetSeed(seed);
  }
}

// static
void* OS::GetRandomMmapAddr() {
  uintptr_t raw_addr;
  {
    MutexGuard guard(rng_mutex.Pointer());
    GetPlatformRandomNumberGenerator()->NextBytes(&raw_addr, sizeof(raw_addr));
  }
#if V8_HOST_ARCH_ARM64
#if defined(V8_TARGET_OS_MACOS)
  DCHECK_EQ(1 << 14, AllocatePageSize());
#endif
  // Keep the address page-aligned, AArch64 supports 4K, 16K and 64K
  // configurations.
  raw_addr = RoundDown(raw_addr, AllocatePageSize());
#endif
#if defined(V8_USE_ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER) || \
    defined(THREAD_SANITIZER) || defined(LEAK_SANITIZER)
  // If random hint addresses interfere with address ranges hard coded in
  // sanitizers, bad things happen. This address range is copied from TSAN
  // source but works with all tools.
  // See crbug.com/539863.
  raw_addr &= 0x007fffff0000ULL;
  raw_addr += 0x7e8000000000ULL;
#else
#if V8_TARGET_ARCH_X64
  // Currently available CPUs have 48 bits of virtual addressing.  Truncate
  // the hint address to 46 bits to give the kernel a fighting chance of
  // fulfilling our placement request.
  raw_addr &= uint64_t{0x3FFFFFFFF000};
#elif V8_TARGET_ARCH_ARM64
#if defined(V8_TARGET_OS_LINUX) || defined(V8_TARGET_OS_ANDROID)
  // On Linux, the default virtual address space is limited to 39 bits when
  // using 4KB pages, see arch/arm64/Kconfig. We truncate to 38 bits.
  raw_addr &= uint64_t{0x3FFFFFF000};
#else
  // On macOS and elsewhere, we use 46 bits, same as on x64.
  raw_addr &= uint64_t{0x3FFFFFFFF000};
#endif
#elif V8_TARGET_ARCH_PPC64
#if V8_OS_AIX
  // AIX: 64 bits of virtual addressing, but we limit address range to minimize
  // Segment Lookaside Buffer (SLB) misses.
  raw_addr &= uint64_t{0x3FFFF000};
  // Use extra address space to isolate the mmap regions.
  raw_addr += uint64_t{0x400000000000};
#else
  // Little-endian Linux: 46 bits of virtual addressing.
  raw_addr &= uint64_t{0x3FFFFFFF0000};
#endif
#elif V8_TARGET_ARCH_S390X
  // Linux on Z uses bits 22-32 for Region Indexing, which translates to 42 bits
  // of virtual addressing.  Truncate to 40 bits to allow kernel chance to
  // fulfill request.
  raw_addr &= uint64_t{0xFFFFFFF000};
#elif V8_TARGET_ARCH_MIPS64
  // 42 bits of virtual addressing. Truncate to 40 bits to allow kernel chance
  // to fulfill request.
  raw_addr &= uint64_t{0xFFFFFF0000};
#elif V8_TARGET_ARCH_RISCV64
  // TODO(RISCV): We need more information from the kernel to correctly mask
  // this address for RISC-V. https://github.com/v8-riscv/v8/issues/375
  raw_addr &= uint64_t{0xFFFFFF0000};
#elif V8_TARGET_ARCH_RISCV32
  // TODO(RISCV): We need more information from the kernel to correctly mask
  // this address for RISC-V. https://github.com/v8-riscv/v8/issues/375
  raw_addr &= 0x3FFFF000;
#elif V8_TARGET_ARCH_LOONG64
  // 40 or 47 bits of virtual addressing. Truncate to 38 bits to allow kernel
  // chance to fulfill request.
  raw_addr &= uint64_t{0x3FFFFF0000};
#else
  raw_addr &= 0x3FFFF000;

#ifdef __sun
  // For our Solaris/illumos mmap hint, we pick a random address in the bottom
  // half of the top half of the address space (that is, the third quarter).
  // Because we do not MAP_FIXED, this will be treated only as a hint -- the
  // system will not fail to mmap() because something else happens to already
  // be mapped at our random address. We deliberately set the hint high enough
  // to get well above the system's break (that is, the heap); Solaris and
  // illumos will try the hint and if that fails allocate as if there were
  // no hint at all. The high hint prevents the break from getting hemmed in
  // at low values, ceding half of the address space to the system heap.
  raw_addr += 0x80000000;
#elif V8_OS_AIX
  // The range 0x30000000 - 0xD0000000 is available on AIX;
  // choose the upper range.
  raw_addr += 0x90000000;
#else
  // The range 0x20000000 - 0x60000000 is relatively unpopulated across a
  // variety of ASLR modes (PAE kernel, NX compat mode, etc) and on macos
  // 10.6 and 10.7.
  raw_addr += 0x20000000;
#endif
#endif
#endif
  return reinterpret_cast<void*>(raw_addr);
}

// TODO(bbudge) Move Cygwin and Fuchsia stuff into platform-specific files.
#if !V8_OS_CYGWIN && !V8_OS_FUCHSIA
#if !V8_OS_ZOS
// static
void* OS::Allocate(void* hint, size_t size, size_t alignment,
                   MemoryPermission access) {
  size_t page_size = AllocatePageSize();
  DCHECK_EQ(0, size % page_size);
  DCHECK_EQ(0, alignment % page_size);
  hint = AlignedAddress(hint, alignment);
  // Add the maximum misalignment so we are guaranteed an aligned base address.
  size_t request_size = size + (alignment - page_size);
  request_size = RoundUp(request_size, OS::AllocatePageSize());
  void* result = base::Allocate(hint, request_size, access, PageType::kPrivate);
  if (result == nullptr) return nullptr;

  // Unmap memory allocated before the aligned base address.
  uint8_t* base = static_cast<uint8_t*>(result);
  uint8_t* aligned_base = reinterpret_cast<uint8_t*>(
      RoundUp(reinterpret_cast<uintptr_t>(base), alignment));
  if (aligned_base != base) {
    DCHECK_LT(base, aligned_base);
    size_t prefix_size = static_cast<size_t>(aligned_base - base);
    Free(base, prefix_size);
    request_size -= prefix_size;
  }
  // Unmap memory allocated after the potentially unaligned end.
  if (size != request_size) {
    DCHECK_LT(size, request_size);
    size_t suffix_size = request_size - size;
    Free(aligned_base + size, suffix_size);
    request_size -= suffix_size;
  }

  DCHECK_EQ(size, request_size);
  return static_cast<void*>(aligned_base);
}

// static
void* OS::AllocateShared(size_t size, MemoryPermission access) {
  DCHECK_EQ(0, size % AllocatePageSize());
  return base::Allocate(nullptr, size, access, PageType::kShared);
}

// static
void OS::Free(void* address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % AllocatePageSize());
  DCHECK_EQ(0, size % AllocatePageSize());
  CHECK_EQ(0, munmap(address, size));
}

// Darwin specific implementation in platform-darwin.cc.
#if !defined(V8_OS_DARWIN)
// static
void* OS::AllocateShared(void* hint, size_t size, MemoryPermission access,
                         PlatformSharedMemoryHandle handle, uint64_t offset) {
  DCHECK_EQ(0, size % AllocatePageSize());
  int prot = GetProtectionFromMemoryPermission(access);
  int fd = FileDescriptorFromSharedMemoryHandle(handle);
  void* result = mmap(hint, size, prot, MAP_SHARED, fd, offset);
  if (result == MAP_FAILED) return nullptr;
  return result;
}
#endif  // !defined(V8_OS_DARWIN)

// static
void OS::FreeShared(void* address, size_t size) {
  DCHECK_EQ(0, size % AllocatePageSize());
  CHECK_EQ(0, munmap(address, size));
}

// static
void OS::Release(void* address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());
  CHECK_EQ(0, munmap(address, size));
}

// static
bool OS::SetPermissions(void* address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());

  int prot = GetProtectionFromMemoryPermission(access);
  int ret = mprotect(address, size, prot);

  // Setting permissions can fail if the limit of VMAs is exceeded.
  // Any failure that's not OOM likely indicates a bug in the caller (e.g.
  // using an invalid mapping) so attempt to catch that here to facilitate
  // debugging of these failures.
  if (ret != 0) CHECK_EQ(ENOMEM, errno);

  // MacOS 11.2 on Apple Silicon refuses to switch permissions from
  // rwx to none. Just use madvise instead.
#if defined(V8_OS_DARWIN)
  if (ret != 0 && access == OS::MemoryPermission::kNoAccess) {
    ret = madvise(address, size, MADV_FREE_REUSABLE);
    return ret == 0;
  }
#endif

  if (ret == 0 && access == OS::MemoryPermission::kNoAccess) {
    // This is advisory; ignore errors and continue execution.
    USE(DiscardSystemPages(address, size));
  }

// For accounting purposes, we want to call MADV_FREE_REUSE on macOS after
// changing permissions away from OS::MemoryPermission::kNoAccess. Since this
// state is not kept at this layer, we always call this if access != kNoAccess.
// The cost is a syscall that effectively no-ops.
// TODO(erikchen): Fix this to only call MADV_FREE_REUSE when necessary.
// https://crbug.com/823915
#if defined(V8_OS_DARWIN)
  if (access != OS::MemoryPermission::kNoAccess) {
    madvise(address, size, MADV_FREE_REUSE);
  }
#endif

  return ret == 0;
}

// static
void OS::SetDataReadOnly(void* address, size_t size) {
  CHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  CHECK_EQ(0, size % CommitPageSize());

  if (mprotect(address, size, PROT_READ) != 0) {
    FATAL("Failed to protect data memory at %p +%zu; error %d\n", address, size,
          errno);
  }
}

// static
bool OS::RecommitPages(void* address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());

#if defined(V8_OS_DARWIN)
  while (madvise(address, size, MADV_FREE_REUSE) == -1 && errno == EAGAIN) {
  }
#endif  // defined(V8_OS_DARWIN)
  return true;
}

// static
bool OS::DiscardSystemPages(void* address, size_t size) {
  // Roughly based on PartitionAlloc's DiscardSystemPagesInternal
  // (base/allocator/partition_allocator/page_allocator_internals_posix.h)
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());
#if defined(V8_OS_DARWIN)
  // On OSX, MADV_FREE_REUSABLE has comparable behavior to MADV_FREE, but also
  // marks the pages with the reusable bit, which allows both Activity Monitor
  // and memory-infra to correctly track the pages.
  int ret;
  do {
    ret = madvise(address, size, MADV_FREE_REUSABLE);
  } while (ret != 0 && errno == EAGAIN);
  if (ret) {
    // MADV_FREE_REUSABLE sometimes fails, so fall back to MADV_DONTNEED.
    ret = madvise(address, size, MADV_DONTNEED);
  }
#elif defined(_AIX) || defined(V8_OS_SOLARIS)
  int ret = madvise(reinterpret_cast<caddr_t>(address), size, MADV_FREE);
  if (ret != 0 && errno == ENOSYS) {
    return true;  // madvise is not available on all systems.
  }
  if (ret != 0 && errno == EINVAL) {
    ret = madvise(reinterpret_cast<caddr_t>(address), size, MADV_DONTNEED);
  }
#else
  int ret = madvise(address, size, MADV_DONTNEED);
#endif
  // madvise with MADV_DONTNEED only fails on illegal parameters. That's a bug
  // in the caller.
  CHECK_EQ(0, ret);
  return true;
}

#if !defined(_AIX)
// See AIX version for details.
// static
bool OS::DecommitPages(void* address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());
  // From https://pubs.opengroup.org/onlinepubs/9699919799/functions/mmap.html:
  // "If a MAP_FIXED request is successful, then any previous mappings [...] for
  // those whole pages containing any part of the address range [pa,pa+len)
  // shall be removed, as if by an appropriate call to munmap(), before the new
  // mapping is established." As a consequence, the memory will be
  // zero-initialized on next access.
  void* ret = mmap(address, size, PROT_NONE,
                   MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (V8_UNLIKELY(ret == MAP_FAILED)) {
    // Decommitting pages can fail if the limit of VMAs is exceeded.
    CHECK_EQ(ENOMEM, errno);
    return false;
  }
  CHECK_EQ(ret, address);
  return true;
}
#endif  // !defined(_AIX)
#endif  // !V8_OS_ZOS

// static
bool OS::SealPages(void* address, size_t size) {
#ifdef V8_ENABLE_MEMORY_SEALING
#if V8_OS_LINUX && defined(__NR_mseal)
  long ret = syscall(__NR_mseal, address, size, 0);
  return ret == 0;
#else
  return false;
#endif
#else  // V8_ENABLE_MEMORY_SEALING
  return false;
#endif
}

// static
bool OS::CanReserveAddressSpace() { return true; }

// static
std::optional<AddressSpaceReservation> OS::CreateAddressSpaceReservation(
    void* hint, size_t size, size_t alignment,
    MemoryPermission max_permission) {
  // On POSIX, address space reservations are backed by private memory mappings.
  MemoryPermission permission = MemoryPermission::kNoAccess;
  if (max_permission == MemoryPermission::kReadWriteExecute) {
    permission = MemoryPermission::kNoAccessWillJitLater;
  }

  void* reservation = Allocate(hint, size, alignment, permission);
  if (!reservation && permission == MemoryPermission::kNoAccessWillJitLater) {
    // Retry without MAP_JIT, for example in case we are running on an old OS X.
    permission = MemoryPermission::kNoAccess;
    reservation = Allocate(hint, size, alignment, permission);
  }

  if (!reservation) return {};

  return AddressSpaceReservation(reservation, size);
}

// static
void OS::FreeAddressSpaceReservation(AddressSpaceReservation reservation) {
  Free(reservation.base(), reservation.size());
}

// Darwin specific implementation in platform-darwin.cc.
#if !defined(V8_OS_DARWIN)
// static
// Need to disable CFI_ICALL due to the indirect call to memfd_create.
DISABLE_CFI_ICALL
PlatformSharedMemoryHandle OS::CreateSharedMemoryHandleForTesting(size_t size) {
#if V8_OS_LINUX && !V8_OS_ANDROID
  // Use memfd_create if available, otherwise mkstemp.
  using memfd_create_t = int (*)(const char*, unsigned int);
  memfd_create_t memfd_create =
      reinterpret_cast<memfd_create_t>(dlsym(RTLD_DEFAULT, "memfd_create"));
  int fd = -1;
  if (memfd_create) {
    fd = memfd_create("V8MemFDForTesting", 0);
  }
  if (fd == -1) {
    char filename[] = "/tmp/v8_tmp_file_for_testing_XXXXXX";
    fd = mkstemp(filename);
    if (fd != -1) CHECK_EQ(0, unlink(filename));
  }
  if (fd == -1) return kInvalidSharedMemoryHandle;
  CHECK_EQ(0, ftruncate(fd, size));
  return SharedMemoryHandleFromFileDescriptor(fd);
#else
  return kInvalidSharedMemoryHandle;
#endif
}

// static
void OS::DestroySharedMemoryHandle(PlatformSharedMemoryHandle handle) {
  DCHECK_NE(kInvalidSharedMemoryHandle, handle);
  int fd = FileDescriptorFromSharedMemoryHandle(handle);
  CHECK_EQ(0, close(fd));
}
#endif  // !defined(V8_OS_DARWIN)

#if !V8_OS_ZOS
// static
bool OS::HasLazyCommits() {
#if V8_OS_AIX || V8_OS_LINUX || V8_OS_DARWIN
  return true;
#else
  // TODO(bbudge) Return true for all POSIX platforms.
  return false;
#endif
}
#endif  // !V8_OS_ZOS
#endif  // !V8_OS_CYGWIN && !V8_OS_FUCHSIA

const char* OS::GetGCFakeMMapFile() {
  return g_gc_fake_mmap;
}


void OS::Sleep(TimeDelta interval) {
  usleep(static_cast<useconds_t>(interval.InMicroseconds()));
}


void OS::Abort() {
  switch (g_abort_mode) {
    case AbortMode::kExitWithSuccessAndIgnoreDcheckFailures:
      _exit(0);
    case AbortMode::kExitWithFailureAndIgnoreDcheckFailures:
      _exit(-1);
    case AbortMode::kImmediateCrash:
      IMMEDIATE_CRASH();
    case AbortMode::kDefault:
      break;
  }
  // Redirect to std abort to signal abnormal program termination.
  abort();
}


void OS::DebugBreak() {
#if V8_HOST_ARCH_ARM
  asm("bkpt 0");
#elif V8_HOST_ARCH_ARM64
  asm("brk 0");
#elif V8_HOST_ARCH_MIPS
  asm("break");
#elif V8_HOST_ARCH_MIPS64
  asm("break");
#elif V8_HOST_ARCH_LOONG64
  asm("break 0");
#elif V8_HOST_ARCH_PPC64
  asm("twge 2,2");
#elif V8_HOST_ARCH_IA32
  asm("int $3");
#elif V8_HOST_ARCH_X64
  asm("int $3");
#elif V8_OS_ZOS
  asm(" dc x'0001'");
#elif V8_HOST_ARCH_S390X
  // Software breakpoint instruction is 0x0001
  asm volatile(".word 0x0001");
#elif V8_HOST_ARCH_RISCV64
  asm("ebreak");
#elif V8_HOST_ARCH_RISCV32
  asm("ebreak");
#else
#error Unsupported host architecture.
#endif
}

#if !V8_OS_ZOS
class PosixMemoryMappedFile final : public OS::MemoryMappedFile {
 public:
  PosixMemoryMappedFile(FILE* file, void* memory, size_t size)
      : file_(file), memory_(memory), size_(size) {}
  ~PosixMemoryMappedFile() final;
  void* memory() const final { return memory_; }
  size_t size() const final { return size_; }

 private:
  FILE* const file_;
  void* const memory_;
  size_t const size_;
};


// static
OS::MemoryMappedFile* OS::MemoryMappedFile::open(const char* name,
                                                 FileMode mode) {
  const char* fopen_mode = (mode == FileMode::kReadOnly) ? "r" : "r+";
  struct stat statbuf;
  // Make sure path exists and is not a directory.
  if (stat(name, &statbuf) == 0 && !S_ISDIR(statbuf.st_mode)) {
    if (FILE* file = fopen(name, fopen_mode)) {
      if (fseek(file, 0, SEEK_END) == 0) {
        long size = ftell(file);  // NOLINT(runtime/int)
        if (size == 0) return new PosixMemoryMappedFile(file, nullptr, 0);
        if (size > 0) {
          int prot = PROT_READ;
          int flags = MAP_PRIVATE;
          if (mode == FileMode::kReadWrite) {
            prot |= PROT_WRITE;
            flags = MAP_SHARED;
          }
          void* const memory =
              mmap(OS::GetRandomMmapAddr(), size, prot, flags, fileno(file), 0);
          if (memory != MAP_FAILED) {
            return new PosixMemoryMappedFile(file, memory, size);
          }
        }
      }
      fclose(file);
    }
  }
  return nullptr;
}

// static
OS::MemoryMappedFile* OS::MemoryMappedFile::create(const char* name,
                                                   size_t size, void* initial) {
  if (FILE* file = fopen(name, "w+")) {
    if (size == 0) return new PosixMemoryMappedFile(file, nullptr, 0);
    size_t result = fwrite(initial, 1, size, file);
    if (result == size && !ferror(file)) {
      void* memory = mmap(OS::GetRandomMmapAddr(), result,
                          PROT_READ | PROT_WRITE, MAP_SHARED, fileno(file), 0);
      if (memory != MAP_FAILED) {
        return new PosixMemoryMappedFile(file, memory, result);
      }
    }
    fclose(file);
  }
  return nullptr;
}


PosixMemoryMappedFile::~PosixMemoryMappedFile() {
  if (memory_) OS::Free(memory_, RoundUp(size_, OS::AllocatePageSize()));
  fclose(file_);
}
#endif  // !V8_OS_ZOS

int OS::GetCurrentProcessId() {
  return static_cast<int>(getpid());
}


int OS::GetCurrentThreadId() {
#if V8_OS_DARWIN || (V8_OS_ANDROID && defined(__APPLE__))
  return static_cast<int>(pthread_mach_thread_np(pthread_self()));
#elif V8_OS_LINUX
  return static_cast<int>(syscall(__NR_gettid));
#elif V8_OS_ANDROID
  return static_cast<int>(gettid());
#elif V8_OS_AIX
  return static_cast<int>(thread_self());
#elif V8_OS_FUCHSIA
  return static_cast<int>(zx_thread_self());
#elif V8_OS_SOLARIS
  return static_cast<int>(pthread_self());
#elif V8_OS_ZOS
  return gettid();
#else
  return static_cast<int>(reinterpret_cast<intptr_t>(pthread_self()));
#endif
}

void OS::ExitProcess(int exit_code) {
  // Use _exit instead of exit to avoid races between isolate
  // threads and static destructors.
  fflush(stdout);
  fflush(stderr);
  _exit(exit_code);
}

// ----------------------------------------------------------------------------
// POSIX date/time support.
//

#if !defined(V8_OS_FUCHSIA)
int OS::GetUserTime(uint32_t* secs, uint32_t* usecs) {
  struct rusage usage;

  if (getrusage(RUSAGE_SELF, &usage) < 0) return -1;
  *secs = static_cast<uint32_t>(usage.ru_utime.tv_sec);
  *usecs = static_cast<uint32_t>(usage.ru_utime.tv_usec);
  return 0;
}
#endif

int OS::GetPeakMemoryUsageKb() {
#if defined(V8_OS_FUCHSIA)
  // Fuchsia does not implement getrusage()
  return -1;
#elif defined(V8_OS_ZOS)
  // TODO(v8:342445981): zos - rusage struct doesn't yet include ru_maxrss
  return -1;
#else
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) < 0) return -1;

#if defined(V8_OS_MACOS) || defined(V8_OS_IOS)
  constexpr int KB = 1024;
  // MacOS and iOS ru_maxrss count bytes
  return static_cast<int>(usage.ru_maxrss / KB);
#else
  // Most other cases (at least Linux, IOS, return kilobytes)
  return static_cast<int>(usage.ru_maxrss);
#endif  // defined(V8_OS_MACOS) || defined(V8_OS_IOS)
#endif  // defined(V8_OS_FUCHSIA)
}

double OS::TimeCurrentMillis() {
  return Time::Now().ToJsTime();
}

double PosixTimezoneCache::DaylightSavingsOffset(double time) {
  if (std::isnan(time)) return std::numeric_limits<double>::quiet_NaN();
  time_t tv = static_cast<time_t>(std::floor(time/msPerSecond));
  struct tm tm;
  struct tm* t = localtime_r(&tv, &tm);
  if (nullptr == t) return std::numeric_limits<double>::quiet_NaN();
  return t->tm_isdst > 0 ? 3600 * msPerSecond : 0;
}


int OS::GetLastError() {
  return errno;
}


// ----------------------------------------------------------------------------
// POSIX stdio support.
//

FILE* OS::FOpen(const char* path, const char* mode) {
  FILE* file = fopen(path, mode);
  if (file == nullptr) return nullptr;
  struct stat file_stat;
  if (fstat(fileno(file), &file_stat) != 0) {
    fclose(file);
    return nullptr;
  }
  bool is_regular_file = ((file_stat.st_mode & S_IFREG) != 0);
  if (is_regular_file) return file;
  fclose(file);
  return nullptr;
}


bool OS::Remove(const char* path) {
  return (remove(path) == 0);
}

char OS::DirectorySeparator() { return '/'; }

bool OS::isDirectorySeparator(const char ch) {
  return ch == DirectorySeparator();
}


FILE* OS::OpenTemporaryFile() {
  return tmpfile();
}

const char* const OS::LogFileOpenMode = "w+";

void OS::Print(const char* format, ...) {
  va_list args;
  va_start(args, format);
  VPrint(format, args);
  va_end(args);
}


void OS::VPrint(const char* format, va_list args) {
#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
#else
  vprintf(format, args);
#endif
}


void OS::FPrint(FILE* out, const char* format, ...) {
  va_list args;
  va_start(args, format);
  VFPrint(out, format, args);
  va_end(args);
}


void OS::VFPrint(FILE* out, const char* format, va_list args) {
#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
  if (out == stdout) {
    __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, format, args);
    return;
  }
#endif
  vfprintf(out, format, args);
}


void OS::PrintError(const char* format, ...) {
  va_list args;
  va_start(args, format);
  VPrintError(format, args);
  va_end(args);
  fflush(stderr);
}


void OS::VPrintError(const char* format, va_list args) {
#if defined(ANDROID) && !defined(V8_ANDROID_LOG_STDOUT)
  __android_log_vprint(ANDROID_LOG_ERROR, LOG_TAG, format, args);
#else
  vfprintf(stderr, format, args);
#endif
}


int OS::SNPrintF(char* str, int length, const char* format, ...) {
  va_list args;
  va_start(args, format);
  int result = VSNPrintF(str, length, format, args);
  va_end(args);
  return result;
}


int OS::VSNPrintF(char* str,
                  int length,
                  const char* format,
                  va_list args) {
  int n = vsnprintf(str, length, format, args);
  if (n < 0 || n >= length) {
    // If the length is zero, the assignment fails.
    if (length > 0)
      str[length - 1] = '\0';
    return -1;
  } else {
    return n;
  }
}


// ----------------------------------------------------------------------------
// POSIX string support.
//

void OS::StrNCpy(char* dest, int length, const char* src, size_t n) {
  strncpy(dest, src, n);
}

// ----------------------------------------------------------------------------
// POSIX Address space reservation support.
//

#if !V8_OS_CYGWIN && !V8_OS_FUCHSIA

std::optional<AddressSpaceReservation>
AddressSpaceReservation::CreateSubReservation(
    void* address, size_t size, OS::MemoryPermission max_permission) {
  DCHECK(Contains(address, size));
  DCHECK_EQ(0, size % OS::AllocatePageSize());
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % OS::AllocatePageSize());

  return AddressSpaceReservation(address, size);
}

bool AddressSpaceReservation::FreeSubReservation(
    AddressSpaceReser
"""


```