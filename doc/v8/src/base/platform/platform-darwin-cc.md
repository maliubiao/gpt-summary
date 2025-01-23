Response:
Let's break down the thought process to analyze the provided C++ code for `platform-darwin.cc`.

1. **Understand the Goal:** The request asks for the functionality of the code, whether it's related to Torque/JavaScript, provides examples, discusses logic/inputs/outputs, and mentions common errors. This requires analyzing the code's purpose and how it interacts with the V8 engine and the operating system.

2. **Identify Key Areas:**  The `#include` directives at the beginning are crucial. They reveal the core functionalities the code deals with:
    * System calls and low-level OS interfaces (`dlfcn.h`, `errno.h`, `mach/*`, `pthread.h`, `semaphore.h`, `signal.h`, `sys/*`, `unistd.h`). This strongly suggests the code interacts directly with the Darwin (macOS/iOS) operating system.
    * V8 internal headers (`"src/base/macros.h"`, `"src/base/platform/*"`). This confirms it's part of V8's platform abstraction layer.

3. **High-Level Purpose:** Combining the included headers, we can infer that `platform-darwin.cc` provides platform-specific implementations of operating system functionalities needed by V8 on macOS and iOS. It acts as an intermediary between V8's platform-independent code and the Darwin kernel.

4. **Function-by-Function Analysis:** Now, go through each function defined in the file:

    * **`GetVMProtFromMemoryPermission`:**  This function takes a V8 `MemoryPermission` enum and translates it into Darwin's `vm_prot_t` (virtual memory protection) flags. This is a straightforward mapping.

    * **`mach_vm_map_wrapper`:** This appears to be a helper function around the `mach_vm_map` system call. It sets default values for certain parameters, simplifying the call.

    * **`GetSharedLibraryAddresses`:** This function uses `_dyld` (dynamic loader) functions to iterate through loaded shared libraries (like `.dylib` files). It extracts information like name, code start address, and size. This is essential for debugging and security features in V8.

    * **`SignalCodeMovingGC`:** This function is empty. It's likely a placeholder for platform-specific actions that might be needed during garbage collection that involves moving code in memory.

    * **`CreateTimezoneCache`:**  Creates a `PosixDefaultTimezoneCache`. This points to time zone handling.

    * **`AdjustSchedulingParams`:** Uses `sysctlbyname` to potentially adjust scheduling parameters. The comments suggest it's related to "tcsm" (likely thread context switch mitigation or something similar) and might be specific to certain architectures.

    * **`GetFirstFreeMemoryRangeWithin`:** Returns `std::nullopt`, indicating this functionality isn't implemented (or needed) on Darwin in this way. It likely relates to finding free memory within a specific range.

    * **`ObtainCurrentThreadStackStart`:** Uses `pthread_get_stackaddr_np` to get the starting address of the current thread's stack.

    * **`CreateSharedMemoryHandleForTesting`:**  Uses Mach APIs (`mach_make_memory_entry_64`) to create a shared memory region. The "ForTesting" suffix suggests it's primarily used in V8's testing infrastructure.

    * **`DestroySharedMemoryHandle`:** Deallocates the Mach port associated with a shared memory handle.

    * **`AllocateShared`:**  Allocates memory in a shared memory segment using `mach_vm_map_wrapper`. It tries with a hint address first and then without.

    * **`RemapPages`:**  Uses `mach_vm_remap` to remap existing memory to a new address, potentially changing its permissions. This is an optimization technique to avoid copying memory.

    * **`AddressSpaceReservation::AllocateShared`:**  Similar to `OS::AllocateShared` but operates within an already reserved address space.

    * **`SetJitWriteProtected`:** Uses `pthread_jit_write_protect_np` to enable or disable JIT (Just-In-Time compilation) write protection. This is a security feature to prevent accidental or malicious modification of JIT-compiled code. The `#pragma` directives handle potential availability warnings.

5. **Torque/JavaScript Relevance:**
    * The `.cc` extension immediately tells us it's C++, not Torque (`.tq`).
    * The connection to JavaScript lies in the JIT compilation. `SetJitWriteProtected` directly impacts the security of JavaScript execution. Shared memory and memory management (allocation, remapping) are crucial for efficient execution of JavaScript code and data.

6. **JavaScript Examples:**  Focus on the visible JavaScript-related features:
    * `SetJitWriteProtected`: This is about V8's internal security and doesn't have a direct, observable JavaScript equivalent. However, its existence ensures that JIT-compiled JavaScript code is better protected.
    * Shared memory: While JavaScript doesn't directly expose these low-level OS primitives, features like `SharedArrayBuffer` in modern JavaScript rely on underlying shared memory mechanisms provided by the platform.

7. **Logic, Inputs, Outputs:** Choose a few key functions:
    * **`GetVMProtFromMemoryPermission`:** Input: `OS::MemoryPermission` (enum value). Output: `vm_prot_t` (integer bitmask). Provide example inputs and their corresponding outputs.
    * **`AllocateShared`:** Input: `hint` (void*), `size` (size_t), `access` (MemoryPermission), `handle` (PlatformSharedMemoryHandle), `offset` (uint64_t). Output: `void*` (allocated address) or `nullptr` on failure. Create a hypothetical successful and failed allocation scenario.

8. **Common Programming Errors:** Think about how developers might misuse the functionalities exposed (or implied) by this code:
    * Incorrect memory permission settings leading to crashes or security vulnerabilities.
    * Failing to deallocate shared memory.
    * Incorrectly handling potential allocation failures.

9. **Structure and Refine:** Organize the findings into clear sections as requested in the prompt: Functionality, Torque/JavaScript relevance, JavaScript examples, Logic/Inputs/Outputs, and Common Errors. Use clear and concise language. Ensure the examples are easy to understand.

10. **Review and Verify:**  Read through the generated analysis to ensure accuracy and completeness. Check for any logical inconsistencies or misunderstandings of the code. For instance, double-check the meaning of the Mach API calls.
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Platform-specific code shared between macOS and iOS goes here. The
// POSIX-compatible parts in platform-posix.cc.

#include <AvailabilityMacros.h>
#include <dlfcn.h>
#include <errno.h>
#include <libkern/OSAtomic.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <mach/vm_map.h>
#include <mach/vm_statistics.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmath>

#undef MAP_TYPE

#include "src/base/macros.h"
#include "src/base/platform/platform-posix-time.h"
#include "src/base/platform/platform-posix.h"
#include "src/base/platform/platform.h"

#if defined(V8_TARGET_OS_IOS)
#include "src/base/ios-headers.h"
#else
#include <mach/mach_vm.h>
#endif

namespace v8 {
namespace base {

namespace {

vm_prot_t GetVMProtFromMemoryPermission(OS::MemoryPermission access) {
  switch (access) {
    case OS::MemoryPermission::kNoAccess:
    case OS::MemoryPermission::kNoAccessWillJitLater:
      return VM_PROT_NONE;
    case OS::MemoryPermission::kRead:
      return VM_PROT_READ;
    case OS::MemoryPermission::kReadWrite:
      return VM_PROT_READ | VM_PROT_WRITE;
    case OS::MemoryPermission::kReadWriteExecute:
      return VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    case OS::MemoryPermission::kReadExecute:
      return VM_PROT_READ | VM_PROT_EXECUTE;
  }
  UNREACHABLE();
}

kern_return_t mach_vm_map_wrapper(mach_vm_address_t* address,
                                  mach_vm_size_t size, int flags,
                                  mach_port_t port,
                                  memory_object_offset_t offset,
                                  vm_prot_t prot) {
  vm_prot_t current_prot = prot;
  vm_prot_t maximum_prot = current_prot;
  return mach_vm_map(mach_task_self(), address, size, 0, flags, port, offset,
                     FALSE, current_prot, maximum_prot, VM_INHERIT_NONE);
}

}  // namespace

std::vector<OS::SharedLibraryAddress> OS::GetSharedLibraryAddresses() {
  std::vector<SharedLibraryAddress> result;
  unsigned int images_count = _dyld_image_count();
  for (unsigned int i = 0; i < images_count; ++i) {
    const mach_header* header = _dyld_get_image_header(i);
    if (header == nullptr) continue;
    unsigned long size;
#if V8_HOST_ARCH_I32
    uint8_t* code_ptr = getsectiondata(header, SEG_TEXT, SECT_TEXT, &size);
#else
    const mach_header_64* header64 =
        reinterpret_cast<const mach_header_64*>(header);
    uint8_t* code_ptr = getsectiondata(header64, SEG_TEXT, SECT_TEXT, &size);
#endif
    if (code_ptr == nullptr) continue;
    const intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    const uintptr_t start = reinterpret_cast<uintptr_t>(code_ptr);
    result.push_back(SharedLibraryAddress(_dyld_get_image_name(i), start,
                                          start + size, slide));
  }
  return result;
}

void OS::SignalCodeMovingGC() {}

TimezoneCache* OS::CreateTimezoneCache() {
  return new PosixDefaultTimezoneCache();
}

void OS::AdjustSchedulingParams() {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
  {
    // Check availability of scheduling params.
    uint32_t val = 0;
    size_t valSize = sizeof(val);
    int rc = sysctlbyname("kern.tcsm_available", &val, &valSize, NULL, 0);
    if (rc < 0 || !val) return;
  }

  {
    // Adjust scheduling params.
    uint32_t val = 1;
    int rc = sysctlbyname("kern.tcsm_enable", NULL, NULL, &val, sizeof(val));
    DCHECK_GE(rc, 0);
    USE(rc);
  }
#endif
}

std::optional<OS::MemoryRange> OS::GetFirstFreeMemoryRangeWithin(
    OS::Address boundary_start, OS::Address boundary_end, size_t minimum_size,
    size_t alignment) {
  return std::nullopt;
}

// static
Stack::StackSlot Stack::ObtainCurrentThreadStackStart() {
  return pthread_get_stackaddr_np(pthread_self());
}

// static
PlatformSharedMemoryHandle OS::CreateSharedMemoryHandleForTesting(size_t size) {
  mach_vm_size_t vm_size = size;
  mach_port_t port;
  kern_return_t kr = mach_make_memory_entry_64(
      mach_task_self(), &vm_size, 0,
      MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE, &port,
      MACH_PORT_NULL);
  if (kr != KERN_SUCCESS) return kInvalidSharedMemoryHandle;
  return SharedMemoryHandleFromMachMemoryEntry(port);
}

// static
void OS::DestroySharedMemoryHandle(PlatformSharedMemoryHandle handle) {
  DCHECK_NE(kInvalidSharedMemoryHandle, handle);
  mach_port_t port = MachMemoryEntryFromSharedMemoryHandle(handle);
  CHECK_EQ(KERN_SUCCESS, mach_port_deallocate(mach_task_self(), port));
}

// static
void* OS::AllocateShared(void* hint, size_t size, MemoryPermission access,
                         PlatformSharedMemoryHandle handle, uint64_t offset) {
  DCHECK_EQ(0, size % AllocatePageSize());

  mach_vm_address_t addr = reinterpret_cast<mach_vm_address_t>(hint);
  vm_prot_t prot = GetVMProtFromMemoryPermission(access);
  mach_port_t shared_mem_port = MachMemoryEntryFromSharedMemoryHandle(handle);
  kern_return_t kr = mach_vm_map_wrapper(&addr, size, VM_FLAGS_FIXED,
                                         shared_mem_port, offset, prot);

  if (kr != KERN_SUCCESS) {
    // Retry without hint.
    kr = mach_vm_map_wrapper(&addr, size, VM_FLAGS_ANYWHERE, shared_mem_port,
                             offset, prot);
  }

  if (kr != KERN_SUCCESS) return nullptr;
  return reinterpret_cast<void*>(addr);
}

// static
bool OS::RemapPages(const void* address, size_t size, void* new_address,
                    MemoryPermission access) {
  DCHECK(IsAligned(reinterpret_cast<uintptr_t>(address), AllocatePageSize()));
  DCHECK(
      IsAligned(reinterpret_cast<uintptr_t>(new_address), AllocatePageSize()));
  DCHECK(IsAligned(size, AllocatePageSize()));

  vm_prot_t cur_protection = GetVMProtFromMemoryPermission(access);
  vm_prot_t max_protection;
  // Asks the kernel to remap *on top* of an existing mapping, rather than
  // copying the data.
  int flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
  mach_vm_address_t target = reinterpret_cast<mach_vm_address_t>(new_address);
  kern_return_t ret =
      mach_vm_remap(mach_task_self(), &target, size, 0, flags, mach_task_self(),
                    reinterpret_cast<mach_vm_address_t>(address), FALSE,
                    &cur_protection, &max_protection, VM_INHERIT_NONE);

  if (ret != KERN_SUCCESS) return false;

  // Did we get the address we wanted?
  CHECK_EQ(new_address, reinterpret_cast<void*>(target));

  return true;
}

bool AddressSpaceReservation::AllocateShared(void* address, size_t size,
                                             OS::MemoryPermission access,
                                             PlatformSharedMemoryHandle handle,
                                             uint64_t offset) {
  DCHECK(Contains(address, size));

  vm_prot_t prot = GetVMProtFromMemoryPermission(access);
  mach_vm_address_t addr = reinterpret_cast<mach_vm_address_t>(address);
  mach_port_t shared_mem_port = MachMemoryEntryFromSharedMemoryHandle(handle);
  kern_return_t kr =
      mach_vm_map_wrapper(&addr, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                          shared_mem_port, offset, prot);
  return kr == KERN_SUCCESS;
}

// See platform-ios.cc for the iOS implementation.
#if V8_HAS_PTHREAD_JIT_WRITE_PROTECT && !defined(V8_OS_IOS)
// Ignoring this warning is considered better than relying on
// __builtin_available.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability-new"

V8_BASE_EXPORT void SetJitWriteProtected(int enable) {
  pthread_jit_write_protect_np(enable);
}

#pragma clang diagnostic pop
#endif

}  // namespace base
}  // namespace v8
```

### 功能列举

`v8/src/base/platform/platform-darwin.cc` 文件是 V8 JavaScript 引擎中特定于 Darwin 平台（macOS 和 iOS）的平台抽象层实现。其主要功能包括：

1. **共享库信息获取:**  获取当前进程加载的所有共享库（如 `.dylib` 文件）的地址、大小和名称。这对于调试、性能分析和安全功能（如代码完整性检查）非常重要。
2. **代码移动 GC 信号:** 提供一个空函数 `SignalCodeMovingGC()`，可能用于在需要进行代码移动的垃圾回收时执行平台特定的操作（当前在 Darwin 平台上没有具体实现）。
3. **时区缓存创建:** 创建 Darwin 平台特定的时区缓存对象，用于处理时间和日期相关的操作。
4. **调整调度参数:**  尝试调整系统调度参数，可能用于优化 V8 引擎的性能，例如通过 `sysctlbyname` 设置 `kern.tcsm_enable`。
5. **查找空闲内存范围:** 提供一个函数 `GetFirstFreeMemoryRangeWithin`，但当前在 Darwin 平台上返回 `std::nullopt`，表示该功能未实现或不需要。
6. **获取当前线程栈起始地址:**  通过 `pthread_get_stackaddr_np` 获取当前线程的栈起始地址。
7. **创建和销毁共享内存句柄 (用于测试):** 提供用于测试目的的创建和销毁共享内存句柄的函数，使用 Mach 内核 API (`mach_make_memory_entry_64` 和 `mach_port_deallocate`)。
8. **分配共享内存:** 使用 Mach 内核 API (`mach_vm_map`) 在共享内存中分配内存，允许在不同进程之间共享内存区域。
9. **重映射内存页:**  使用 Mach 内核 API (`mach_vm_remap`) 将现有的内存页重映射到新的地址，可以用于优化内存管理和实现某些高级功能。
10. **在预留地址空间分配共享内存:**  在已预留的地址空间内部分配共享内存。
11. **设置 JIT 代码写保护:**  如果定义了 `V8_HAS_PTHREAD_JIT_WRITE_PROTECT` 并且不是 iOS 系统，则提供 `SetJitWriteProtected` 函数，使用 `pthread_jit_write_protect_np` 来启用或禁用 JIT（Just-In-Time）编译代码的写保护，增强安全性。
12. **内存权限转换:** 提供一个内部函数 `GetVMProtFromMemoryPermission`，将 V8 内部的内存权限枚举转换为 Darwin 系统使用的内存保护标志 (`vm_prot_t`)。
13. **Mach VM Map 封装:** 提供一个内部函数 `mach_vm_map_wrapper`，作为 `mach_vm_map` 系统调用的一个简单封装。

### Torque 源代码判断

`v8/src/base/platform/platform-darwin.cc` 的文件扩展名是 `.cc`，表示这是一个 C++ 源代码文件。如果文件以 `.tq` 结尾，那么它才会被认为是 V8 Torque 源代码。因此，这个文件**不是** V8 Torque 源代码。

### 与 JavaScript 的关系

`v8/src/base/platform/platform-darwin.cc` 文件中的许多功能都与 JavaScript 的执行有直接或间接的关系：

* **共享库信息:** V8 需要知道加载了哪些库，这对于模块加载、WebAssembly 的执行等功能至关重要。
* **内存管理 (分配、重映射、共享内存):** JavaScript 引擎需要管理内存来存储对象、执行代码等。这些平台特定的内存操作是 V8 内存管理的基础。
* **JIT 代码写保护:**  这是一个重要的安全特性。JIT 编译将 JavaScript 代码转换为机器码，而写保护可以防止恶意代码修改已编译的 JIT 代码。

**JavaScript 示例 (与 JIT 代码写保护相关):**

尽管 JavaScript 代码本身不能直接调用 `SetJitWriteProtected`，但这个函数的存在直接影响了 JavaScript 的安全性。当 JIT 代码写保护启用时，尝试修改已编译的 JavaScript 代码会导致程序崩溃，从而阻止潜在的安全漏洞利用。

例如，考虑一个潜在的漏洞，攻击者试图修改已经 JIT 编译的 JavaScript 函数，以改变其行为。如果启用了 JIT 代码写保护，这种尝试将会失败。

```javascript
// 这是一个概念性的例子，说明 JIT 写保护的重要性，
// JavaScript 代码本身无法直接控制 JIT 写保护。

function vulnerableFunction() {
  console.log("This is the original function.");
}

// 假设攻击者可以修改内存中的 vulnerableFunction 的 JIT 代码
// 在启用了 JIT 写保护的情况下，这种尝试会失败。

// 实际的攻击方式会更复杂，涉及到内存操作等。
```

### 代码逻辑推理

**假设输入与输出 (以 `GetVMProtFromMemoryPermission` 为例):**

* **假设输入 1:** `OS::MemoryPermission::kReadWrite`
* **预期输出 1:** `VM_PROT_READ | VM_PROT_WRITE` (Darwin 系统中表示读写权限的标志位组合)

* **假设输入 2:** `OS::MemoryPermission::kNoAccess`
* **预期输出 2:** `VM_PROT_NONE` (Darwin 系统中表示无访问权限的标志)

**假设输入与输出 (以 `AllocateShared` 为例):**

* **假设输入:**
    * `hint`: `nullptr` (不提供地址提示)
    * `size`: `4096` (分配 4KB，假设系统页大小为 4KB)
    * `access`: `OS::MemoryPermission::kReadWrite`
    * `handle`: 一个有效的共享内存句柄
    * `offset`: `0` (从共享内存的起始位置开始)
* **预期输出:**
    * 如果分配成功：返回一个非空的 `void*` 指针，指向分配到的共享内存地址。
    * 如果分配失败（例如，内存不足）：返回 `nullptr`。

### 涉及用户常见的编程错误

1. **不匹配的内存权限:** 用户在进行 Native 代码开发并与 V8 交互时，可能会错误地设置内存权限。例如，尝试执行一块只读内存中的代码，或者尝试写入一块只读的共享内存。这会导致程序崩溃或产生不可预测的行为。

   ```c++
   // 错误示例：尝试执行只读内存
   void* memory = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   typedef void (*Func)();
   Func func = reinterpret_cast<Func>(memory);
   // 调用 func 会导致程序崩溃，因为内存没有执行权限。
   // func();
   ```

2. **共享内存管理错误:**  用户在使用共享内存时，可能会忘记解除映射或销毁共享内存句柄，导致资源泄漏。

   ```c++
   // 错误示例：忘记解除映射
   size_t shared_size = 4096;
   PlatformSharedMemoryHandle handle = OS::CreateSharedMemoryHandleForTesting(shared_size);
   void* shared_memory = OS::AllocateShared(nullptr, shared_size, OS::MemoryPermission::kReadWrite, handle, 0);

   // ... 使用 shared_memory ...

   // 忘记解除映射，可能导致资源泄漏
   // OS::DestroySharedMemoryHandle(handle);
   ```

3. **JIT 代码写保护相关的假设错误:**  用户在进行底层调试或安全研究时，可能会错误地假设 JIT 代码区域是可以随意修改的。启用了 JIT 代码写保护后，任何尝试修改这些区域的操作都会失败。

   ```c++
   // 假设可以修改 JIT 代码 (在启用了写保护的情况下会失败)
   // 这通常发生在试图进行热补丁或者动态代码注入等操作时。
   ```

总而言之，`v8/src/base/platform/platform-darwin.cc` 是 V8 引擎在 Darwin 平台上运行的关键组成部分，它提供了与操作系统底层交互的能力，支持 V8 的内存管理、代码执行、安全性和其他核心功能。理解这个文件的作用有助于深入理解 V8 引擎的平台适配机制。

### 提示词
```
这是目录为v8/src/base/platform/platform-darwin.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/platform/platform-darwin.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Platform-specific code shared between macOS and iOS goes here. The
// POSIX-compatible parts in platform-posix.cc.

#include <AvailabilityMacros.h>
#include <dlfcn.h>
#include <errno.h>
#include <libkern/OSAtomic.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <mach/vm_map.h>
#include <mach/vm_statistics.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmath>

#undef MAP_TYPE

#include "src/base/macros.h"
#include "src/base/platform/platform-posix-time.h"
#include "src/base/platform/platform-posix.h"
#include "src/base/platform/platform.h"

#if defined(V8_TARGET_OS_IOS)
#include "src/base/ios-headers.h"
#else
#include <mach/mach_vm.h>
#endif

namespace v8 {
namespace base {

namespace {

vm_prot_t GetVMProtFromMemoryPermission(OS::MemoryPermission access) {
  switch (access) {
    case OS::MemoryPermission::kNoAccess:
    case OS::MemoryPermission::kNoAccessWillJitLater:
      return VM_PROT_NONE;
    case OS::MemoryPermission::kRead:
      return VM_PROT_READ;
    case OS::MemoryPermission::kReadWrite:
      return VM_PROT_READ | VM_PROT_WRITE;
    case OS::MemoryPermission::kReadWriteExecute:
      return VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    case OS::MemoryPermission::kReadExecute:
      return VM_PROT_READ | VM_PROT_EXECUTE;
  }
  UNREACHABLE();
}

kern_return_t mach_vm_map_wrapper(mach_vm_address_t* address,
                                  mach_vm_size_t size, int flags,
                                  mach_port_t port,
                                  memory_object_offset_t offset,
                                  vm_prot_t prot) {
  vm_prot_t current_prot = prot;
  vm_prot_t maximum_prot = current_prot;
  return mach_vm_map(mach_task_self(), address, size, 0, flags, port, offset,
                     FALSE, current_prot, maximum_prot, VM_INHERIT_NONE);
}

}  // namespace

std::vector<OS::SharedLibraryAddress> OS::GetSharedLibraryAddresses() {
  std::vector<SharedLibraryAddress> result;
  unsigned int images_count = _dyld_image_count();
  for (unsigned int i = 0; i < images_count; ++i) {
    const mach_header* header = _dyld_get_image_header(i);
    if (header == nullptr) continue;
    unsigned long size;
#if V8_HOST_ARCH_I32
    uint8_t* code_ptr = getsectiondata(header, SEG_TEXT, SECT_TEXT, &size);
#else
    const mach_header_64* header64 =
        reinterpret_cast<const mach_header_64*>(header);
    uint8_t* code_ptr = getsectiondata(header64, SEG_TEXT, SECT_TEXT, &size);
#endif
    if (code_ptr == nullptr) continue;
    const intptr_t slide = _dyld_get_image_vmaddr_slide(i);
    const uintptr_t start = reinterpret_cast<uintptr_t>(code_ptr);
    result.push_back(SharedLibraryAddress(_dyld_get_image_name(i), start,
                                          start + size, slide));
  }
  return result;
}

void OS::SignalCodeMovingGC() {}

TimezoneCache* OS::CreateTimezoneCache() {
  return new PosixDefaultTimezoneCache();
}

void OS::AdjustSchedulingParams() {
#if V8_TARGET_ARCH_X64 || V8_TARGET_ARCH_IA32
  {
    // Check availability of scheduling params.
    uint32_t val = 0;
    size_t valSize = sizeof(val);
    int rc = sysctlbyname("kern.tcsm_available", &val, &valSize, NULL, 0);
    if (rc < 0 || !val) return;
  }

  {
    // Adjust scheduling params.
    uint32_t val = 1;
    int rc = sysctlbyname("kern.tcsm_enable", NULL, NULL, &val, sizeof(val));
    DCHECK_GE(rc, 0);
    USE(rc);
  }
#endif
}

std::optional<OS::MemoryRange> OS::GetFirstFreeMemoryRangeWithin(
    OS::Address boundary_start, OS::Address boundary_end, size_t minimum_size,
    size_t alignment) {
  return std::nullopt;
}

// static
Stack::StackSlot Stack::ObtainCurrentThreadStackStart() {
  return pthread_get_stackaddr_np(pthread_self());
}

// static
PlatformSharedMemoryHandle OS::CreateSharedMemoryHandleForTesting(size_t size) {
  mach_vm_size_t vm_size = size;
  mach_port_t port;
  kern_return_t kr = mach_make_memory_entry_64(
      mach_task_self(), &vm_size, 0,
      MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE, &port,
      MACH_PORT_NULL);
  if (kr != KERN_SUCCESS) return kInvalidSharedMemoryHandle;
  return SharedMemoryHandleFromMachMemoryEntry(port);
}

// static
void OS::DestroySharedMemoryHandle(PlatformSharedMemoryHandle handle) {
  DCHECK_NE(kInvalidSharedMemoryHandle, handle);
  mach_port_t port = MachMemoryEntryFromSharedMemoryHandle(handle);
  CHECK_EQ(KERN_SUCCESS, mach_port_deallocate(mach_task_self(), port));
}

// static
void* OS::AllocateShared(void* hint, size_t size, MemoryPermission access,
                         PlatformSharedMemoryHandle handle, uint64_t offset) {
  DCHECK_EQ(0, size % AllocatePageSize());

  mach_vm_address_t addr = reinterpret_cast<mach_vm_address_t>(hint);
  vm_prot_t prot = GetVMProtFromMemoryPermission(access);
  mach_port_t shared_mem_port = MachMemoryEntryFromSharedMemoryHandle(handle);
  kern_return_t kr = mach_vm_map_wrapper(&addr, size, VM_FLAGS_FIXED,
                                         shared_mem_port, offset, prot);

  if (kr != KERN_SUCCESS) {
    // Retry without hint.
    kr = mach_vm_map_wrapper(&addr, size, VM_FLAGS_ANYWHERE, shared_mem_port,
                             offset, prot);
  }

  if (kr != KERN_SUCCESS) return nullptr;
  return reinterpret_cast<void*>(addr);
}

// static
bool OS::RemapPages(const void* address, size_t size, void* new_address,
                    MemoryPermission access) {
  DCHECK(IsAligned(reinterpret_cast<uintptr_t>(address), AllocatePageSize()));
  DCHECK(
      IsAligned(reinterpret_cast<uintptr_t>(new_address), AllocatePageSize()));
  DCHECK(IsAligned(size, AllocatePageSize()));

  vm_prot_t cur_protection = GetVMProtFromMemoryPermission(access);
  vm_prot_t max_protection;
  // Asks the kernel to remap *on top* of an existing mapping, rather than
  // copying the data.
  int flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
  mach_vm_address_t target = reinterpret_cast<mach_vm_address_t>(new_address);
  kern_return_t ret =
      mach_vm_remap(mach_task_self(), &target, size, 0, flags, mach_task_self(),
                    reinterpret_cast<mach_vm_address_t>(address), FALSE,
                    &cur_protection, &max_protection, VM_INHERIT_NONE);

  if (ret != KERN_SUCCESS) return false;

  // Did we get the address we wanted?
  CHECK_EQ(new_address, reinterpret_cast<void*>(target));

  return true;
}

bool AddressSpaceReservation::AllocateShared(void* address, size_t size,
                                             OS::MemoryPermission access,
                                             PlatformSharedMemoryHandle handle,
                                             uint64_t offset) {
  DCHECK(Contains(address, size));

  vm_prot_t prot = GetVMProtFromMemoryPermission(access);
  mach_vm_address_t addr = reinterpret_cast<mach_vm_address_t>(address);
  mach_port_t shared_mem_port = MachMemoryEntryFromSharedMemoryHandle(handle);
  kern_return_t kr =
      mach_vm_map_wrapper(&addr, size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                          shared_mem_port, offset, prot);
  return kr == KERN_SUCCESS;
}

// See platform-ios.cc for the iOS implementation.
#if V8_HAS_PTHREAD_JIT_WRITE_PROTECT && !defined(V8_OS_IOS)
// Ignoring this warning is considered better than relying on
// __builtin_available.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability-new"

V8_BASE_EXPORT void SetJitWriteProtected(int enable) {
  pthread_jit_write_protect_np(enable);
}

#pragma clang diagnostic pop
#endif

}  // namespace base
}  // namespace v8
```