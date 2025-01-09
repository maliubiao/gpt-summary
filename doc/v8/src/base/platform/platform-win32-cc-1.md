Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/base/platform/platform-win32.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename suggests platform-specific functionality for Windows. Keywords like `OS::Allocate`, `VirtualAlloc`, `CreateFileMapping` point towards memory management and system-level operations.

2. **Group functions by category:**  Look for related functions and group them thematically. Common areas in platform code include:
    * Memory allocation/deallocation (regular and shared)
    * Memory permission manipulation
    * Address space reservation
    * File mapping
    * Threading
    * System calls (sleep, abort, debug break)
    * Stack information
    * Symbol loading for debugging

3. **Summarize each function group:**  For each group, explain the main purpose and key functions involved. Note any specific Windows API calls used.

4. **Address specific instructions:**
    * **`.tq` extension:** Check the filename. If it ended in `.tq`, mention Torque.
    * **JavaScript relationship:**  Consider how these low-level operations relate to JavaScript's memory management and execution.
    * **Code logic/reasoning:** Identify scenarios where the code makes decisions (e.g., retrying `MapViewOfFile` without a hint).
    * **Common programming errors:** Think about typical mistakes developers make when dealing with memory, threads, and system calls.
    * **Overall summary:** Combine the individual function group summaries into a concise overview.

5. **Review and refine:** Ensure the summary is clear, accurate, and addresses all aspects of the prompt. Use precise language to describe technical concepts.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Just list each function and its parameters.
* **Correction:**  That's too granular. The user wants to understand *what* the code does at a higher level. Grouping functions is essential.
* **Initial thought:** Focus only on the positive path (successful execution).
* **Correction:** The code includes error handling (e.g., checking return values). Mentioning this is important.
* **Initial thought:**  Assume the user is a V8 internals expert.
* **Correction:** The prompt doesn't specify the user's background. Explain concepts clearly, even if they seem obvious to someone deeply familiar with V8.
* **Initial thought:**  Overlook the dynamically loaded symbol functionality.
* **Correction:** The section on `LoadDbgHelpAndTlHelp32` and related functions is significant for debugging and should be included.
```javascript
// 假设我们有一个简单的 JavaScript 数组
const myArray = [1, 2, 3];

// V8 引擎需要在内存中分配空间来存储这个数组。
// platform-win32.cc 中的 OS::Allocate 等函数就负责在 Windows 平台上进行这种内存分配。

// 当我们访问数组元素时，例如：
const firstElement = myArray[0];

// V8 引擎需要确保这块内存是可读的。
// platform-win32.cc 中的 OS::SetPermissions 等函数就负责设置内存的访问权限。

// 如果我们修改数组元素：
myArray[0] = 4;

// V8 引擎需要确保这块内存是可写的。
// 同样，OS::SetPermissions 等函数会确保内存具有写入权限。

// 当数组不再使用时，V8 引擎会释放这块内存：
// （这通常发生在垃圾回收期间）

// platform-win32.cc 中的 OS::Free 等函数就负责在 Windows 平台上释放不再使用的内存。
```

## 功能归纳：

这段 C++ 代码（`v8/src/base/platform/platform-win32.cc`）是 V8 JavaScript 引擎在 **Windows 操作系统**上的平台特定实现，主要负责提供**操作系统抽象层**，让 V8 的核心代码能够以平台无关的方式进行内存管理、线程管理和其他系统调用。

具体来说，它实现了以下核心功能：

1. **内存管理:**
   - **分配内存 (`OS::Allocate`):**  在 Windows 上使用 `VirtualAlloc` 分配内存页，并根据需要进行提交（`MEM_COMMIT`）或仅预留（`MEM_RESERVE`）。可以指定内存对齐方式。
   - **释放内存 (`OS::Free`):** 使用 `VirtualFree` 释放已分配的内存。
   - **分配共享内存 (`OS::AllocateShared`):**  使用文件映射 (`CreateFileMapping`, `MapViewOfFileEx`) 来创建和映射共享内存区域，允许不同进程之间共享数据。
   - **释放共享内存 (`OS::FreeShared`):** 使用 `UnmapViewOfFile` 解除共享内存的映射。
   - **释放已提交的内存 (`OS::Release`):** 使用 `VirtualFree` 的 `MEM_DECOMMIT` 操作来释放已提交的物理内存，但保留地址空间。
   - **设置内存权限 (`OS::SetPermissions`):** 使用 `VirtualAllocWrapper` (或 `VirtualFree` 的 `MEM_DECOMMIT`) 来更改内存页的访问权限（例如，只读、读写、禁止访问）。
   - **设置数据为只读 (`OS::SetDataReadOnly`):** 使用 `VirtualProtect` 将内存页设置为只读。
   - **重新提交内存页 (`OS::RecommitPages`):**  本质上是重新设置内存页的权限，使其可访问。
   - **丢弃系统页 (`OS::DiscardSystemPages`):** 尝试使用 `DiscardVirtualMemory` (如果可用) 或 `VirtualAllocWrapper` 的 `MEM_RESET` 来释放物理内存，但不保证立即返回给系统或清零。
   - **取消提交内存页 (`OS::DecommitPages`):** 使用 `VirtualFree` 的 `MEM_DECOMMIT` 操作，使内存页变为保留状态，数据丢失。
   - **密封页 (`OS::SealPages`):**  在 Windows 上总是返回 `false`，表示不支持此功能。

2. **地址空间预留 (`OS::CreateAddressSpaceReservation`, `OS::FreeAddressSpaceReservation`):**
   - 使用 `VirtualAlloc` 的 `MEM_RESERVE` 和 `MEM_RESERVE_PLACEHOLDER` 来预留一块地址空间，但不实际分配物理内存。这可以防止其他分配占用这块空间。
   - 提供了操作预留地址空间的子区域的功能 (`AddressSpaceReservation` 类中的方法，例如 `SplitPlaceholder`, `MergePlaceholders`, `Allocate`, `Free`, `AllocateShared`, `FreeShared`, `SetPermissions`, 等)。这些方法通常使用 `VirtualAlloc2`, `MapViewOfFile3`, `UnmapViewOfFile2` 等更高级的 API。

3. **共享内存句柄管理 (`OS::CreateSharedMemoryHandleForTesting`, `OS::DestroySharedMemoryHandle`):**
   - 用于创建和销毁共享内存的文件映射句柄，主要用于测试目的。

4. **睡眠 (`OS::Sleep`, `PreciseSleepTimer`):**
   - 使用 Windows API `Sleep` 来暂停当前线程的执行。
   - `PreciseSleepTimer` 类尝试使用高精度计时器 (`CreateWaitableTimerExW` 配合 `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` 标志) 来实现更精确的睡眠。

5. **程序终止 (`OS::Abort`):**
   - 提供了多种终止程序的方式，包括调用 `DebugBreak` (如果存在调试器)、刷新输出缓冲区、调用 `_exit` 或 `abort`。

6. **调试断点 (`OS::DebugBreak`):**
   - 在代码中插入断点，当执行到此处时会触发调试器的中断。

7. **内存映射文件 (`OS::MemoryMappedFile`):**
   - 提供了创建和打开内存映射文件的方式，允许将文件内容映射到进程的地址空间，方便读写。

8. **线程管理 (`Thread` 类):**
   - 提供了创建、启动和加入线程的功能，使用了 `_beginthreadex` 和 `WaitForSingleObject` 等 Windows API。
   - 提供了线程局部存储 (`Thread::CreateThreadLocalKey`, `Thread::DeleteThreadLocalKey`, `Thread::GetThreadLocal`, `Thread::SetThreadLocal`)，允许每个线程拥有独立的变量副本。

9. **获取共享库地址 (`OS::GetSharedLibraryAddresses`):**
   - 使用 `DbgHelp.dll` 和 `TlHelp32.h` 中的函数（动态加载）来获取当前进程加载的共享库（DLL）的地址信息，这对于生成堆栈跟踪等调试信息非常重要。

10. **堆栈信息 (`Stack::ObtainCurrentThreadStackStart`, `Stack::GetCurrentStackPosition`):**
    - 提供了获取当前线程堆栈起始地址和当前堆栈指针位置的方法，用于堆栈相关的操作。

11. **调整调度参数 (`OS::AdjustSchedulingParams`):**
    - 在 Windows 上此方法为空，表示不进行任何特定的调度参数调整。

12. **查找空闲内存范围 (`OS::GetFirstFreeMemoryRangeWithin`):**
    - 使用 `VirtualQuery` 遍历指定范围内的虚拟内存，查找足够大小和对齐的空闲内存区域。

13. **控制台输出 (`EnsureConsoleOutputWin32`):**
    - 确保控制台输出能够正常工作，设置错误模式和 CRT 报告模式。

**关于 .tq 扩展:**

代码的文件名是 `platform-win32.cc`，**不以 `.tq` 结尾**。因此，它不是 V8 Torque 源代码。Torque 用于定义 V8 的内置函数和类型系统。

**总结:**

`v8/src/base/platform/platform-win32.cc` 是 V8 在 Windows 平台上的基础支撑，它封装了底层的 Windows API，为 V8 的高级功能（如 JavaScript 对象的内存分配、并发执行等）提供了必要的操作系统服务抽象。它确保了 V8 能够在 Windows 上正确且高效地运行。

**常见的编程错误（与这段代码涉及的功能相关）：**

1. **内存泄漏:**  分配了内存但没有正确释放，导致程序占用的内存越来越多。例如，调用 `OS::Allocate` 后忘记调用 `OS::Free`。
2. **访问越界:** 读写了不属于已分配内存区域的地址，可能导致程序崩溃。例如，使用指向已释放内存的指针。
3. **线程同步问题:** 在多线程环境下，如果没有正确地同步对共享资源的访问，可能导致数据竞争和程序行为不可预测。例如，多个线程同时修改同一块共享内存而没有使用互斥锁或其他同步机制。
4. **共享内存使用错误:**  在不同进程中使用共享内存时，需要确保所有进程都正确映射和取消映射，并且对共享内存的访问是同步的。
5. **文件映射错误:**  打开、创建或映射文件时，需要处理可能发生的错误，例如文件不存在、权限不足等。忘记关闭文件句柄或映射视图也可能导致资源泄漏。
6. **不正确的内存权限设置:**  尝试访问没有相应权限的内存区域会导致访问冲突。例如，尝试写入一个只读的内存页。
7. **线程创建失败:**  `_beginthreadex` 可能因为各种原因失败，例如系统资源不足。没有检查返回值可能导致程序行为异常。
8. **线程局部存储使用不当:**  错误的键值或在线程退出后访问线程局部存储可能导致错误。
9. **动态加载库失败:**  `LoadLibrary` 和 `GetProcAddress` 调用可能失败，需要进行错误处理，否则后续使用这些函数指针的代码会崩溃。

Prompt: 
```
这是目录为v8/src/base/platform/platform-win32.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/platform/platform-win32.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""

// static
void* OS::Allocate(void* hint, size_t size, size_t alignment,
                   MemoryPermission access) {
  size_t page_size = AllocatePageSize();
  DCHECK_EQ(0, size % page_size);
  DCHECK_EQ(0, alignment % page_size);
  DCHECK_LE(page_size, alignment);
  hint = AlignedAddress(hint, alignment);

  DWORD flags = (access == OS::MemoryPermission::kNoAccess)
                    ? MEM_RESERVE
                    : MEM_RESERVE | MEM_COMMIT;
  DWORD protect = GetProtectionFromMemoryPermission(access);

  return AllocateInternal(hint, size, alignment, page_size, flags, protect);
}

// static
void OS::Free(void* address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % AllocatePageSize());
  DCHECK_EQ(0, size % AllocatePageSize());
  USE(size);
  CHECK_NE(0, VirtualFree(address, 0, MEM_RELEASE));
}

// static
void* OS::AllocateShared(void* hint, size_t size, MemoryPermission permission,
                         PlatformSharedMemoryHandle handle, uint64_t offset) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(hint) % AllocatePageSize());
  DCHECK_EQ(0, size % AllocatePageSize());
  DCHECK_EQ(0, offset % AllocatePageSize());

  DWORD off_hi = static_cast<DWORD>(offset >> 32);
  DWORD off_lo = static_cast<DWORD>(offset);
  DWORD access = GetFileViewAccessFromMemoryPermission(permission);

  HANDLE file_mapping = FileMappingFromSharedMemoryHandle(handle);
  void* result =
      MapViewOfFileEx(file_mapping, access, off_hi, off_lo, size, hint);

  if (!result) {
    // Retry without hint.
    result = MapViewOfFile(file_mapping, access, off_hi, off_lo, size);
  }

  return result;
}

// static
void OS::FreeShared(void* address, size_t size) {
  CHECK(UnmapViewOfFile(address));
}

// static
void OS::Release(void* address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());
  CHECK_NE(0, VirtualFree(address, size, MEM_DECOMMIT));
}

// static
bool OS::SetPermissions(void* address, size_t size, MemoryPermission access) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());
  if (access == MemoryPermission::kNoAccess) {
    return VirtualFree(address, size, MEM_DECOMMIT) != 0;
  }
  DWORD protect = GetProtectionFromMemoryPermission(access);
  void* result = VirtualAllocWrapper(address, size, MEM_COMMIT, protect);

  // Any failure that's not OOM likely indicates a bug in the caller (e.g.
  // using an invalid mapping) so attempt to catch that here to facilitate
  // debugging of these failures.
  if (!result) CheckIsOOMError(GetLastError());

  return result != nullptr;
}

void OS::SetDataReadOnly(void* address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());

  DWORD old_protection;
  CHECK(VirtualProtect(address, size, PAGE_READONLY, &old_protection));
  CHECK(old_protection == PAGE_READWRITE || old_protection == PAGE_WRITECOPY);
}

// static
bool OS::RecommitPages(void* address, size_t size, MemoryPermission access) {
  return SetPermissions(address, size, access);
}

// static
bool OS::DiscardSystemPages(void* address, size_t size) {
  // On Windows, discarded pages are not returned to the system immediately and
  // not guaranteed to be zeroed when returned to the application.
  using DiscardVirtualMemoryFunction =
      DWORD(WINAPI*)(PVOID virtualAddress, SIZE_T size);
  static std::atomic<DiscardVirtualMemoryFunction> discard_virtual_memory(
      reinterpret_cast<DiscardVirtualMemoryFunction>(-1));
  if (discard_virtual_memory ==
      reinterpret_cast<DiscardVirtualMemoryFunction>(-1))
    discard_virtual_memory =
        reinterpret_cast<DiscardVirtualMemoryFunction>(GetProcAddress(
            GetModuleHandle(L"Kernel32.dll"), "DiscardVirtualMemory"));
  // Use DiscardVirtualMemory when available because it releases faster than
  // MEM_RESET.
  DiscardVirtualMemoryFunction discard_function = discard_virtual_memory.load();
  if (discard_function) {
    DWORD ret = discard_function(address, size);
    if (!ret) return true;
  }
  // DiscardVirtualMemory is buggy in Win10 SP0, so fall back to MEM_RESET on
  // failure.
  void* ptr = VirtualAllocWrapper(address, size, MEM_RESET, PAGE_READWRITE);
  CHECK(ptr);
  return ptr;
}

// static
bool OS::DecommitPages(void* address, size_t size) {
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % CommitPageSize());
  DCHECK_EQ(0, size % CommitPageSize());
  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree:
  // "If a page is decommitted but not released, its state changes to reserved.
  // Subsequently, you can call VirtualAlloc to commit it, or VirtualFree to
  // release it. Attempts to read from or write to a reserved page results in an
  // access violation exception."
  // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
  // for MEM_COMMIT: "The function also guarantees that when the caller later
  // initially accesses the memory, the contents will be zero."
  return VirtualFree(address, size, MEM_DECOMMIT) != 0;
}

// static
bool OS::SealPages(void* address, size_t size) { return false; }

// static
bool OS::CanReserveAddressSpace() {
  return VirtualAlloc2 != nullptr && MapViewOfFile3 != nullptr &&
         UnmapViewOfFile2 != nullptr;
}

// static
std::optional<AddressSpaceReservation> OS::CreateAddressSpaceReservation(
    void* hint, size_t size, size_t alignment,
    MemoryPermission max_permission) {
  CHECK(CanReserveAddressSpace());

  size_t page_size = AllocatePageSize();
  DCHECK_EQ(0, size % page_size);
  DCHECK_EQ(0, alignment % page_size);
  DCHECK_LE(page_size, alignment);
  hint = AlignedAddress(hint, alignment);

  // On Windows, address space reservations are backed by placeholder mappings.
  void* reservation =
      AllocateInternal(hint, size, alignment, page_size,
                       MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
  if (!reservation) return {};

  return AddressSpaceReservation(reservation, size);
}

// static
void OS::FreeAddressSpaceReservation(AddressSpaceReservation reservation) {
  OS::Free(reservation.base(), reservation.size());
}

// static
PlatformSharedMemoryHandle OS::CreateSharedMemoryHandleForTesting(size_t size) {
  HANDLE handle = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr,
                                    PAGE_READWRITE, 0, size, nullptr);
  if (!handle) return kInvalidSharedMemoryHandle;
  return SharedMemoryHandleFromFileMapping(handle);
}

// static
void OS::DestroySharedMemoryHandle(PlatformSharedMemoryHandle handle) {
  DCHECK_NE(kInvalidSharedMemoryHandle, handle);
  HANDLE file_mapping = FileMappingFromSharedMemoryHandle(handle);
  CHECK(CloseHandle(file_mapping));
}

// static
bool OS::HasLazyCommits() {
  // TODO(alph): implement for the platform.
  return false;
}

void OS::Sleep(TimeDelta interval) {
  ::Sleep(static_cast<DWORD>(interval.InMilliseconds()));
}

PreciseSleepTimer::PreciseSleepTimer() : timer_(NULL) {}
PreciseSleepTimer::~PreciseSleepTimer() { Close(); }
PreciseSleepTimer::PreciseSleepTimer(PreciseSleepTimer&& other) V8_NOEXCEPT {
  Close();
  timer_ = other.timer_;
  other.timer_ = NULL;
}
PreciseSleepTimer& PreciseSleepTimer::operator=(PreciseSleepTimer&& other)
    V8_NOEXCEPT {
  Close();
  timer_ = other.timer_;
  other.timer_ = NULL;
  return *this;
}
bool PreciseSleepTimer::IsInitialized() const { return timer_ != NULL; }
void PreciseSleepTimer::Close() {
  if (timer_ != NULL) {
    CloseHandle(timer_);
    timer_ = NULL;
  }
}

void PreciseSleepTimer::TryInit() {
  Close();
  // This flag allows precise sleep times, but is only available since Windows
  // 10 version 1803.
  DWORD flags = CREATE_WAITABLE_TIMER_HIGH_RESOLUTION;
  // The TIMER_MODIFY_STATE permission allows setting the timer, and SYNCHRONIZE
  // allows waiting for it.
  DWORD desired_access = TIMER_MODIFY_STATE | SYNCHRONIZE;
  timer_ =
      CreateWaitableTimerExW(NULL,  // Cannot be inherited by child processes
                             NULL,  // Cannot be looked up by name
                             flags, desired_access);
}

void PreciseSleepTimer::Sleep(TimeDelta interval) const {
  // Time is specified in 100 nanosecond intervals. Negative values indicate
  // relative time.
  LARGE_INTEGER due_time;
  due_time.QuadPart = -interval.InMicroseconds() * 10;
  LONG period = 0;  // Not periodic; wake only once
  PTIMERAPCROUTINE completion_routine = NULL;
  LPVOID arg_to_completion_routine = NULL;
  BOOL resume = false;  // No need to wake system from sleep
  CHECK(SetWaitableTimer(timer_, &due_time, period, completion_routine,
                         arg_to_completion_routine, resume));

  DWORD timeout_interval = INFINITE;  // Return only when the object is signaled
  CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(timer_, timeout_interval));
}

void OS::Abort() {
  // Give a chance to debug the failure.
  if (IsDebuggerPresent()) {
    DebugBreak();
  }

  // Before aborting, make sure to flush output buffers.
  fflush(stdout);
  fflush(stderr);

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

  // Make the MSVCRT do a silent abort.
  raise(SIGABRT);

  // Make sure function doesn't return.
  abort();
}


void OS::DebugBreak() {
#if V8_CC_MSVC
  // To avoid Visual Studio runtime support the following code can be used
  // instead
  // __asm { int 3 }
  __debugbreak();
#else
  ::DebugBreak();
#endif
}


class Win32MemoryMappedFile final : public OS::MemoryMappedFile {
 public:
  Win32MemoryMappedFile(HANDLE file, HANDLE file_mapping, void* memory,
                        size_t size)
      : file_(file),
        file_mapping_(file_mapping),
        memory_(memory),
        size_(size) {}
  ~Win32MemoryMappedFile() final;
  void* memory() const final { return memory_; }
  size_t size() const final { return size_; }

 private:
  HANDLE const file_;
  HANDLE const file_mapping_;
  void* const memory_;
  size_t const size_;
};


// static
OS::MemoryMappedFile* OS::MemoryMappedFile::open(const char* name,
                                                 FileMode mode) {
  // Open a physical file.
  DWORD access = GENERIC_READ;
  if (mode == FileMode::kReadWrite) {
    access |= GENERIC_WRITE;
  }

  std::wstring utf16_name = ConvertUtf8StringToUtf16(name);
  HANDLE file = CreateFileW(utf16_name.c_str(), access,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, 0, nullptr);
  if (file == INVALID_HANDLE_VALUE) return nullptr;

  DWORD size = GetFileSize(file, nullptr);
  if (size == 0) return new Win32MemoryMappedFile(file, nullptr, nullptr, 0);

  DWORD protection =
      (mode == FileMode::kReadOnly) ? PAGE_READONLY : PAGE_READWRITE;
  // Create a file mapping for the physical file.
  HANDLE file_mapping =
      CreateFileMapping(file, nullptr, protection, 0, size, nullptr);
  if (file_mapping == nullptr) return nullptr;

  // Map a view of the file into memory.
  DWORD view_access =
      (mode == FileMode::kReadOnly) ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS;
  void* memory = MapViewOfFile(file_mapping, view_access, 0, 0, size);
  return new Win32MemoryMappedFile(file, file_mapping, memory, size);
}

// static
OS::MemoryMappedFile* OS::MemoryMappedFile::create(const char* name,
                                                   size_t size, void* initial) {
  std::wstring utf16_name = ConvertUtf8StringToUtf16(name);
  // Open a physical file.
  HANDLE file = CreateFileW(utf16_name.c_str(), GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_ALWAYS, 0, nullptr);
  if (file == nullptr) return nullptr;
  if (size == 0) return new Win32MemoryMappedFile(file, nullptr, nullptr, 0);
  // Create a file mapping for the physical file.
  HANDLE file_mapping = CreateFileMapping(file, nullptr, PAGE_READWRITE, 0,
                                          static_cast<DWORD>(size), nullptr);
  if (file_mapping == nullptr) return nullptr;
  // Map a view of the file into memory.
  void* memory = MapViewOfFile(file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, size);
  if (memory) memmove(memory, initial, size);
  return new Win32MemoryMappedFile(file, file_mapping, memory, size);
}


Win32MemoryMappedFile::~Win32MemoryMappedFile() {
  if (memory_) UnmapViewOfFile(memory_);
  if (file_mapping_) CloseHandle(file_mapping_);
  CloseHandle(file_);
}

std::optional<AddressSpaceReservation>
AddressSpaceReservation::CreateSubReservation(
    void* address, size_t size, OS::MemoryPermission max_permission) {
  // Nothing to do, the sub reservation must already have been split by now.
  DCHECK(Contains(address, size));
  DCHECK_EQ(0, size % OS::AllocatePageSize());
  DCHECK_EQ(0, reinterpret_cast<uintptr_t>(address) % OS::AllocatePageSize());

  return AddressSpaceReservation(address, size);
}

bool AddressSpaceReservation::FreeSubReservation(
    AddressSpaceReservation reservation) {
  // Nothing to do.
  // Pages allocated inside the reservation must've already been freed.
  return true;
}

bool AddressSpaceReservation::SplitPlaceholder(void* address, size_t size) {
  DCHECK(Contains(address, size));
  return VirtualFree(address, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
}

bool AddressSpaceReservation::MergePlaceholders(void* address, size_t size) {
  DCHECK(Contains(address, size));
  return VirtualFree(address, size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
}

bool AddressSpaceReservation::Allocate(void* address, size_t size,
                                       OS::MemoryPermission access) {
  DCHECK(Contains(address, size));
  CHECK(VirtualAlloc2);
  DWORD flags = (access == OS::MemoryPermission::kNoAccess)
                    ? MEM_RESERVE | MEM_REPLACE_PLACEHOLDER
                    : MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER;
  DWORD protect = GetProtectionFromMemoryPermission(access);
  return VirtualAlloc2(GetCurrentProcess(), address, size, flags, protect,
                       nullptr, 0);
}

bool AddressSpaceReservation::Free(void* address, size_t size) {
  DCHECK(Contains(address, size));
  return VirtualFree(address, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
}

bool AddressSpaceReservation::AllocateShared(void* address, size_t size,
                                             OS::MemoryPermission access,
                                             PlatformSharedMemoryHandle handle,
                                             uint64_t offset) {
  DCHECK(Contains(address, size));
  CHECK(MapViewOfFile3);

  DWORD protect = GetProtectionFromMemoryPermission(access);
  HANDLE file_mapping = FileMappingFromSharedMemoryHandle(handle);
  return MapViewOfFile3(file_mapping, GetCurrentProcess(), address, offset,
                        size, MEM_REPLACE_PLACEHOLDER, protect, nullptr, 0);
}

bool AddressSpaceReservation::FreeShared(void* address, size_t size) {
  DCHECK(Contains(address, size));
  CHECK(UnmapViewOfFile2);

  return UnmapViewOfFile2(GetCurrentProcess(), address,
                          MEM_PRESERVE_PLACEHOLDER);
}

bool AddressSpaceReservation::SetPermissions(void* address, size_t size,
                                             OS::MemoryPermission access) {
  DCHECK(Contains(address, size));
  return OS::SetPermissions(address, size, access);
}

bool AddressSpaceReservation::RecommitPages(void* address, size_t size,
                                            OS::MemoryPermission access) {
  DCHECK(Contains(address, size));
  return OS::RecommitPages(address, size, access);
}

bool AddressSpaceReservation::DiscardSystemPages(void* address, size_t size) {
  DCHECK(Contains(address, size));
  return OS::DiscardSystemPages(address, size);
}

bool AddressSpaceReservation::DecommitPages(void* address, size_t size) {
  DCHECK(Contains(address, size));
  return OS::DecommitPages(address, size);
}

// The following code loads functions defined in DbhHelp.h and TlHelp32.h
// dynamically. This is to avoid being depending on dbghelp.dll and
// tlhelp32.dll when running (the functions in tlhelp32.dll have been moved to
// kernel32.dll at some point so loading functions defines in TlHelp32.h
// dynamically might not be necessary any more - for some versions of Windows?).

// Function pointers to functions dynamically loaded from dbghelp.dll.
#define DBGHELP_FUNCTION_LIST(V)  \
  V(SymInitialize)                \
  V(SymGetOptions)                \
  V(SymSetOptions)                \
  V(SymGetSearchPath)             \
  V(SymLoadModule64)              \
  V(StackWalk64)                  \
  V(SymGetSymFromAddr64)          \
  V(SymGetLineFromAddr64)         \
  V(SymFunctionTableAccess64)     \
  V(SymGetModuleBase64)

// Function pointers to functions dynamically loaded from dbghelp.dll.
#define TLHELP32_FUNCTION_LIST(V)  \
  V(CreateToolhelp32Snapshot)      \
  V(Module32FirstW)                \
  V(Module32NextW)

// Define the decoration to use for the type and variable name used for
// dynamically loaded DLL function..
#define DLL_FUNC_TYPE(name) _##name##_
#define DLL_FUNC_VAR(name) _##name

// Define the type for each dynamically loaded DLL function. The function
// definitions are copied from DbgHelp.h and TlHelp32.h. The IN and VOID macros
// from the Windows include files are redefined here to have the function
// definitions to be as close to the ones in the original .h files as possible.
#ifndef IN
#define IN
#endif
#ifndef VOID
#define VOID void
#endif

// DbgHelp isn't supported on MinGW yet
#ifndef __MINGW32__
// DbgHelp.h functions.
using DLL_FUNC_TYPE(SymInitialize) = BOOL(__stdcall*)(IN HANDLE hProcess,
                                                      IN PSTR UserSearchPath,
                                                      IN BOOL fInvadeProcess);
using DLL_FUNC_TYPE(SymGetOptions) = DWORD(__stdcall*)(VOID);
using DLL_FUNC_TYPE(SymSetOptions) = DWORD(__stdcall*)(IN DWORD SymOptions);
using DLL_FUNC_TYPE(SymGetSearchPath) = BOOL(__stdcall*)(
    IN HANDLE hProcess, OUT PSTR SearchPath, IN DWORD SearchPathLength);
using DLL_FUNC_TYPE(SymLoadModule64) = DWORD64(__stdcall*)(
    IN HANDLE hProcess, IN HANDLE hFile, IN PSTR ImageName, IN PSTR ModuleName,
    IN DWORD64 BaseOfDll, IN DWORD SizeOfDll);
using DLL_FUNC_TYPE(StackWalk64) = BOOL(__stdcall*)(
    DWORD MachineType, HANDLE hProcess, HANDLE hThread,
    LPSTACKFRAME64 StackFrame, PVOID ContextRecord,
    PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
    PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
    PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
    PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
using DLL_FUNC_TYPE(SymGetSymFromAddr64) = BOOL(__stdcall*)(
    IN HANDLE hProcess, IN DWORD64 qwAddr, OUT PDWORD64 pdwDisplacement,
    OUT PIMAGEHLP_SYMBOL64 Symbol);
using DLL_FUNC_TYPE(SymGetLineFromAddr64) =
    BOOL(__stdcall*)(IN HANDLE hProcess, IN DWORD64 qwAddr,
                     OUT PDWORD pdwDisplacement, OUT PIMAGEHLP_LINE64 Line64);
// DbgHelp.h typedefs. Implementation found in dbghelp.dll.
using DLL_FUNC_TYPE(SymFunctionTableAccess64) = PVOID(__stdcall*)(
    HANDLE hProcess,
    DWORD64 AddrBase);  // DbgHelp.h typedef PFUNCTION_TABLE_ACCESS_ROUTINE64
using DLL_FUNC_TYPE(SymGetModuleBase64) = DWORD64(__stdcall*)(
    HANDLE hProcess,
    DWORD64 AddrBase);  // DbgHelp.h typedef PGET_MODULE_BASE_ROUTINE64

// TlHelp32.h functions.
using DLL_FUNC_TYPE(CreateToolhelp32Snapshot) =
    HANDLE(__stdcall*)(DWORD dwFlags, DWORD th32ProcessID);
using DLL_FUNC_TYPE(Module32FirstW) = BOOL(__stdcall*)(HANDLE hSnapshot,
                                                       LPMODULEENTRY32W lpme);
using DLL_FUNC_TYPE(Module32NextW) = BOOL(__stdcall*)(HANDLE hSnapshot,
                                                      LPMODULEENTRY32W lpme);

#undef IN
#undef VOID

// Declare a variable for each dynamically loaded DLL function.
#define DEF_DLL_FUNCTION(name) DLL_FUNC_TYPE(name) DLL_FUNC_VAR(name) = nullptr;
DBGHELP_FUNCTION_LIST(DEF_DLL_FUNCTION)
TLHELP32_FUNCTION_LIST(DEF_DLL_FUNCTION)
#undef DEF_DLL_FUNCTION

// Load the functions. This function has a lot of "ugly" macros in order to
// keep down code duplication.

static bool LoadDbgHelpAndTlHelp32() {
  static bool dbghelp_loaded = false;

  if (dbghelp_loaded) return true;

  HMODULE module;

  // Load functions from the dbghelp.dll module.
  module = LoadLibrary(TEXT("dbghelp.dll"));
  if (module == nullptr) {
    return false;
  }

#define LOAD_DLL_FUNC(name)                                                 \
  DLL_FUNC_VAR(name) =                                                      \
      reinterpret_cast<DLL_FUNC_TYPE(name)>(GetProcAddress(module, #name));

DBGHELP_FUNCTION_LIST(LOAD_DLL_FUNC)

#undef LOAD_DLL_FUNC

  // Load functions from the kernel32.dll module (the TlHelp32.h function used
  // to be in tlhelp32.dll but are now moved to kernel32.dll).
  module = LoadLibrary(TEXT("kernel32.dll"));
  if (module == nullptr) {
    return false;
  }

#define LOAD_DLL_FUNC(name)                                                 \
  DLL_FUNC_VAR(name) =                                                      \
      reinterpret_cast<DLL_FUNC_TYPE(name)>(GetProcAddress(module, #name));

TLHELP32_FUNCTION_LIST(LOAD_DLL_FUNC)

#undef LOAD_DLL_FUNC

  // Check that all functions where loaded.
bool result =
#define DLL_FUNC_LOADED(name) (DLL_FUNC_VAR(name) != nullptr)&&

    DBGHELP_FUNCTION_LIST(DLL_FUNC_LOADED)
        TLHELP32_FUNCTION_LIST(DLL_FUNC_LOADED)

#undef DLL_FUNC_LOADED
            true;

  dbghelp_loaded = result;
  return result;
  // NOTE: The modules are never unloaded and will stay around until the
  // application is closed.
}

#undef DBGHELP_FUNCTION_LIST
#undef TLHELP32_FUNCTION_LIST
#undef DLL_FUNC_VAR
#undef DLL_FUNC_TYPE


// Load the symbols for generating stack traces.
static std::vector<OS::SharedLibraryAddress> LoadSymbols(
    HANDLE process_handle) {
  static std::vector<OS::SharedLibraryAddress> result;

  static bool symbols_loaded = false;

  if (symbols_loaded) return result;

  BOOL ok;

  // Initialize the symbol engine.
  ok = _SymInitialize(process_handle,  // hProcess
                      nullptr,         // UserSearchPath
                      false);          // fInvadeProcess
  if (!ok) return result;

  DWORD options = _SymGetOptions();
  options |= SYMOPT_LOAD_LINES;
  options |= SYMOPT_FAIL_CRITICAL_ERRORS;
  options = _SymSetOptions(options);

  char buf[OS::kStackWalkMaxNameLen] = {0};
  ok = _SymGetSearchPath(process_handle, buf, OS::kStackWalkMaxNameLen);
  if (!ok) {
    int err = GetLastError();
    OS::Print("%d\n", err);
    return result;
  }

  HANDLE snapshot = _CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE,       // dwFlags
      GetCurrentProcessId());  // th32ProcessId
  if (snapshot == INVALID_HANDLE_VALUE) return result;
  MODULEENTRY32W module_entry;
  module_entry.dwSize = sizeof(module_entry);  // Set the size of the structure.
  BOOL cont = _Module32FirstW(snapshot, &module_entry);
  while (cont) {
    DWORD64 base;
    // NOTE the SymLoadModule64 function has the peculiarity of accepting a
    // both unicode and ASCII strings even though the parameter is PSTR.
    base = _SymLoadModule64(
        process_handle,                                       // hProcess
        0,                                                    // hFile
        reinterpret_cast<PSTR>(module_entry.szExePath),       // ImageName
        reinterpret_cast<PSTR>(module_entry.szModule),        // ModuleName
        reinterpret_cast<DWORD64>(module_entry.modBaseAddr),  // BaseOfDll
        module_entry.modBaseSize);                            // SizeOfDll
    if (base == 0) {
      int err = GetLastError();
      if (err != ERROR_MOD_NOT_FOUND &&
          err != ERROR_INVALID_HANDLE) {
        result.clear();
        return result;
      }
    }
    int lib_name_length = WideCharToMultiByte(
        CP_UTF8, 0, module_entry.szExePath, -1, nullptr, 0, nullptr, nullptr);
    std::string lib_name(lib_name_length, 0);
    WideCharToMultiByte(CP_UTF8, 0, module_entry.szExePath, -1, &lib_name[0],
                        lib_name_length, nullptr, nullptr);
    result.push_back(OS::SharedLibraryAddress(
        lib_name, reinterpret_cast<uintptr_t>(module_entry.modBaseAddr),
        reinterpret_cast<uintptr_t>(module_entry.modBaseAddr +
                                    module_entry.modBaseSize)));
    cont = _Module32NextW(snapshot, &module_entry);
  }
  CloseHandle(snapshot);

  symbols_loaded = true;
  return result;
}


std::vector<OS::SharedLibraryAddress> OS::GetSharedLibraryAddresses() {
  // SharedLibraryEvents are logged when loading symbol information.
  // Only the shared libraries loaded at the time of the call to
  // GetSharedLibraryAddresses are logged.  DLLs loaded after
  // initialization are not accounted for.
  if (!LoadDbgHelpAndTlHelp32()) return std::vector<OS::SharedLibraryAddress>();
  HANDLE process_handle = GetCurrentProcess();
  return LoadSymbols(process_handle);
}

void OS::SignalCodeMovingGC() {}

#else  // __MINGW32__
std::vector<OS::SharedLibraryAddress> OS::GetSharedLibraryAddresses() {
  return std::vector<OS::SharedLibraryAddress>();
}

void OS::SignalCodeMovingGC() {}
#endif  // __MINGW32__


int OS::ActivationFrameAlignment() {
#ifdef _WIN64
  return 16;  // Windows 64-bit ABI requires the stack to be 16-byte aligned.
#elif defined(__MINGW32__)
  // With gcc 4.4 the tree vectorization optimizer can generate code
  // that requires 16 byte alignment such as movdqa on x86.
  return 16;
#else
  return 8;  // Floating-point math runs faster with 8-byte alignment.
#endif
}

#if defined(V8_OS_WIN)
void EnsureConsoleOutputWin32() {
  UINT new_flags =
      SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;
  UINT existing_flags = SetErrorMode(new_flags);
  SetErrorMode(existing_flags | new_flags);
#if defined(_MSC_VER)
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
  _set_error_mode(_OUT_TO_STDERR);
#endif  // defined(_MSC_VER)
}
#endif  // defined(V8_OS_WIN)

// ----------------------------------------------------------------------------
// Win32 thread support.

// Definition of invalid thread handle and id.
static const HANDLE kNoThread = INVALID_HANDLE_VALUE;

// Entry point for threads. The supplied argument is a pointer to the thread
// object. The entry function dispatches to the run method in the thread
// object. It is important that this function has __stdcall calling
// convention.
static unsigned int __stdcall ThreadEntry(void* arg) {
  Thread* thread = reinterpret_cast<Thread*>(arg);
  thread->NotifyStartedAndRun();
  return 0;
}


class Thread::PlatformData {
 public:
  explicit PlatformData(HANDLE thread) : thread_(thread) {}
  HANDLE thread_;
  unsigned thread_id_;
};


// Initialize a Win32 thread object. The thread has an invalid thread
// handle until it is started.

Thread::Thread(const Options& options)
    : stack_size_(options.stack_size()), start_semaphore_(nullptr) {
  data_ = new PlatformData(kNoThread);
  set_name(options.name());
}


void Thread::set_name(const char* name) {
  OS::StrNCpy(name_, sizeof(name_), name, strlen(name));
  name_[sizeof(name_) - 1] = '\0';
}


// Close our own handle for the thread.
Thread::~Thread() {
  if (data_->thread_ != kNoThread) CloseHandle(data_->thread_);
  delete data_;
}


// Create a new thread. It is important to use _beginthreadex() instead of
// the Win32 function CreateThread(), because the CreateThread() does not
// initialize thread specific structures in the C runtime library.
bool Thread::Start() {
  uintptr_t result = _beginthreadex(nullptr, static_cast<unsigned>(stack_size_),
                                    ThreadEntry, this, 0, &data_->thread_id_);
  data_->thread_ = reinterpret_cast<HANDLE>(result);
  return result != 0;
}

// Wait for thread to terminate.
void Thread::Join() {
  if (data_->thread_id_ != GetCurrentThreadId()) {
    WaitForSingleObject(data_->thread_, INFINITE);
  }
}


Thread::LocalStorageKey Thread::CreateThreadLocalKey() {
  DWORD result = TlsAlloc();
  DCHECK(result != TLS_OUT_OF_INDEXES);
  return static_cast<LocalStorageKey>(result);
}


void Thread::DeleteThreadLocalKey(LocalStorageKey key) {
  BOOL result = TlsFree(static_cast<DWORD>(key));
  USE(result);
  DCHECK(result);
}


void* Thread::GetThreadLocal(LocalStorageKey key) {
  return TlsGetValue(static_cast<DWORD>(key));
}


void Thread::SetThreadLocal(LocalStorageKey key, void* value) {
  BOOL result = TlsSetValue(static_cast<DWORD>(key), value);
  USE(result);
  DCHECK(result);
}

void OS::AdjustSchedulingParams() {}

std::optional<OS::MemoryRange> OS::GetFirstFreeMemoryRangeWithin(
    OS::Address boundary_start, OS::Address boundary_end, size_t minimum_size,
    size_t alignment) {
  // Search for the virtual memory (vm) ranges within the boundary.
  // If a range is free and larger than {minimum_size}, then push it to the
  // returned vector.
  uintptr_t vm_start = RoundUp(boundary_start, alignment);
  uintptr_t vm_end = 0;
  MEMORY_BASIC_INFORMATION mi;
  // This loop will terminate once the scanning reaches the higher address
  // to the end of boundary or the function VirtualQuery fails.
  while (vm_start < boundary_end &&
         VirtualQuery(reinterpret_cast<LPCVOID>(vm_start), &mi, sizeof(mi)) !=
             0) {
    vm_start = reinterpret_cast<uintptr_t>(mi.BaseAddress);
    vm_end = vm_start + mi.RegionSize;
    if (mi.State == MEM_FREE) {
      // The available area is the overlap of the virtual memory range and
      // boundary. Push the overlapped memory range to the vector if there is
      // enough space.
      const uintptr_t overlap_start =
          RoundUp(std::max(vm_start, boundary_start), alignment);
      const uintptr_t overlap_end =
          RoundDown(std::min(vm_end, boundary_end), alignment);
      if (overlap_start < overlap_end &&
          overlap_end - overlap_start >= minimum_size) {
        return OS::MemoryRange{overlap_start, overlap_end};
      }
    }
    // Continue to visit the next virtual memory range.
    vm_start = vm_end;
  }

  return {};
}

// static
Stack::StackSlot Stack::ObtainCurrentThreadStackStart() {
#if defined(V8_TARGET_ARCH_X64)
  return reinterpret_cast<void*>(
      reinterpret_cast<NT_TIB64*>(NtCurrentTeb())->StackBase);
#elif defined(V8_TARGET_ARCH_32_BIT)
  return reinterpret_cast<void*>(
      reinterpret_cast<NT_TIB*>(NtCurrentTeb())->StackBase);
#elif defined(V8_TARGET_ARCH_ARM64)
  // Windows 8 and later, see
  // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadstacklimits
  ULONG_PTR lowLimit, highLimit;
  ::GetCurrentThreadStackLimits(&lowLimit, &highLimit);
  return reinterpret_cast<void*>(highLimit);
#else
#error Unsupported ObtainCurrentThreadStackStart.
#endif
}

// static
Stack::StackSlot Stack::GetCurrentStackPosition() {
#if V8_CC_MSVC
  return _AddressOfReturnAddress();
#else
  return __builtin_frame_address(0);
#endif
}

}  // namespace base
}  // namespace v8

"""


```