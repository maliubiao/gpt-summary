Response:
Let's break down the thought process for analyzing this C code. The goal is to understand its functionality, its relation to reverse engineering, its low-level aspects, potential logic, common errors, and how a user might reach this code.

**1. Initial Code Scan and High-Level Understanding:**

* **File Name:** `gummemory-windows.c` immediately tells us this file is about memory management and is specific to Windows.
* **Includes:**  `gummemory.h`, `gummemory-priv.h`, `gum/gumwindows.h`, `<stdlib.h>`. These suggest the file interacts with a larger memory management system (`gummemory`), has private implementation details (`gummemory-priv`), uses Windows-specific types and functions (`gumwindows.h`), and uses standard library functions.
* **Function Prefixes:**  Functions like `gum_memory_*` and `_gum_memory_*` indicate this is part of a structured memory management module. The underscore likely signifies internal or backend functions.
* **Windows API Calls:**  We see calls like `GetSystemInfo`, `ReadProcessMemory`, `WriteProcessMemory`, `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `FlushInstructionCache`, `GetProcAddress`, `GetModuleHandleW`, `VirtualQuery`. These are core Windows memory management APIs.

**2. Functionality Breakdown (Iterating through Functions):**

I'd go through each function and try to understand its purpose. Here's a simplified version of that process:

* `_gum_memory_backend_init`, `_gum_memory_backend_deinit`: Initialization and cleanup for the Windows memory backend. Likely empty in this specific file, as the core initialization is handled elsewhere.
* `_gum_memory_backend_query_page_size`:  Uses `GetSystemInfo` to get the system's page size. Fundamental for memory management.
* `gum_memory_is_readable`: Checks if memory is readable using `gum_memory_get_protection`.
* `gum_memory_query_protection`: Gets the memory protection attributes of a single byte using `gum_memory_get_protection`.
* `gum_memory_read`: Reads memory using `ReadProcessMemory`. Handles partial reads across page boundaries. This is crucial for inspecting process memory.
* `gum_memory_write`: Writes memory using `WriteProcessMemory`. Essential for modifying process memory.
* `gum_try_mprotect`: Changes memory protection using `VirtualProtect`. This is key for techniques like hooking and code patching.
* `gum_clear_cache`: Flushes the instruction cache using `FlushInstructionCache`. Important after modifying code in memory to ensure the CPU sees the changes.
* `gum_try_alloc_n_pages`, `gum_try_alloc_n_pages_near`:  Tries to allocate contiguous pages of memory using `gum_memory_allocate_near`.
* `gum_query_page_allocation_range`:  Simply returns the base address and size of an allocated block.
* `gum_free_pages`:  Releases allocated memory using `VirtualFree`.
* `gum_memory_allocate`: Allocates memory, trying to align it to a specific boundary. Handles cases where the initial allocation isn't aligned correctly.
* `gum_memory_allocate_near`: Tries to allocate memory near a specified address. This is useful for code injection and proximity-based techniques.
* `gum_virtual_alloc`:  A helper function for `VirtualAlloc`, trying a specific address first, then letting the system choose.
* `gum_memory_free`, `gum_memory_release`, `gum_memory_recommit`, `gum_memory_discard`, `gum_memory_decommit`: Various functions for managing allocated memory with different Windows API calls (releasing, decommitting, discarding).
* `gum_memory_get_protection`:  The core function for getting memory protection attributes using `VirtualQuery`. Handles cases spanning multiple pages.
* `gum_page_protection_from_windows`, `gum_page_protection_to_windows`:  Convert between Windows protection flags and the Gum's internal `GumPageProtection` enum.

**3. Connecting to Reverse Engineering:**

As I analyze the functions, I'd be constantly thinking, "How does this relate to reverse engineering?"  The keywords that pop out are:

* **Reading memory:** Inspecting data structures, code, etc.
* **Writing memory:** Patching code, modifying data.
* **Changing memory protection:** Making code writable for patching, making data executable for code injection.
* **Allocating memory:** Injecting new code or data.
* **Near allocation:** Facilitating code injection in close proximity to existing code.

**4. Identifying Low-Level Aspects:**

The use of:

* Windows API calls for memory management.
* Pointers and memory addresses.
* Page sizes and alignment.
* Memory protection attributes (read, write, execute).
* Instruction cache flushing.

clearly points to low-level interactions with the operating system's memory management. Even though the code itself isn't directly interacting with the *kernel*, it's using the *kernel's* APIs to manage process memory.

**5. Looking for Logic and Potential Inputs/Outputs:**

For functions with more complex logic, like `gum_memory_read`, `gum_memory_allocate`, and `gum_memory_allocate_near`, I'd mentally trace the code flow:

* **`gum_memory_read`:** Input: address, length. Output: allocated buffer with data, number of bytes read. Handles potential partial reads.
* **`gum_memory_allocate`:** Input: optional address, size, alignment, protection. Output: allocated memory address (or NULL). The retry logic for alignment is a key piece of logic.
* **`gum_memory_allocate_near`:** Input: address spec (near address, max distance), size, alignment, protection. Output: allocated memory address near the target (or NULL). The iterative search for a suitable address is the core logic here.

**6. Considering User Errors:**

I'd think about common mistakes a *developer using this library* might make:

* Incorrectly specifying memory protection flags.
* Trying to read or write memory outside of allocated regions.
* Forgetting to flush the instruction cache after modifying code.
* Not checking for NULL returns from allocation functions.
* Issues with alignment.

**7. Tracing User Operations (Debugging Perspective):**

I'd imagine a scenario where a Frida user wants to instrument a Windows process:

1. **User writes a Frida script:** This script uses Frida's JavaScript API.
2. **Frida's JavaScript engine:**  Executes the script.
3. **Script calls Frida functions:**  For example, `Memory.readByteArray()`, `Memory.writeByteArray()`, `Memory.protect()`, `Memory.alloc()`.
4. **Frida's core:**  Receives these requests and needs to implement them on the target Windows process.
5. **`gum` layer:** Frida uses `gum` as its instrumentation library. The JavaScript API calls translate to `gum` function calls.
6. **`gummemory-windows.c`:**  The `gum` library, specifically for Windows, uses this file to perform the actual memory operations by calling the Windows API.

Therefore, a user's high-level action (like reading memory via a Frida script) eventually leads down to the low-level Windows API calls within `gummemory-windows.c`.

**Self-Correction/Refinement:**

Initially, I might just list the functions and their direct API calls. However, to provide a more complete answer, I'd need to:

* **Synthesize the information:** Group related functions by their broader purpose (allocation, reading, writing, protection).
* **Explain the *why*:** Not just *what* the code does, but *why* it's doing it in the context of dynamic instrumentation and reverse engineering.
* **Provide concrete examples:** Illustrate the concepts with specific scenarios.
* **Consider the user's perspective:** Explain how someone using Frida would indirectly interact with this code.

This iterative process of reading, analyzing, connecting to the core problem (dynamic instrumentation), and refining the explanation leads to a comprehensive understanding of the code.
好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/backend-windows/gummemory-windows.c` 这个文件。这是一个 Frida 的组件，负责在 Windows 平台上进行内存管理操作。

**文件功能概览:**

这个 C 文件实现了 Frida Gum 库在 Windows 后端的内存管理功能。它封装了 Windows 平台的内存管理 API，并提供了 Frida Gum 需要的抽象接口，例如内存的分配、释放、读写、权限修改等。其核心目标是为 Frida 提供的动态插桩能力打下基础，使得 Frida 可以在目标进程中操作内存。

**与逆向方法的关联及举例说明:**

这个文件中的功能与逆向工程息息相关，因为逆向分析经常需要读取、修改目标进程的内存来理解其行为或进行破解。

* **内存读取 (`gum_memory_read`)**:
    * **功能**: 允许 Frida 读取目标进程指定地址的内存数据。
    * **逆向举例**:  逆向工程师可以使用 Frida 脚本，调用 `Memory.readByteArray(address, length)`，最终会调用到这里的 `gum_memory_read` 函数，来读取目标进程中某个变量的值，例如游戏中的生命值、金币数量，或者读取函数的指令来分析其逻辑。
    * **用户操作**: 用户编写 Frida 脚本，使用 `Memory.readByteArray(0xXXXXXXXX, 100)`，指定要读取的内存地址和长度。

* **内存写入 (`gum_memory_write`)**:
    * **功能**: 允许 Frida 向目标进程的指定地址写入数据。
    * **逆向举例**: 逆向工程师可以使用 Frida 脚本，调用 `Memory.writeByteArray(address, bytes)`，最终调用到 `gum_memory_write`，来修改目标进程的内存，例如修改游戏中的生命值，跳过某些安全检查，或者修改函数的返回值。
    * **用户操作**: 用户编写 Frida 脚本，使用 `Memory.writeByteArray(0xXXXXXXXX, [0x90, 0x90])`，向指定地址写入 NOP 指令。

* **修改内存保护属性 (`gum_try_mprotect`)**:
    * **功能**: 允许 Frida 修改目标进程内存页的保护属性（例如，从只读修改为可读写执行）。
    * **逆向举例**: 当需要修改目标进程的代码时，例如进行 Hook 操作，通常需要先将代码所在的内存页修改为可写。Frida 的 `Interceptor` API 底层会使用到这个功能。
    * **用户操作**: Frida 脚本中使用 `Memory.protect(address, size, 'rwx')`，将指定地址和大小的内存区域设置为可读、可写、可执行。

* **内存分配 (`gum_memory_allocate`, `gum_memory_allocate_near`)**:
    * **功能**: 允许 Frida 在目标进程中分配新的内存空间。`gum_memory_allocate_near` 尝试在指定地址附近分配内存。
    * **逆向举例**: 进行代码注入时，需要在目标进程中分配一块新的内存来存放注入的代码。
    * **用户操作**: Frida 脚本中使用 `Memory.alloc(size)` 或 `Memory.allocNear(address, size)` 来分配内存。

* **清除指令缓存 (`gum_clear_cache`)**:
    * **功能**: 在修改了内存中的代码后，需要清除 CPU 的指令缓存，以确保 CPU 执行的是修改后的代码。
    * **逆向举例**: 在使用 Frida Hook 修改了函数指令后，必须调用这个函数来同步缓存。
    * **用户操作**: Frida 内部在进行代码修改后会自动调用，用户一般不需要直接操作。

* **查询内存保护属性 (`gum_memory_query_protection`, `gum_memory_get_protection`)**:
    * **功能**: 允许 Frida 查询指定内存地址的保护属性。
    * **逆向举例**: 在进行内存操作前，可能需要先查询内存的保护属性，以避免访问受保护的内存区域导致程序崩溃。
    * **用户操作**: 用户可以通过 Frida 脚本使用 `Process.getModuleByAddress(address).findMemoryRanges('rwx')` 等方法间接触发。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然这个文件是针对 Windows 平台的，但其设计思想和某些概念在其他平台上也有共通之处。

* **二进制底层知识**:
    * **内存地址**: 文件中大量使用了指针 (`gpointer`) 和内存地址，这是理解二进制程序运行的基础。
    * **内存页 (Page)**:  很多操作（如 `gum_try_mprotect`）是以内存页为单位进行的。`_gum_memory_backend_query_page_size` 获取系统页大小。
    * **内存保护属性 (Read, Write, Execute)**:  文件中的 `GumPageProtection` 枚举和 Windows 的 `PAGE_*` 常量直接对应于操作系统提供的内存保护机制。
    * **指令缓存 (Instruction Cache)**: `gum_clear_cache` 函数直接操作了 CPU 的指令缓存，这是底层 CPU 架构相关的知识。
    * **Windows API**:  代码大量使用了 Windows 内存管理 API，如 `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, `ReadProcessMemory`, `WriteProcessMemory` 等。

* **与 Linux 和 Android 的对比**:
    * **内存管理抽象**: 虽然具体的 API 不同，但 Linux 和 Android 也有类似的内存管理概念和功能，例如 `mmap`, `munmap`, `mprotect` 等。Frida Gum 的设计目标是在不同平台上提供统一的内存管理接口。
    * **页大小**: Linux 和 Android 也有页的概念，可以使用 `getpagesize()` 获取。
    * **内存保护标志**:  Linux 和 Android 使用 `PROT_READ`, `PROT_WRITE`, `PROT_EXEC` 等标志。
    * **指令缓存同步**: Linux 上可以使用 `syscall(SYS_cacheflush, ...)` 或类似的系统调用来同步缓存。Android 内核也提供类似机制。

**逻辑推理、假设输入与输出:**

以下是一些函数的逻辑推理和假设输入输出：

* **`gum_memory_is_readable(address, len)`**:
    * **假设输入**: `address = 0x00401000`, `len = 10`
    * **逻辑**: 调用 `gum_memory_get_protection` 获取该地址范围的内存保护属性，如果包含 `GUM_PAGE_READ`，则返回 `TRUE`，否则返回 `FALSE`。
    * **可能的输出**: `TRUE` 或 `FALSE`，取决于 `0x00401000` 开始的 10 字节内存是否可读。

* **`gum_memory_read(address, len, n_bytes_read)`**:
    * **假设输入**: `address = 0x00402000`, `len = 5`, `n_bytes_read = NULL`
    * **逻辑**: 分配 `len` 大小的内存，然后调用 `ReadProcessMemory` 从目标进程读取数据到分配的内存中。
    * **可能的输出**: 返回一个包含从 `0x00402000` 读取的 5 字节数据的 `guint8 *` 指针。

* **`gum_try_mprotect(address, size, prot)`**:
    * **假设输入**: `address = 0x00403000`, `size = 4096`, `prot = GUM_PAGE_RWX`
    * **逻辑**: 将 `GumPageProtection` 转换为 Windows 的保护属性 (`PAGE_EXECUTE_READWRITE`)，然后调用 `VirtualProtect` 修改内存保护属性。
    * **可能的输出**: `TRUE` (修改成功) 或 `FALSE` (修改失败)。

**涉及用户或者编程常见的使用错误及举例说明:**

* **尝试读写未映射或无权限的内存**:
    * **错误**: 用户使用 Frida 脚本读取或写入一个无效的内存地址，或者对只读内存进行写操作。
    * **后果**:  可能导致目标进程崩溃，或者 Frida 报告错误。
    * **用户操作**: `Memory.readByteArray(0x12345, 10)`，但 `0x12345` 是一个未分配或无权限访问的地址。

* **修改内存保护属性失败**:
    * **错误**: 用户尝试修改某些关键系统内存区域的保护属性，或者由于权限不足导致修改失败。
    * **后果**: `gum_try_mprotect` 返回 `FALSE`，后续的内存操作可能会失败。
    * **用户操作**: 尝试修改系统 DLL 的内存保护属性。

* **忘记清除指令缓存**:
    * **错误**: 在修改了目标进程的代码后，没有调用或 Frida 内部没有正确调用 `gum_clear_cache`。
    * **后果**: CPU 仍然执行旧的指令缓存，导致代码修改没有生效或者行为异常。
    * **用户场景**:  虽然用户通常不直接调用，但如果 Frida 的某些内部逻辑出现问题，可能会发生这种情况。

* **内存分配失败**:
    * **错误**:  尝试分配过大的内存块，或者目标进程的内存空间不足。
    * **后果**: `gum_memory_allocate` 或 `gum_memory_allocate_near` 返回 `NULL`，导致后续依赖于分配内存的操作失败。
    * **用户操作**: `Memory.alloc(1024 * 1024 * 1024 * 10)` 尝试分配 10GB 的内存。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本**: 用户使用 Frida 的 JavaScript API 编写脚本，例如需要读取目标进程的某个变量的值。
   ```javascript
   let address = Module.getBaseAddress("target_process.exe").add(0x1000);
   let value = Memory.readU32(address);
   console.log("Value:", value);
   ```

2. **Frida 脚本引擎执行**: Frida 的 JavaScript 引擎执行这段脚本。

3. **调用 Frida 的 `Memory` API**: `Memory.readU32(address)` 被调用。

4. **`Memory.readU32` 映射到 Gum 层的调用**: Frida 的 JavaScript API 会映射到其 Native 代码层，最终会调用到 Gum 库的相应函数，例如 `gum_memory_read` 的包装函数。

5. **到达 `gummemory-windows.c`**: 如果目标进程运行在 Windows 上，并且 Frida 使用了 Windows 后端，那么最终会调用到 `frida/subprojects/frida-gum/gum/backend-windows/gummemory-windows.c` 文件中的 `gum_memory_read` 函数。

6. **调用 Windows API**: `gum_memory_read` 函数内部会调用 Windows 的 `ReadProcessMemory` API 来实际读取目标进程的内存。

**调试线索**:

当在 Frida 调试内存相关问题时，可以关注以下线索：

* **Frida 脚本的错误信息**: Frida 可能会报告内存访问错误。
* **目标进程的崩溃信息**: 如果操作不当，可能会导致目标进程崩溃。
* **使用 Frida 的调试功能**:  Frida 提供了 `DebugSymbol` 等 API 可以帮助分析内存布局。
* **查看 Frida Gum 的日志**:  如果 Frida 以调试模式运行，可能会输出更详细的 Gum 库的日志信息。
* **使用 Windows 的调试工具**: 例如 WinDbg，可以附加到目标进程，观察内存状态和 API 调用。

总而言之，`gummemory-windows.c` 是 Frida 在 Windows 平台上实现核心内存操作的关键组件，它封装了底层的 Windows API，并为 Frida 的高级功能提供了基础支持，这对于动态插桩和逆向工程至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-windows/gummemory-windows.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "gum/gumwindows.h"

#include <stdlib.h>

static gpointer gum_virtual_alloc (gpointer address, gsize size,
    DWORD allocation_type, DWORD page_protection);
static gboolean gum_memory_get_protection (gconstpointer address, gsize len,
    GumPageProtection * prot);

void
_gum_memory_backend_init (void)
{
}

void
_gum_memory_backend_deinit (void)
{
}

guint
_gum_memory_backend_query_page_size (void)
{
  SYSTEM_INFO si;

  GetSystemInfo (&si);

  return si.dwPageSize;
}

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &prot))
    return FALSE;

  return (prot & GUM_PAGE_READ) != 0;
}

gboolean
gum_memory_query_protection (gconstpointer address,
                             GumPageProtection * prot)
{
  return gum_memory_get_protection (address, 1, prot);
}

guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint8 * result;
  gsize offset;
  HANDLE self;
  gsize page_size;

  result = g_malloc (len);
  offset = 0;

  self = GetCurrentProcess ();
  page_size = gum_query_page_size ();

  while (offset != len)
  {
    const guint8 * chunk_address, * page_address;
    gsize page_offset, chunk_size;
    SIZE_T n;
    BOOL success;

    chunk_address = (const guint8 *) address + offset;
    page_address = GSIZE_TO_POINTER (
        GPOINTER_TO_SIZE (chunk_address) & ~(page_size - 1));
    page_offset = chunk_address - page_address;
    chunk_size = MIN (len - offset, page_size - page_offset);

    success = ReadProcessMemory (self, chunk_address, result + offset,
        chunk_size, &n);
    if (!success)
      break;
    offset += n;
  }

  if (offset == 0)
  {
    g_free (result);
    result = NULL;
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = offset;

  return result;
}

gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  return WriteProcessMemory (GetCurrentProcess (), address, bytes, len, NULL);
}

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection prot)
{
  DWORD win_prot, old_protect;

  win_prot = gum_page_protection_to_windows (prot);

  return VirtualProtect (address, size, win_prot, &old_protect);
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
  FlushInstructionCache (GetCurrentProcess (), address, size);
}

gpointer
gum_try_alloc_n_pages (guint n_pages,
                       GumPageProtection prot)
{
  return gum_try_alloc_n_pages_near (n_pages, prot, NULL);
}

gpointer
gum_try_alloc_n_pages_near (guint n_pages,
                            GumPageProtection prot,
                            const GumAddressSpec * spec)
{
  gpointer result;
  gsize page_size, size;

  page_size = gum_query_page_size ();
  size = n_pages * page_size;

  result = gum_memory_allocate_near (spec, size, page_size, prot);
  if (result != NULL && prot == GUM_PAGE_NO_ACCESS)
  {
    gum_memory_recommit (result, size, prot);
  }

  return result;
}

void
gum_query_page_allocation_range (gconstpointer mem,
                                 guint size,
                                 GumMemoryRange * range)
{
  range->base_address = GUM_ADDRESS (mem);
  range->size = size;
}

void
gum_free_pages (gpointer mem)
{
  BOOL success G_GNUC_UNUSED;

  success = VirtualFree (mem, 0, MEM_RELEASE);
  g_assert (success);
}

gpointer
gum_memory_allocate (gpointer address,
                     gsize size,
                     gsize alignment,
                     GumPageProtection prot)
{
  DWORD allocation_type, win_prot;
  gpointer base, aligned_base;
  gsize padded_size;
  gint retries = 3;

  allocation_type = (prot == GUM_PAGE_NO_ACCESS)
      ? MEM_RESERVE
      : MEM_RESERVE | MEM_COMMIT;

  win_prot = gum_page_protection_to_windows (prot);

  base = gum_virtual_alloc (address, size, allocation_type, win_prot);
  if (base == NULL)
    return NULL;

  aligned_base = GUM_ALIGN_POINTER (gpointer, base, alignment);
  if (aligned_base == base)
    return base;

  gum_memory_free (base, size);
  base = NULL;
  aligned_base = NULL;
  address = NULL;

  padded_size = size + (alignment - gum_query_page_size ());

  while (retries-- != 0)
  {
    base = gum_virtual_alloc (address, padded_size, allocation_type, win_prot);
    if (base == NULL)
      return NULL;

    gum_memory_free (base, padded_size);
    aligned_base = GUM_ALIGN_POINTER (gpointer, base, alignment);
    base = VirtualAlloc (aligned_base, size, allocation_type, win_prot);
    if (base != NULL)
      break;
  }

  return base;
}

gpointer
gum_memory_allocate_near (const GumAddressSpec * spec,
                          gsize size,
                          gsize alignment,
                          GumPageProtection prot)
{
  gpointer result = NULL;
  gsize page_size, step_size;
  DWORD win_prot;
  guint8 * low_address, * high_address;

  result = gum_memory_allocate (NULL, size, alignment, prot);
  if (result == NULL)
    return NULL;
  if (spec == NULL || gum_address_spec_is_satisfied_by (spec, result))
    return result;
  gum_memory_free (result, size);

  page_size = gum_query_page_size ();
  step_size = MAX (page_size, GUM_ALIGN_SIZE (alignment, page_size));
  win_prot = gum_page_protection_to_windows (prot);

  low_address = GSIZE_TO_POINTER (
      (GPOINTER_TO_SIZE (spec->near_address) & ~(step_size - 1)));
  high_address = low_address;

  do
  {
    gsize cur_distance;

    low_address -= step_size;
    high_address += step_size;
    cur_distance = (gsize) high_address - (gsize) spec->near_address;
    if (cur_distance > spec->max_distance)
      break;

    result = VirtualAlloc (low_address, size, MEM_COMMIT | MEM_RESERVE,
        win_prot);
    if (result == NULL)
    {
      result = VirtualAlloc (high_address, size, MEM_COMMIT | MEM_RESERVE,
          win_prot);
    }
  }
  while (result == NULL);

  return result;
}

static gpointer
gum_virtual_alloc (gpointer address,
                   gsize size,
                   DWORD allocation_type,
                   DWORD page_protection)
{
  gpointer result = NULL;

  if (address != NULL)
  {
    result = VirtualAlloc (address, size, allocation_type, page_protection);
  }

  if (result == NULL)
  {
    result = VirtualAlloc (NULL, size, allocation_type, page_protection);
  }

  return result;
}

gboolean
gum_memory_free (gpointer address,
                 gsize size)
{
  return VirtualFree (address, 0, MEM_RELEASE);
}

gboolean
gum_memory_release (gpointer address,
                    gsize size)
{
  return VirtualFree (address, size, MEM_DECOMMIT);
}

gboolean
gum_memory_recommit (gpointer address,
                     gsize size,
                     GumPageProtection prot)
{
  return VirtualAlloc (address, size, MEM_COMMIT,
      gum_page_protection_to_windows (prot)) != NULL;
}

gboolean
gum_memory_discard (gpointer address,
                    gsize size)
{
  static gboolean initialized = FALSE;
  static DWORD (WINAPI * discard_impl) (PVOID address, SIZE_T size);

  if (!initialized)
  {
    discard_impl = GUM_POINTER_TO_FUNCPTR (DWORD (WINAPI *) (PVOID, SIZE_T),
        GetProcAddress (GetModuleHandleW (L"kernel32.dll"),
          "DiscardVirtualMemory"));
    initialized = TRUE;
  }

  if (discard_impl != NULL)
  {
    if (discard_impl (address, size) == ERROR_SUCCESS)
      return TRUE;
  }

  return VirtualAlloc (address, size, MEM_RESET, PAGE_READWRITE) != NULL;
}

gboolean
gum_memory_decommit (gpointer address,
                     gsize size)
{
  return VirtualFree (address, size, MEM_DECOMMIT);
}

static gboolean
gum_memory_get_protection (gconstpointer address,
                           gsize len,
                           GumPageProtection * prot)
{
  gboolean success = FALSE;
  MEMORY_BASIC_INFORMATION mbi;

  if (prot == NULL)
  {
    GumPageProtection ignored_prot;

    return gum_memory_get_protection (address, len, &ignored_prot);
  }

  *prot = GUM_PAGE_NO_ACCESS;

  if (len > 1)
  {
    gsize page_size, start_page, end_page, cur_page;

    page_size = gum_query_page_size ();

    start_page = GPOINTER_TO_SIZE (address) & ~(page_size - 1);
    end_page = (GPOINTER_TO_SIZE (address) + len - 1) & ~(page_size - 1);

    success = gum_memory_get_protection (GSIZE_TO_POINTER (start_page), 1,
        prot);

    for (cur_page = start_page + page_size;
        cur_page != end_page + page_size;
        cur_page += page_size)
    {
      GumPageProtection cur_prot;

      if (gum_memory_get_protection (GSIZE_TO_POINTER (cur_page), 1, &cur_prot))
      {
        success = TRUE;
        *prot &= cur_prot;
      }
      else
      {
        *prot = GUM_PAGE_NO_ACCESS;
        break;
      }
    }

    return success;
  }

  success = VirtualQuery (address, &mbi, sizeof (mbi)) != 0;
  if (success)
    *prot = gum_page_protection_from_windows (mbi.Protect);

  return success;
}

GumPageProtection
gum_page_protection_from_windows (DWORD native_prot)
{
  switch (native_prot & 0xff)
  {
    case PAGE_NOACCESS:
      return GUM_PAGE_NO_ACCESS;
    case PAGE_READONLY:
      return GUM_PAGE_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
      return GUM_PAGE_RW;
    case PAGE_EXECUTE:
      return GUM_PAGE_EXECUTE;
    case PAGE_EXECUTE_READ:
      return GUM_PAGE_RX;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return GUM_PAGE_RWX;
  }

  g_assert_not_reached ();
}

DWORD
gum_page_protection_to_windows (GumPageProtection prot)
{
  switch (prot)
  {
    case GUM_PAGE_NO_ACCESS:
      return PAGE_NOACCESS;
    case GUM_PAGE_READ:
      return PAGE_READONLY;
    case GUM_PAGE_READ | GUM_PAGE_WRITE:
      return PAGE_READWRITE;
    case GUM_PAGE_READ | GUM_PAGE_EXECUTE:
      return PAGE_EXECUTE_READ;
    case GUM_PAGE_EXECUTE | GUM_PAGE_READ | GUM_PAGE_WRITE:
      return PAGE_EXECUTE_READWRITE;
  }

#ifndef G_DISABLE_ASSERT
  g_assert_not_reached ();
#else
  abort ();
#endif
}
```