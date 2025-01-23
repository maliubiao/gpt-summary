Response:
Let's break down the thought process for analyzing this C code.

**1. Initial Understanding of the Context:**

The prompt clearly states this is a source file (`gummemory-qnx.c`) within the Frida project. Frida is a dynamic instrumentation toolkit. The file path `frida/subprojects/frida-gum/gum/backend-qnx/` gives crucial information:

*   `frida`: Top-level Frida project.
*   `subprojects/frida-gum`: Likely the "Gum" component, which handles low-level interaction with the target process's memory.
*   `backend-qnx`:  Specifically for the QNX operating system. This is a key detail – the code will contain QNX-specific system calls and structures.
*   `gummemory-qnx.c`:  Deals with memory operations.

Therefore, the primary purpose of this file is to provide Frida's Gum component with the ability to interact with a target process's memory on QNX.

**2. Core Functionality Identification (High-Level):**

Quickly scanning the function names reveals the core operations:

*   `gum_memory_is_readable`, `gum_memory_is_writable`: Checking memory access permissions.
*   `gum_memory_query_protection`: Getting the protection flags of a memory region.
*   `gum_memory_read`, `gum_memory_write`: Reading and writing memory.
*   `gum_try_mprotect`: Changing memory protection (like `mprotect` but with Frida-specific logic).
*   `gum_clear_cache`:  Invalidating CPU caches.
*   `gum_memory_get_protection`:  The underlying function for getting memory protection information.
*   `_gum_page_protection_from_posix`: Converting POSIX protection flags to Frida's internal representation.

**3. Deep Dive into Key Functions and Concepts:**

Now, let's examine some of the crucial functions in more detail and connect them to the prompt's requirements:

*   **`/proc/self/as`:** The use of `/proc/self/as` for reading and writing memory immediately signals interaction with the target process's address space. This is a common technique in debugging and instrumentation tools on Unix-like systems (including QNX). This links directly to "binary底层" concepts.

*   **`open`, `lseek`, `read`, `write`:** Standard Unix system calls for file I/O are used to access the `/proc/self/as` file. This reinforces the "binary底层" aspect.

*   **`mprotect`:**  This is a fundamental system call for changing memory protection. The code around it reveals Frida's attempt to handle cases where simply calling `mprotect` might fail (specifically, when trying to make a read-only page writable).

*   **`ThreadCtl(_NTO_TCTL_THREADS_HOLD, ...)` and `ThreadCtl(_NTO_TCTL_THREADS_CONT, ...)`:** These are QNX-specific system calls for holding and resuming threads. This highlights the "QNX内核" dependence. The reason for this becomes clear when considering the workaround for `mprotect` failures: by holding threads, Frida ensures no other thread interferes during the memory remapping process.

*   **`mmap` with `MAP_FIXED`:**  The use of `mmap` with `MAP_FIXED` is a technique to map a memory region at a *specific* address. This is crucial for Frida to inject code or modify existing code. This relates to "binary底层" and "逆向的方法" (code injection).

*   **`devctl(fd, DCMD_PROC_PAGEDATA, ...)`:** This QNX-specific system call is used to retrieve memory map information (`procfs_mapinfo`). This is how Frida obtains the protection flags of memory regions and aligns with "QNX内核" knowledge.

*   **Page Alignment:** The code frequently performs bitwise operations (`& ~(page_size - 1)`) to align addresses to page boundaries. This is essential when working with memory protection and mapping, a core concept in operating system memory management ("binary底层", "linux内核").

*   **`GumPageProtection`:** This is Frida's internal representation of memory protection flags, showing an abstraction layer over the underlying OS flags.

**4. Connecting to Prompt Requirements:**

Now, specifically address each point in the prompt:

*   **功能 (Functions):**  List the high-level functions identified in step 2, briefly describing their purpose.

*   **与逆向的方法的关系 (Relationship to Reversing):** Focus on the `gum_memory_read`, `gum_memory_write`, and `gum_try_mprotect` functions. Explain how these allow Frida to inspect and modify the target process's memory, which are fundamental operations in dynamic analysis and reverse engineering. Give concrete examples, like reading function arguments or patching code.

*   **涉及到的二进制底层, linux, android内核及框架的知识 (Binary, Linux, Android Kernel/Framework):**
    *   **Binary:**  Emphasize the direct manipulation of memory, address spaces, and the use of `/proc/self/as`.
    *   **Linux:** While this code is QNX-specific, mention that the general concepts of memory protection, `/proc` filesystem (even if the details differ), and `mprotect` are common in Linux.
    *   **Android Kernel/Framework:** Explicitly state that this code is *not* directly related to Android, as it targets QNX. However, acknowledge that the *concepts* of dynamic instrumentation and memory manipulation are applicable to Android (though the implementation would be different).

*   **如果做了逻辑推理，请给出假设输入与输出 (Logical Reasoning, Input/Output):**  Select a function like `gum_memory_is_readable` or `gum_memory_get_protection` and create a simple scenario. Define the input (an address and length) and predict the output (TRUE/FALSE or the protection flags) based on the code's logic.

*   **如果涉及用户或者编程常见的使用错误，请举例说明 (User/Programming Errors):**  Think about how someone using the Frida API (which uses these lower-level functions) might make mistakes. Examples include trying to write to read-only memory, providing incorrect sizes, or assuming memory layouts.

*   **说明用户操作是如何一步步的到达这里，作为调试线索 (User Steps to Reach This Code):**  Trace back from the low-level `gummemory-qnx.c` file to higher-level Frida API calls. Describe a typical Frida workflow: attaching to a process, finding an address, and then using Frida's `readByteArray`, `writeByteArray`, or code modification functions. Explain how these actions ultimately lead to the execution of the functions in this C file.

**5. Refinement and Clarity:**

Finally, review the generated explanation for clarity, accuracy, and completeness. Ensure that the language is precise and that the examples are easy to understand. For instance, when explaining the `mprotect` workaround, clarify why holding threads is necessary.

By following this structured approach, we can systematically analyze the C code and generate a comprehensive explanation that addresses all aspects of the prompt. The key is to understand the code's purpose within the larger Frida context and to connect the specific implementation details to the broader concepts of operating systems, memory management, and reverse engineering.
这个文件 `gummemory-qnx.c` 是 Frida 工具中用于在 QNX 操作系统上进行内存操作的后端实现。它提供了 Frida 在目标进程中读取、写入和修改内存的能力。以下是该文件的功能及其与逆向、底层知识、逻辑推理和常见错误的关系：

**功能列表:**

1. **`gum_memory_is_readable(gconstpointer address, gsize len)`:**
    *   **功能:** 检查目标进程中指定地址的内存区域是否可读。
    *   **逆向关系:** 在动态分析中，判断一段内存是否可读是常见的需求，例如检查函数参数、读取字符串或数据结构。

2. **`gum_memory_is_writable(gconstpointer address, gsize len)`:**
    *   **功能:** 检查目标进程中指定地址的内存区域是否可写。
    *   **逆向关系:** 修改内存是 Frida 的核心功能之一，例如修改函数返回值、跳过指令或修改数据。在进行代码注入或 hook 时，需要确保目标内存是可写的。

3. **`gum_memory_query_protection(gconstpointer address, GumPageProtection * prot)`:**
    *   **功能:** 查询目标进程中指定地址的内存页保护属性（例如，可读、可写、可执行）。
    *   **逆向关系:** 了解内存保护属性对于理解程序的内存布局和安全机制至关重要。例如，可以识别哪些内存区域用于代码执行，哪些用于数据存储。

4. **`gum_memory_read(gconstpointer address, gsize len, gsize * n_bytes_read)`:**
    *   **功能:** 从目标进程的指定地址读取指定长度的内存数据。
    *   **逆向关系:** 这是最基础的内存读取操作，用于获取目标进程的任何内存内容，例如代码、数据、字符串等。

5. **`gum_memory_write(gpointer address, const guint8 * bytes, gsize len)`:**
    *   **功能:** 将指定的数据写入目标进程的指定地址。
    *   **逆向关系:** 这是 Frida 修改目标进程行为的关键功能，可以用于代码注入、hook、数据修改等。

6. **`gum_try_mprotect(gpointer address, gsize size, GumPageProtection prot)`:**
    *   **功能:** 尝试修改目标进程中指定内存区域的保护属性。如果直接使用 `mprotect` 失败（例如，尝试将只读内存变为可写），则会尝试使用 `mmap` 重新映射内存来实现。
    *   **逆向关系:** 修改内存保护属性是实现某些高级 hook 或代码注入技术的必要步骤。例如，在只读代码段中插入 hook 代码。

7. **`gum_clear_cache(gpointer address, gsize size)`:**
    *   **功能:** 使指定内存区域的 CPU 缓存失效。
    *   **逆向关系:** 在修改代码后，需要清除指令缓存，以确保 CPU 执行的是修改后的指令，而不是旧的缓存内容。

8. **`gum_memory_get_protection(gconstpointer address, gsize n, gsize * size, GumPageProtection * prot)`:**
    *   **功能:** 获取目标进程中指定地址开始的 `n` 个字节的内存保护属性。这是其他 `gum_memory_*` 函数的基础。
    *   **底层知识 (QNX):**  该函数使用 QNX 特定的系统调用 `devctl` 和 `/proc/self/as` 文件来获取内存映射信息。

9. **`_gum_page_protection_from_posix(const gint flags)`:**
    *   **功能:** 将 POSIX 标准的内存保护标志转换为 Frida 内部的 `GumPageProtection` 枚举值。
    *   **底层知识 (POSIX):**  涉及 POSIX 标准中定义的 `PROT_READ`, `PROT_WRITE`, `PROT_EXEC` 等标志。

**与逆向的方法的关系及举例说明:**

*   **读取内存 (Reverse Engineering through Memory Reading):**  假设你想知道目标进程中某个全局变量的值。你可以使用 Frida 脚本，先找到该变量的地址，然后使用 `gum_memory_read` 读取该地址的内存内容。例如，如果目标程序有一个名为 `g_counter` 的全局整数变量，你可以在 Frida 脚本中执行类似的操作：
    ```javascript
    const counterAddress = Module.findExportByName(null, 'g_counter');
    if (counterAddress) {
        const counterValue = Memory.readU32(counterAddress);
        console.log(`Counter value: ${counterValue}`);
    }
    ```
    这个 `Memory.readU32` 在底层会调用 `gum_memory_read`。

*   **修改内存 (Reverse Engineering through Memory Modification):**  假设你想跳过目标程序中的一个安全检查。你可以找到该检查对应的指令地址，然后使用 `gum_memory_write` 将该指令替换为无操作指令 (NOP)。例如，将某个条件跳转指令替换为 NOP 指令，强制程序执行特定分支。

*   **修改内存保护属性 (Reverse Engineering through Protection Modification):**  假设你想在目标进程的只读代码段中插入 hook 代码。你需要先使用 `gum_try_mprotect` 将该代码段的保护属性修改为可写，然后再写入你的 hook 代码。

**涉及到的二进制底层, Linux, Android内核及框架的知识及举例说明:**

*   **二进制底层:**
    *   **`/proc/self/as`:**  该文件是 Linux 和 QNX 等系统中用于访问进程地址空间的特殊文件。`open("/proc/self/as", O_RDONLY)` 打开这个文件，允许读取进程的内存。`lseek(fd, GPOINTER_TO_SIZE (address), SEEK_SET)` 将文件指针移动到指定的内存地址，使得后续的 `read` 和 `write` 操作能够访问该地址的内存。
    *   **内存页大小:**  `gum_query_page_size()` 获取系统的内存页大小，这在进行内存保护属性修改时非常重要，因为 `mprotect` 等系统调用通常以页为单位进行操作。
    *   **内存对齐:**  在 `gum_try_mprotect` 中，可以看到对地址进行页对齐的操作：
        ```c
        aligned_address = GSIZE_TO_POINTER (
            GPOINTER_TO_SIZE (address) & ~(page_size - 1));
        aligned_size =
            (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
        ```
        这是因为内存保护属性只能以页为单位进行修改。

*   **QNX 内核:**
    *   **`sys/neutrino.h` 和 `sys/procfs.h`:** 包含了 QNX 特定的系统调用和数据结构定义。
    *   **`devctl(fd, DCMD_PROC_PAGEDATA, ...)`:**  这是 QNX 特有的设备控制函数，用于获取进程的内存映射信息，包括每个内存区域的起始地址、大小和保护属性。
    *   **`ThreadCtl(_NTO_TCTL_THREADS_HOLD, 0)` 和 `ThreadCtl(_NTO_TCTL_THREADS_CONT, 0)`:**  这两个是 QNX 特有的线程控制函数，用于挂起和恢复所有线程。在 `gum_try_mprotect` 中，当尝试修改只读内存的保护属性时，会使用 `mmap` 重新映射内存。为了保证操作的原子性，需要暂停所有线程，防止其他线程同时访问正在修改的内存区域。
    *   **`mmap(aligned_address, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, NOFD, 0)`:**  即使 `mprotect` 失败，QNX 仍然允许使用 `mmap` 重新映射内存。`MAP_FIXED` 标志表示尝试在指定的 `aligned_address` 映射内存。

*   **Linux 内核:**  虽然此文件是 QNX 特定的，但它使用了一些与 Linux 相似的概念，例如 `/proc/self/as` 和 `mprotect` 系统调用。在 Linux 上，Frida 的内存操作后端会使用类似的机制，但具体的系统调用可能会有所不同。

*   **Android 内核及框架:**  该文件是 QNX 平台的实现，与 Android 内核没有直接关系。Android 有自己的一套内存管理和保护机制，Frida 在 Android 上的实现会有不同的代码和系统调用。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设输入:**

*   **函数:** `gum_memory_is_readable`
*   **输入参数:**
    *   `address`:  指向目标进程中某个已分配但只读内存区域的地址 (例如，代码段中的一个函数地址)。
    *   `len`: 10 (尝试检查 10 个字节)。

**逻辑推理:**

`gum_memory_is_readable` 会调用 `gum_memory_get_protection` 获取该地址的内存保护属性。如果该内存区域的保护属性包含 `GUM_PAGE_READ` 标志，并且其大小大于等于 `len`，则 `gum_memory_is_readable` 返回 `TRUE`，否则返回 `FALSE`。

**预期输出:**

`TRUE` (因为代码段通常是可读的)。

**假设输入:**

*   **函数:** `gum_memory_write`
*   **输入参数:**
    *   `address`: 指向目标进程中某个只读内存区域的地址。
    *   `bytes`:  一个包含要写入的数据的字节数组。
    *   `len`:  要写入的数据长度。

**逻辑推理:**

`gum_memory_write` 首先调用 `gum_memory_is_writable` 检查目标地址是否可写。由于假设地址指向只读内存区域，`gum_memory_is_writable` 会返回 `FALSE`，因此 `gum_memory_write` 会直接返回 `FALSE`，不会尝试写入。

**预期输出:**

`FALSE`.

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **尝试写入只读内存:** 用户可能错误地尝试使用 `Memory.writeByteArray` 或类似的 Frida API 函数向只读内存区域写入数据，例如尝试修改代码段中的指令而没有先修改内存保护属性。这会导致 `gum_memory_write` 返回 `FALSE`。

2. **读取或写入超出分配范围的内存:** 用户可能计算错误的内存地址或长度，导致尝试读取或写入超出目标进程已分配的内存区域。这可能会导致程序崩溃或 Frida 报告错误。例如，访问一个已经被 `free` 掉的内存地址。

3. **在多线程环境下不加锁地修改内存:** 如果目标进程是多线程的，并且用户在 Frida 脚本中修改了共享内存，但没有采取适当的同步措施，可能会导致数据竞争和未定义的行为。虽然 `gummemory-qnx.c` 本身不直接处理线程同步，但错误的使用方式可能导致问题。

4. **假设固定的内存布局:** 用户可能假设目标进程的内存布局是固定的，但在不同的运行环境下（例如，不同的 QNX 版本或编译器选项），内存布局可能会发生变化，导致 Frida 脚本失效。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要 hook 目标进程中的一个函数 `calculate_sum`，并修改其返回值。以下是用户操作到达 `gummemory-qnx.c` 中相关函数的步骤：

1. **编写 Frida 脚本:** 用户编写 JavaScript 代码，使用 Frida 的 API 来 hook `calculate_sum` 函数。例如：
    ```javascript
    Interceptor.attach(Module.findExportByName(null, 'calculate_sum'), {
        onLeave: function(retval) {
            console.log("Original return value:", retval.toInt32());
            retval.replace(100); // 修改返回值为 100
            console.log("Modified return value:", retval.toInt32());
        }
    });
    ```

2. **Frida 解析脚本并执行:** Frida 接收到这个脚本后，会解析 `Interceptor.attach` 调用。

3. **查找函数地址:** `Module.findExportByName` 会在目标进程的模块中查找 `calculate_sum` 函数的地址。这可能涉及到读取目标进程的内存来解析 ELF 文件头和符号表，最终可能调用 `gum_memory_read`。

4. **设置 Hook:** `Interceptor.attach` 会在 `calculate_sum` 函数的入口或出口处设置 hook。这通常涉及到修改目标进程的内存，将原始指令替换为跳转到 Frida 注入的 hook 代码的指令。这个过程会调用 `gum_memory_write`。

5. **修改返回值:** 当 `calculate_sum` 函数执行完毕并返回时，`onLeave` 函数会被调用。`retval.replace(100)` 尝试修改返回值。在底层，Frida 需要将新的返回值写入到函数调用栈上保存返回值的内存位置。这个操作会调用 `gum_memory_write`。

6. **修改内存保护属性 (如果需要):** 如果用户尝试 hook 的函数位于只读的代码段，Frida 可能需要先调用 `gum_try_mprotect` 将包含该函数的内存页设置为可写，然后再写入 hook 代码。

因此，用户的这些高层操作最终会转化为对 `gummemory-qnx.c` 中函数的调用，以实现内存的读取、写入和保护属性修改。在调试 Frida 脚本时，如果遇到内存相关的错误，例如无法写入内存，就可以检查 `gummemory-qnx.c` 中的逻辑，查看是否是因为目标内存不可写或者其他原因导致操作失败。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-qnx/gummemory-qnx.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "gumqnx-priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>

static gboolean gum_memory_get_protection (gconstpointer address, gsize n,
    gsize * size, GumPageProtection * prot);

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_READ) != 0;
}

static gboolean
gum_memory_is_writable (gconstpointer address,
                        gsize len)
{
  gsize size;
  GumPageProtection prot;

  if (!gum_memory_get_protection (address, len, &size, &prot))
    return FALSE;

  return size >= len && (prot & GUM_PAGE_WRITE) != 0;
}

gboolean
gum_memory_query_protection (gconstpointer address,
                             GumPageProtection * prot)
{
  gsize size;

  if (!gum_memory_get_protection (address, 1, &size, prot))
    return FALSE;

  return size >= 1;
}

guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  int fd = -1;
  guint8 * buffer = NULL;
  gint num_read = 0;
  gint res G_GNUC_UNUSED;

  fd = open ("/proc/self/as", O_RDONLY);
  g_assert (fd != -1);
  res = lseek (fd, GPOINTER_TO_SIZE (address), SEEK_SET);
  g_assert (GINT_TO_POINTER (res) == address);

  buffer = g_malloc (len);
  num_read = read (fd, buffer, len);
  if (num_read == -1)
  {
    g_free (buffer);
    buffer = NULL;
  }
  if (n_bytes_read != NULL)
    *n_bytes_read = num_read;

  close (fd);

  return buffer;
}

gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  gboolean success = FALSE;
  int fd = -1;
  gint res G_GNUC_UNUSED;
  gint num_written = 0;

  if (!gum_memory_is_writable (address, len))
    return success;

  fd = open ("/proc/self/as", O_RDWR);
  g_assert (fd != -1);
  res = lseek (fd, GPOINTER_TO_SIZE (address), SEEK_SET);
  g_assert (GINT_TO_POINTER (res) == address);

  num_written = write (fd, bytes, len);
  if (num_written == len)
    success = TRUE;

  close (fd);

  return success;
}

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection prot)
{
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;
  gint posix_prot;
  gint result;

  g_assert (size != 0);

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  posix_prot = _gum_page_protection_to_posix (prot);

  result = mprotect (aligned_address, aligned_size, posix_prot);
  if (result == -1 && errno == EACCES &&
      (prot & GUM_PAGE_WRITE) == GUM_PAGE_WRITE)
  {
    int fd = -1;
    char * buffer;
    gpointer address_mmapped G_GNUC_UNUSED;
    gint total_read_count = 0;

    fd = open ("/proc/self/as", O_RDONLY);
    g_assert (fd != -1);

    buffer = g_alloca (aligned_size);
    g_assert (buffer != NULL);

    lseek (fd, GPOINTER_TO_SIZE (aligned_address), SEEK_SET);

    while (total_read_count < aligned_size)
    {
      gint read_count = read (fd, &buffer[total_read_count],
          aligned_size - total_read_count);
      total_read_count += read_count;
    }

    ThreadCtl (_NTO_TCTL_THREADS_HOLD, 0);

    address_mmapped = mmap (aligned_address, aligned_size,
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, NOFD, 0);
    g_assert (address_mmapped == aligned_address);

    memcpy (aligned_address, buffer, aligned_size);

    result = mprotect (aligned_address, aligned_size, posix_prot);

    ThreadCtl (_NTO_TCTL_THREADS_CONT, 0);

    close (fd);
  }

  return result == 0;
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
  msync (address, size, MS_INVALIDATE_ICACHE);
}

static gboolean
gum_memory_get_protection (gconstpointer address,
                           gsize n,
                           gsize * size,
                           GumPageProtection * prot)
{
  gboolean success;
  gint fd, res G_GNUC_UNUSED;
  procfs_mapinfo * mapinfos;
  gint num_mapinfos;
  gpointer start, end;
  gint i;

  if (size == NULL || prot == NULL)
  {
    gsize ignored_size;
    GumPageProtection ignored_prot;

    return gum_memory_get_protection (address, n,
        (size != NULL) ? size : &ignored_size,
        (prot != NULL) ? prot : &ignored_prot);
  }

  if (n > 1)
  {
    gsize page_size, start_page, end_page, cur_page;

    page_size = gum_query_page_size ();

    start_page = GPOINTER_TO_SIZE (address) & ~(page_size - 1);
    end_page = (GPOINTER_TO_SIZE (address) + n - 1) & ~(page_size - 1);

    success = gum_memory_get_protection (GSIZE_TO_POINTER (start_page), 1, NULL,
        prot);
    if (success)
    {
      *size = page_size - (GPOINTER_TO_SIZE (address) - start_page);
      for (cur_page = start_page + page_size;
           cur_page != end_page + page_size;
           cur_page += page_size)
      {
        GumPageProtection cur_prot;

        if (gum_memory_get_protection (GSIZE_TO_POINTER (cur_page), 1, NULL,
            &cur_prot) && (cur_prot != GUM_PAGE_NO_ACCESS ||
            *prot == GUM_PAGE_NO_ACCESS))
        {
          *size += page_size;
          *prot &= cur_prot;
        }
        else
        {
          break;
        }
      }
      *size = MIN (*size, n);
    }

    return success;
  }

  success = FALSE;
  *size = 0;
  *prot = GUM_PAGE_NO_ACCESS;

  fd = open ("/proc/self/as", O_RDONLY);
  g_assert (fd != -1);

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &num_mapinfos);
  g_assert (res == 0);

  mapinfos = g_malloc (num_mapinfos * sizeof (procfs_mapinfo));

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      sizeof (procfs_mapinfo) * num_mapinfos, &num_mapinfos);
  g_assert (res == 0);

  for (i = 0; i != num_mapinfos; i++)
  {
    start = GSIZE_TO_POINTER (mapinfos[i].vaddr & 0xffffffff);
    end = start + mapinfos[i].size;

    if (start > address)
      break;
    else if (address >= start && address + n - 1 < end)
    {
      success = TRUE;
      *size = 1;

      *prot = _gum_page_protection_from_posix (mapinfos[i].flags);
      break;
    }
  }

  g_free (mapinfos);
  close (fd);

  return success;
}

GumPageProtection
_gum_page_protection_from_posix (const gint flags)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if (flags & PROT_READ)
    prot |= GUM_PAGE_READ;
  if (flags & PROT_WRITE)
    prot |= GUM_PAGE_WRITE;
  if (flags & PROT_EXEC)
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}
```