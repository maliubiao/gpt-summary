Response:
Let's break down the thought process for analyzing the `linker_block_allocator.cpp` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the code, covering its functionality, relationship to Android, libc function explanations, dynamic linker aspects, example usage, error scenarios, and how Android frameworks/NDK lead to its use, concluding with a Frida hook example. This is a multi-faceted analysis, requiring both code understanding and knowledge of the Android ecosystem.

**2. Initial Code Scan and High-Level Understanding:**

* **File Name and Location:** `bionic/linker/linker_block_allocator.cpp`. "linker" strongly suggests this is part of the dynamic linker in Android. "block allocator" hints at a memory management mechanism that allocates fixed-size blocks.
* **Includes:**  `<inttypes.h>`, `<string.h>`, `<sys/mman.h>`, `<sys/param.h>`, `<sys/prctl.h>`, `<unistd.h>`, `"linker_debug.h"`. These headers confirm system-level operations (memory mapping, process control, standard library functions) and a linker-specific debug header.
* **Key Data Structures:** `LinkerBlockAllocatorPage`, `FreeBlockInfo`. These are the building blocks of the allocator. `LinkerBlockAllocatorPage` seems to represent a large chunk of memory, and `FreeBlockInfo` likely manages the free blocks within a page.
* **Class:** `LinkerBlockAllocator`. This encapsulates the allocation logic. Its members `block_size_`, `page_list_`, `free_block_list_`, and `allocated_` provide further clues about its state and behavior.
* **Core Methods:** `alloc()`, `free()`, `create_new_page()`, `find_page()`, `protect_all()`, `purge()`. These are the fundamental operations of a memory allocator.

**3. Deeper Dive into Functionality:**

* **`LinkerBlockAllocator(size_t block_size)`:** The constructor initializes the allocator with a specific `block_size`. The `__BIONIC_ALIGN` and `MAX` calls suggest alignment and minimum size requirements for the blocks.
* **`alloc()`:** This is the allocation function. It first checks if there are free blocks. If not, it creates a new page. Then, it retrieves a free block, updates the free list, and returns the allocated block. The `memset` call suggests zeroing the allocated memory.
* **`free(void* block)`:**  The deallocation function. It finds the page the block belongs to, clears the block, and adds it back to the free list.
* **`create_new_page()`:**  This function uses `mmap` to allocate a large chunk of memory. `prctl` is used to give the memory region a name for debugging. The newly allocated page is divided into blocks, and these blocks are linked into the `free_block_list_`.
* **`find_page(void* block)`:**  This function iterates through the list of allocated pages to find the page containing a given block.
* **`protect_all(int prot)`:** This function uses `mprotect` to change the memory protection flags of all allocated pages. This is a security or memory management technique.
* **`purge()`:** This function deallocates all allocated pages using `munmap`. It only does this if no blocks are currently allocated.

**4. Connecting to Android and the Dynamic Linker:**

* **"linker" in the path and class name:**  Strong indication this is part of the dynamic linker's internal memory management.
* **`kAllocateSize`, `kBlockSizeAlign`, `kBlockSizeMin`:** These constants suggest fixed-size allocations, which is common in linkers for managing data structures related to shared libraries.
* **Purpose:**  The allocator likely manages memory for linker-specific data, such as:
    * Loaded shared library information (e.g., `soinfo`).
    * Symbol tables.
    * Relocation entries.
    * Other internal linker data structures.

**5. Analyzing libc Functions:**

For each libc function, the explanation should cover:

* **Purpose:** What the function does in general.
* **How it's used in this code:** The specific role it plays in the `LinkerBlockAllocator`.
* **Implementation details (brief):** A high-level overview of how the function works at the OS level.

**6. Dynamic Linker Aspects:**

* **`soinfo` Structure (Hypothetical):**  Create a simplified example of a `soinfo` structure that this allocator might be used for.
* **SO Layout:**  Illustrate a typical memory layout of a loaded shared library, showing where the `soinfo` and other linker-managed data would reside.
* **Linking Process:**  Explain how the linker uses this allocator during the process of loading and linking shared libraries.

**7. Logic Inference and Examples:**

* **Allocation and Freeing:** Provide simple scenarios showing how `alloc()` and `free()` are used and how the internal free list changes.

**8. Common User Errors:**

Focus on errors that could arise if this allocator were exposed directly (though it's an internal component):

* Double freeing.
* Using freed memory.
* Memory leaks (though the `purge()` function mitigates this for the linker).

**9. Android Framework/NDK Integration:**

* **High-Level Flow:** Start from the application or NDK, trace the path through system calls (like `dlopen`) that eventually trigger the dynamic linker.
* **Linker Involvement:** Explain how the dynamic linker (`/system/bin/linker64` or `/system/bin/linker`) is invoked.
* **Allocator Usage:** Point out the stage during linking where this block allocator would be used to manage linker data.

**10. Frida Hooking:**

* **Target Functions:** Choose relevant functions like `alloc()` or `create_new_page()`.
* **Hook Code:**  Provide JavaScript code snippets using Frida to intercept these functions, log arguments, and potentially modify behavior.

**Self-Correction/Refinement during the process:**

* **Initial Focus:**  Might initially focus too much on the C++ details of the allocator. Need to remember the broader context of the dynamic linker and Android.
* **Depth of libc explanations:** Avoid getting bogged down in overly detailed OS-level implementations of libc functions. Keep it relevant to how they're used in the code.
* **SO Layout Simplification:**  The actual SO layout is complex. Provide a simplified, illustrative example.
* **Frida Hook Specificity:**  Make sure the Frida hook examples are concrete and demonstrate a useful debugging scenario.

By following these steps, the comprehensive analysis presented in the initial good answer can be constructed logically and thoroughly. The process involves understanding the code, connecting it to the broader system, and providing concrete examples and debugging techniques.
这是一个关于 Android Bionic 库中动态链接器（linker）的源代码文件 `linker_block_allocator.cpp` 的分析。这个文件实现了一个简单的块分配器，用于动态链接器在加载和管理共享库时分配固定大小的内存块。

**功能列举:**

1. **固定大小内存块分配:**  该分配器的核心功能是分配预定义大小的内存块。这个大小在编译时确定，并且对所有分配的块都是相同的。
2. **内存页管理:** 它将内存组织成固定大小的“页”（pages）。当需要分配新的块，并且当前没有可用的空闲块时，它会分配新的内存页。
3. **空闲块管理:**  它维护一个空闲块的链表 (`free_block_list_`)，用于快速找到可用的内存块。
4. **内存保护:** 它提供了 `protect_all` 方法来修改所有已分配内存页的保护属性（例如，设置为只读）。
5. **内存释放 (Purge):**  它提供了 `purge` 方法来释放所有已分配的内存页，但这只有在没有已分配的块时才执行。这通常在动态链接器不再需要这些内存时发生。

**与 Android 功能的关系及举例:**

这个块分配器是 Android 动态链接器内部使用的组件，它不直接暴露给应用程序开发者。它的主要作用是帮助动态链接器管理其内部数据结构，例如：

* **加载的共享库信息 (`soinfo`)**:  动态链接器需要存储关于每个加载的共享库的信息，例如它的加载地址、依赖关系、符号表等。这些 `soinfo` 结构体可能就使用这个块分配器进行分配。
    * **例子:** 当一个应用程序使用 `System.loadLibrary("mylib")` 加载一个 NDK 库时，Android Framework 会调用底层的 `dlopen` 函数。动态链接器在处理 `dlopen` 请求时，需要分配内存来存储 `mylib.so` 的相关信息，这些内存可能就来自于 `LinkerBlockAllocator`。
* **符号查找表:** 动态链接器需要在不同的共享库之间解析符号引用。它会维护一些内部的数据结构来加速符号查找，这些数据结构的内存也可能由此分配器管理。
* **重定位信息:**  当加载共享库时，动态链接器需要修改代码和数据段中的地址，使其指向正确的内存位置。相关的重定位信息也可能存储在使用此分配器分配的内存中。

**libc 函数的功能实现解释:**

* **`memset(void* s, int c, size_t n)`:**
    * **功能:** 将从 `s` 指向的地址开始的 `n` 个字节设置为值 `c`。
    * **实现:**  `memset` 通常使用优化的汇编指令，例如 SIMD 指令，来快速填充内存。它会逐字节或逐字地将指定的值写入内存区域。
    * **在代码中的使用:**
        * `memset(block_info, 0, block_size_);` 在 `alloc` 函数中用于将新分配的内存块清零，确保分配的内存不包含之前使用过的残留数据。
        * `memset(block, 0, block_size_);` 在 `free` 函数中用于在释放内存块之前将其清零。这有助于调试，并在某些安全敏感的场景中防止信息泄露。
* **`mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)`:**
    * **功能:**  创建一个新的内存映射。它可以将文件或设备映射到进程的地址空间，或者创建匿名内存映射（就像代码中使用的）。
    * **实现:**  `mmap` 是一个系统调用，它与操作系统内核交互。内核会分配指定大小的虚拟内存区域，并将其映射到物理内存（如果是匿名映射）或文件/设备的页缓存。
    * **在代码中的使用:**
        * `mmap(nullptr, kAllocateSize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` 在 `create_new_page` 函数中用于分配新的内存页。
            * `nullptr`:  让内核选择映射的起始地址。
            * `kAllocateSize`:  要映射的内存大小。
            * `PROT_READ|PROT_WRITE`:  设置内存页的保护属性为可读写。
            * `MAP_PRIVATE|MAP_ANONYMOUS`:  创建一个私有的匿名映射，意味着对该映射的修改不会影响到其他进程或文件系统。
            * `-1`:  表示不映射到任何文件。
            * `0`:  偏移量，对于匿名映射没有意义。
* **`mprotect(void* addr, size_t len, int prot)`:**
    * **功能:**  修改一个内存区域的保护属性。
    * **实现:**  `mprotect` 也是一个系统调用，它通知内核修改指定内存区域的页表条目，以改变其访问权限（读、写、执行）。
    * **在代码中的使用:**
        * `mprotect(page, kAllocateSize, prot)` 在 `protect_all` 函数中用于修改整个内存页的保护属性。`prot` 参数可以是 `PROT_READ`、`PROT_WRITE`、`PROT_EXEC` 或它们的组合。动态链接器可能使用它来设置某些内存区域为只读，以提高安全性或防止意外修改。
* **`munmap(void* addr, size_t length)`:**
    * **功能:**  解除对先前使用 `mmap` 创建的内存映射。
    * **实现:**  `munmap` 是一个系统调用，它通知内核释放与指定内存区域相关的资源，包括虚拟地址空间和物理内存（如果已分配）。
    * **在代码中的使用:**
        * `munmap(page, kAllocateSize)` 在 `purge` 函数中用于释放不再需要的内存页。
* **`prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)`:**
    * **功能:**  执行进程相关的控制操作。
    * **实现:**  `prctl` 是一个系统调用，它提供了一系列与进程行为相关的控制选项。
    * **在代码中的使用:**
        * `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, page, kAllocateSize, "linker_alloc")` 在 `create_new_page` 函数中使用，用于为匿名映射的内存区域设置一个名称。这个名称通常在 `/proc/[pid]/maps` 文件中可见，方便调试和分析。
* **`unistd.h` 中的函数 (例如 `getpid`)**：虽然代码中没有直接使用，但 `async_safe_fatal` 宏可能会用到一些 `unistd.h` 中的函数来输出错误信息，例如 `getpid` 获取进程 ID。
* **`sys/param.h` 中的宏 (例如 `MAX`)`：
    * **功能:** 提供系统相关的常量和宏定义。`MAX` 宏用于返回两个值中的较大者。
    * **在代码中的使用:** `MAX(block_size, kBlockSizeMin)` 确保分配的块大小至少为 `kBlockSizeMin`。

**涉及 dynamic linker 的功能及 so 布局样本和链接处理过程:**

这个 `LinkerBlockAllocator` 是动态链接器内部使用的组件，它并不直接参与共享库的链接过程，而是为链接器提供内存管理服务。

**SO 布局样本 (简化):**

当一个共享库被加载到内存中时，它的布局可能如下所示 (简化，不同架构和操作系统可能有所不同):

```
+---------------------+  <- 加载基址 (load base address)
|  .text (代码段)      |
+---------------------+
|  .rodata (只读数据)  |
+---------------------+
|  .data (可写数据)    |
+---------------------+
|  .bss (未初始化数据) |
+---------------------+
|  .dynamic (动态链接信息) |  <--  可能包含需要动态链接器处理的信息
+---------------------+
|  ... (其他段)      |
+---------------------+
```

**链接处理过程 (与 `LinkerBlockAllocator` 的关系):**

1. **加载共享库:** 当 `dlopen` 被调用时，动态链接器负责找到并加载指定的共享库到内存中。
2. **解析 ELF 文件:** 动态链接器解析共享库的 ELF 文件头，读取段信息、符号表、重定位表等。
3. **分配内存:** 在解析过程中，动态链接器需要为内部数据结构分配内存，例如 `soinfo` 结构体，用于存储关于这个共享库的信息。**`LinkerBlockAllocator` 在这里发挥作用，为这些结构体提供内存。**
4. **符号解析和重定位:** 动态链接器遍历重定位表，找到需要被修改的地址。它查找需要的符号，并修改代码或数据段中的地址，使其指向正确的内存位置。
5. **执行初始化代码:**  在链接完成后，动态链接器会执行共享库的初始化代码 (例如，构造函数)。

**`LinkerBlockAllocator` 的作用体现在第 3 步，即为动态链接器管理其内部数据结构分配内存。它本身不参与符号解析或重定位的逻辑。**

**假设输入与输出 (逻辑推理):**

假设我们有一个 `LinkerBlockAllocator` 实例，其 `block_size_` 为 32 字节。

**场景 1: 首次分配**

* **假设输入:** 调用 `alloc()`。此时 `free_block_list_` 为 `nullptr`。
* **推理过程:**
    1. `free_block_list_ == nullptr` 为真，调用 `create_new_page()`。
    2. `create_new_page()` 使用 `mmap` 分配一个新的内存页 (大小为 `kAllocateSize`)。
    3. 新页被划分成多个 32 字节的块，并链接到 `free_block_list_`。
    4. `alloc()` 从 `free_block_list_` 中取出一个块，并返回该块的地址。
* **预期输出:** 返回指向新分配的 32 字节内存块的指针，`free_block_list_` 指向下一个可用的空闲块。

**场景 2: 分配后释放**

* **假设输入:**
    1. 调用 `alloc()` 返回指针 `p1`。
    2. 调用 `alloc()` 返回指针 `p2`。
    3. 调用 `free(p1)`。
* **推理过程:**
    1. `alloc()` 正常分配两个块。
    2. `free(p1)` 将 `p1` 指向的块添加到 `free_block_list_` 的头部。
* **预期输出:** `free_block_list_` 指向 `p1` 指向的内存块，该块的 `next_block` 指向之前 `free_block_list_` 指向的块。

**用户或编程常见的使用错误 (如果此分配器暴露给用户):**

由于 `LinkerBlockAllocator` 是动态链接器的内部实现，普通开发者不会直接使用它。但是，如果将其暴露出来，可能会遇到以下错误：

1. **重复释放 (Double Free):**
   ```c++
   LinkerBlockAllocator allocator(32);
   void* ptr = allocator.alloc();
   allocator.free(ptr);
   allocator.free(ptr); // 错误：ptr 已经被释放
   ```
   这会导致程序崩溃或内存损坏，因为尝试将已经被释放的内存块再次添加到空闲链表中，可能会破坏链表结构。

2. **使用已释放的内存 (Use After Free):**
   ```c++
   LinkerBlockAllocator allocator(32);
   void* ptr = allocator.alloc();
   allocator.free(ptr);
   memset(ptr, 0, 32); // 错误：ptr 指向的内存已经被释放，再次访问可能导致问题
   ```
   访问已经被释放的内存可能导致程序崩溃、数据损坏或安全漏洞。

3. **内存泄漏 (Memory Leak - 如果没有 `purge` 或类似的机制):**
   如果分配了内存但没有正确释放，会导致内存泄漏。虽然 `LinkerBlockAllocator` 内部有 `purge` 方法，但如果开发者不小心丢失了指向已分配内存的指针，仍然可能发生泄漏。

**Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例:**

**调用路径:**

1. **应用程序或 NDK 代码调用 `dlopen` 或 `System.loadLibrary`:** 这是加载共享库的入口点。
2. **`dlopen` 系统调用:**  该调用最终会进入 Android 运行时的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`)。
3. **动态链接器初始化:** 动态链接器在启动时会初始化各种内部数据结构，包括 `LinkerBlockAllocator` 的实例。
4. **加载和链接共享库:** 当动态链接器处理 `dlopen` 请求时，它会解析 ELF 文件，分配内存来存储共享库的信息 (`soinfo`)，并进行符号解析和重定位。在这个过程中，**动态链接器会调用其内部的 `LinkerBlockAllocator` 的 `alloc` 方法来分配所需的内存块。**

**Frida Hook 示例:**

可以使用 Frida 来 hook `LinkerBlockAllocator::alloc` 方法，以观察内存分配的情况。

```javascript
if (Process.arch === 'arm64') {
    const linker_block_allocator_alloc = Module.findExportByName("linker64", "_ZN19LinkerBlockAllocator5allocEv");

    if (linker_block_allocator_alloc) {
        Interceptor.attach(linker_block_allocator_alloc, {
            onEnter: function (args) {
                console.log("[LinkerBlockAllocator::alloc] Called");
                // 可以在这里查看寄存器或内存状态
            },
            onLeave: function (retval) {
                console.log("[LinkerBlockAllocator::alloc] Returned: " + retval);
                // 可以查看返回值（分配的内存地址）
            }
        });
    } else {
        console.log("Could not find LinkerBlockAllocator::alloc in linker64");
    }
} else if (Process.arch === 'arm') {
    const linker_block_allocator_alloc = Module.findExportByName("linker", "_ZN19LinkerBlockAllocator5allocEv");

    if (linker_block_allocator_alloc) {
        Interceptor.attach(linker_block_allocator_alloc, {
            onEnter: function (args) {
                console.log("[LinkerBlockAllocator::alloc] Called");
            },
            onLeave: function (retval) {
                console.log("[LinkerBlockAllocator::alloc] Returned: " + retval);
            }
        });
    } else {
        console.log("Could not find LinkerBlockAllocator::alloc in linker");
    }
}
```

**解释:**

1. **`Process.arch`:**  获取当前进程的架构 (arm64 或 arm)。
2. **`Module.findExportByName`:**  在动态链接器模块 (`linker64` 或 `linker`) 中查找 `LinkerBlockAllocator::alloc` 函数的符号。需要根据架构使用正确的链接器名称和符号 mangling 后的名称。
3. **`Interceptor.attach`:**  拦截找到的函数。
4. **`onEnter`:**  在函数执行之前调用，可以查看参数。
5. **`onLeave`:**  在函数执行之后调用，可以查看返回值。

**运行 Frida Hook:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_allocator.js`).
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <your_app_package_name> -l hook_allocator.js --no-pause
   ```
   或者，如果应用程序已经在运行：
   ```bash
   frida -U <your_app_package_name> -l hook_allocator.js
   ```
3. 当应用程序加载共享库时，Frida 会拦截 `LinkerBlockAllocator::alloc` 的调用，并在控制台上打印日志信息，显示函数被调用以及返回的内存地址。

这个 Frida hook 允许开发者观察动态链接器内部的内存分配行为，这对于理解动态链接过程和调试相关问题非常有帮助。

### 提示词
```
这是目录为bionic/linker/linker_block_allocator.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```cpp
/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "linker_block_allocator.h"

#include <inttypes.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "linker_debug.h"

static constexpr size_t kMaxPageSize = 65536;
static constexpr size_t kAllocateSize = kMaxPageSize * 6;
static_assert(kAllocateSize % kMaxPageSize == 0, "Invalid kAllocateSize.");

struct LinkerBlockAllocatorPage {
  LinkerBlockAllocatorPage* next;
  uint8_t bytes[kAllocateSize - 16] __attribute__((aligned(16)));
};

struct FreeBlockInfo {
  void* next_block;
  size_t num_free_blocks;
};

static_assert(kBlockSizeAlign >= alignof(FreeBlockInfo));
static_assert(kBlockSizeMin == sizeof(FreeBlockInfo));

LinkerBlockAllocator::LinkerBlockAllocator(size_t block_size)
    : block_size_(__BIONIC_ALIGN(MAX(block_size, kBlockSizeMin), kBlockSizeAlign)),
      page_list_(nullptr),
      free_block_list_(nullptr),
      allocated_(0) {}

void* LinkerBlockAllocator::alloc() {
  if (free_block_list_ == nullptr) {
    create_new_page();
  }

  FreeBlockInfo* block_info = reinterpret_cast<FreeBlockInfo*>(free_block_list_);
  if (block_info->num_free_blocks > 1) {
    FreeBlockInfo* next_block_info = reinterpret_cast<FreeBlockInfo*>(
      reinterpret_cast<char*>(free_block_list_) + block_size_);
    next_block_info->next_block = block_info->next_block;
    next_block_info->num_free_blocks = block_info->num_free_blocks - 1;
    free_block_list_ = next_block_info;
  } else {
    free_block_list_ = block_info->next_block;
  }

  memset(block_info, 0, block_size_);

  ++allocated_;

  return block_info;
}

void LinkerBlockAllocator::free(void* block) {
  if (block == nullptr) {
    return;
  }

  LinkerBlockAllocatorPage* page = find_page(block);
  CHECK(page != nullptr);

  ssize_t offset = reinterpret_cast<uint8_t*>(block) - page->bytes;
  CHECK((offset % block_size_) == 0);

  memset(block, 0, block_size_);

  FreeBlockInfo* block_info = reinterpret_cast<FreeBlockInfo*>(block);

  block_info->next_block = free_block_list_;
  block_info->num_free_blocks = 1;

  free_block_list_ = block_info;

  --allocated_;
}

void LinkerBlockAllocator::protect_all(int prot) {
  for (LinkerBlockAllocatorPage* page = page_list_; page != nullptr; page = page->next) {
    if (mprotect(page, kAllocateSize, prot) == -1) {
      async_safe_fatal("mprotect(%p, %zu, %d) failed: %m", page, kAllocateSize, prot);
    }
  }
}

void LinkerBlockAllocator::create_new_page() {
  static_assert(sizeof(LinkerBlockAllocatorPage) == kAllocateSize,
                "Invalid sizeof(LinkerBlockAllocatorPage)");

  LinkerBlockAllocatorPage* page = reinterpret_cast<LinkerBlockAllocatorPage*>(
      mmap(nullptr, kAllocateSize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));
  CHECK(page != MAP_FAILED);

  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, page, kAllocateSize, "linker_alloc");

  FreeBlockInfo* first_block = reinterpret_cast<FreeBlockInfo*>(page->bytes);
  first_block->next_block = free_block_list_;
  first_block->num_free_blocks = sizeof(page->bytes) / block_size_;

  free_block_list_ = first_block;

  page->next = page_list_;
  page_list_ = page;
}

LinkerBlockAllocatorPage* LinkerBlockAllocator::find_page(void* block) {
  CHECK(block != nullptr);

  LinkerBlockAllocatorPage* page = page_list_;
  while (page != nullptr) {
    const uint8_t* page_ptr = reinterpret_cast<const uint8_t*>(page);
    if (block >= (page_ptr + sizeof(page->next)) && block < (page_ptr + kAllocateSize)) {
      return page;
    }

    page = page->next;
  }

  async_safe_fatal("couldn't find page for %p", block);
}

void LinkerBlockAllocator::purge() {
  if (allocated_) {
    return;
  }

  LinkerBlockAllocatorPage* page = page_list_;
  while (page) {
    LinkerBlockAllocatorPage* next = page->next;
    munmap(page, kAllocateSize);
    page = next;
  }
  page_list_ = nullptr;
  free_block_list_ = nullptr;
}
```