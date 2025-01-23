Response:
Let's break down the request and the provided code snippet to formulate a comprehensive answer.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `dlmalloc.c`, a memory allocator, within the context of the Frida dynamic instrumentation tool. Specifically, they are interested in:

* **Functionality:** What does this code do?
* **Relationship to Reverse Engineering:** How is it relevant to reverse engineering tasks?
* **Low-level Details:** Connections to binary, Linux/Android kernels, and frameworks.
* **Logical Reasoning:** Input/output examples (though this is challenging for a general-purpose allocator).
* **Common User Errors:** How mistakes in usage could lead to interaction with this code.
* **User Path to This Code:** How a user's actions in Frida might lead to this code being executed.
* **Summary of Functionality:** A concise overview.

**2. Analyzing the Code Snippet (Part 2):**

This specific part of the `dlmalloc.c` file focuses heavily on:

* **Configuration Macros:**  Defines and undefines various macros that control the behavior and features of the memory allocator. Examples include `HAVE_MMAP`, `DEFAULT_MMAP_THRESHOLD`, `USE_BUILTIN_FFS`, `NO_MALLINFO`, etc. These macros allow for customization based on the target platform and desired functionality.
* **Mallopt Options:** Defines symbolic names for `mallopt` parameters (`M_TRIM_THRESHOLD`, `M_GRANULARITY`, `M_MMAP_THRESHOLD`). `mallopt` is a function to tune the allocator's behavior.
* **Mallinfo Structure:** Defines the `mallinfo` struct, which holds statistics about memory usage. It includes platform-specific handling for systems that have their own `malloc.h`.
* **Public Function Declarations (with `DLMALLOC_EXPORT`):**  Declares the public interface of the allocator. These are the functions that user code (or in this case, Frida internals) would call: `malloc`, `free`, `calloc`, `realloc`, `memalign`, `posix_memalign`, `valloc`, `mallopt`, `malloc_footprint`, `malloc_max_footprint`, `malloc_footprint_limit`, `malloc_set_footprint_limit`, `malloc_inspect_all`, `mallinfo`, and various independent allocation and bulk free functions.
* **Conditional Compilation (`#if MSPACES`):** Introduces the concept of "mspaces," which are independent memory allocation regions. This allows for more fine-grained memory management.
* **Internal Includes:** Includes standard C libraries and some system-specific headers (`unistd.h`, `sys/mman.h`) that the memory allocator relies on.
* **Locking Mechanisms (`#if USE_LOCKS`):**  Indicates that the allocator can be configured to use locks for thread safety.
* **Bit Scanning (`#if defined(_MSC_VER) && _MSC_VER>=1300`):** Shows the use of compiler intrinsics for efficient bit manipulation on Windows.
* **Page Size Determination:** Demonstrates platform-specific methods for obtaining the system's page size.

**3. Formulating the Answer - Iterative Process:**

* **Start with the Obvious:** The code is a memory allocator. Its primary function is managing memory.
* **Connect to Frida:**  Frida needs to allocate memory for instrumenting processes. `dlmalloc.c` is the mechanism Frida uses for this.
* **Reverse Engineering Relevance:** Memory allocation is *fundamental* in reverse engineering. Understanding how memory is managed is key to analyzing program behavior, finding vulnerabilities, and understanding data structures.
* **Low-level Connections:** The code directly interacts with operating system primitives like `sbrk` and `mmap`. This ties it to the kernel. The mention of Android hints at its use in that environment.
* **Logical Reasoning (Challenge):**  Difficult to give concrete input/output for the entire allocator. Focus on the *types* of operations.
* **User Errors:**  Standard memory management pitfalls are relevant (double frees, memory leaks, buffer overflows).
* **User Path (Frida Specific):**  Think about common Frida use cases that involve memory allocation.
* **Structure the Answer:**  Organize the information into the requested categories. Use clear headings and bullet points.
* **Refine and Elaborate:** Add details and examples where appropriate. For instance, explain what `sbrk` and `mmap` do. Explain the purpose of the `mallinfo` struct.
* **Address Part 2:** Specifically summarize the functionality evident in the provided code *segment*.

**Pre-computation/Pre-analysis (Mental Steps):**

* **Recall knowledge of memory allocators:**  What are the common functions? What are the underlying system calls?
* **Recognize `dlmalloc`:** It's a well-known general-purpose allocator.
* **Identify Key Concepts in the Snippet:** Macros, `mallopt`, `mallinfo`, function declarations, conditional compilation, system calls.
* **Consider the Frida Context:** Why would Frida need a custom allocator? (Likely for portability and control).

By following this thought process, combining code analysis with knowledge of operating systems and reverse engineering concepts, and iteratively refining the answer, we arrive at the comprehensive response provided previously.
好的，让我们来分析一下`frida/subprojects/frida-gum/gum/dlmalloc.c`的这段代码片段（第二部分）。

**功能归纳：**

这段代码主要定义了 `dlmalloc` 内存分配器的各种配置选项、数据结构以及公共接口（函数声明）。它为后续的内存管理逻辑奠定了基础。具体来说，它完成了以下功能：

1. **配置宏定义:** 定义了大量的预编译宏，用于控制 `dlmalloc` 的行为和特性。这些宏可以根据不同的平台和需求进行配置，例如是否支持 `mmap`，默认的 `mmap` 阈值，是否使用内置的 `ffs` 函数等等。
2. **`mallopt` 参数定义:** 定义了 `mallopt` 函数可以接受的参数，例如 `M_TRIM_THRESHOLD`（释放内存阈值）、`M_GRANULARITY`（内存分配粒度）、`M_MMAP_THRESHOLD`（使用 `mmap` 的阈值）。这些参数允许用户在运行时调整内存分配器的行为。
3. **`mallinfo` 结构体声明:** 声明了 `mallinfo` 结构体，该结构体用于返回内存分配器的统计信息，例如已分配的 arena 大小、空闲块数量、已映射区域大小等等。代码中考虑了不同系统可能存在的 `malloc.h` 文件，并提供了兼容的声明。
4. **公共函数接口声明:** 声明了 `dlmalloc` 对外提供的各种内存管理函数，例如 `dlmalloc`（分配内存）、`dlfree`（释放内存）、`dlcalloc`（分配并清零内存）、`dlrealloc`（重新分配内存）、`dlmemalign`（按指定对齐方式分配内存）等等。这些函数是用户代码与内存分配器交互的主要入口。
5. **条件编译:** 使用 `#if` 等预编译指令，根据不同的宏定义选择性地编译某些代码。例如，`#if !ONLY_MSPACES` 表示只有在不使用独立的内存空间（mspace）时才编译某些函数。
6. **`mspace` 相关定义:**  如果定义了 `MSPACES`，则会声明与独立内存空间管理相关的类型（`mspace`）和函数，例如 `create_mspace`、`destroy_mspace`、`mspace_malloc`、`mspace_free` 等。这允许创建和管理多个独立的内存堆。
7. **内部头文件包含:**  包含了标准 C 库的头文件（如 `stdio.h`、`errno.h`、`stdlib.h`、`string.h`）以及一些系统相关的头文件（如 `unistd.h`、`sys/mman.h`），这些头文件提供了内存分配器实现所需的各种函数和类型定义。
8. **锁机制声明:** 如果定义了 `USE_LOCKS`，则会声明用于线程安全的锁机制相关的代码。
9. **位扫描声明:**  针对特定的平台（例如 Windows），声明了用于高效位扫描的函数。
10. **获取页大小:**  定义了获取系统页大小的宏，并考虑了各种平台上的不同实现方式。

**与逆向方法的关联及举例说明：**

内存分配是程序运行的基础，逆向工程中理解内存分配器的行为至关重要。

* **理解内存布局:** 逆向分析时，了解程序如何分配和释放内存可以帮助我们理解数据结构的布局、对象的生命周期以及潜在的内存泄漏或缓冲区溢出漏洞。`dlmalloc.c` 的代码揭示了内存块的组织方式、元数据的存储方式以及空闲块的管理策略。
* **查找和分析堆漏洞:**  `dlmalloc` 的实现细节，例如 chunk 的结构、合并空闲块的算法等，直接关系到堆溢出、Use-After-Free 等漏洞的产生和利用。逆向分析 `dlmalloc` 可以帮助我们理解这些漏洞的原理和利用方法。
* **Hook 和监控内存操作:** 在动态 instrumentation 工具 Frida 中，我们可以 hook `dlmalloc` 提供的内存分配和释放函数，监控程序的内存使用情况，例如分配了哪些内存，在何处释放，是否有异常操作。

**举例说明:**

假设我们正在逆向分析一个程序，怀疑它存在堆溢出漏洞。通过 Frida，我们可以 hook `dlmalloc` 和 `dlfree`：

```javascript
// Hook malloc
Interceptor.attach(Module.findExportByName(null, "malloc"), {
  onEnter: function (args) {
    this.size = args[0].toInt();
    console.log("malloc called, size:", this.size);
  },
  onLeave: function (retval) {
    if (retval.isNull()) {
      console.log("malloc failed");
    } else {
      console.log("malloc returned:", retval, "for size:", this.size);
    }
  },
});

// Hook free
Interceptor.attach(Module.findExportByName(null, "free"), {
  onEnter: function (args) {
    this.ptr = args[0];
    if (!this.ptr.isNull()) {
      console.log("free called on:", this.ptr);
    }
  },
});
```

通过观察 `malloc` 的分配大小和 `free` 的释放地址，我们可以初步判断是否存在异常的内存操作。如果发现 `malloc` 分配的块大小异常的大，或者 `free` 释放了不应该释放的地址，就可能存在漏洞。进一步，我们可以结合 `malloc_usable_size` 来检查实际可用的内存大小，帮助定位溢出点。

**涉及的二进制底层、Linux、Android 内核及框架知识及举例说明：**

* **二进制底层:**  `dlmalloc` 直接操作内存地址和数据，涉及到指针运算、内存对齐等底层概念。例如，代码中会计算 chunk 的大小、元数据的位置等，这些操作都是基于二进制级别的内存布局。
* **Linux 内核:** `dlmalloc` 使用 `sbrk` 和 `mmap` 等系统调用向操作系统申请内存。`sbrk` 用于增加进程的堆空间，`mmap` 用于创建新的内存映射区域。理解这些系统调用的工作原理有助于理解 `dlmalloc` 如何与内核交互。
* **Android 内核:** Android 系统基于 Linux 内核，因此 `dlmalloc` 在 Android 上的行为与 Linux 类似。
* **框架:** 在 Android 框架中，例如 ART (Android Runtime)，底层的内存分配也依赖于类似 `dlmalloc` 的机制。理解 `dlmalloc` 可以帮助我们理解 Android 框架中对象的创建和销毁过程。

**举例说明:**

* **`sbrk`:**  `dlmalloc` 在堆空间不足时会调用 `sbrk` 系统调用来扩展堆。逆向分析时，我们可以观察 `sbrk` 的调用情况，了解程序何时以及如何向操作系统申请更多内存。
* **`mmap`:**  对于较大的内存分配请求，`dlmalloc` 可能会使用 `mmap` 来分配独立的内存区域。我们可以通过观察 `mmap` 的调用参数（地址、大小、保护属性等）来理解这些大块内存的用途。

**逻辑推理、假设输入与输出：**

虽然 `dlmalloc.c` 本身是一个实现，但我们可以对它的行为进行逻辑推理。

**假设输入:**

1. 调用 `dlmalloc(100)`：请求分配 100 字节的内存。
2. 调用 `dlmalloc(200)`：请求分配 200 字节的内存。
3. 调用 `dlfree(ptr1)`：释放之前 `dlmalloc(100)` 返回的指针 `ptr1`。
4. 调用 `dlmalloc(50)`：请求分配 50 字节的内存。

**预期输出/行为:**

1. `dlmalloc(100)` 可能会返回一个指向大小大于等于 100 字节的内存块的指针。由于内存分配器有对齐和元数据的需求，实际分配的大小可能会略大。
2. `dlmalloc(200)` 类似地会返回一个指向大小大于等于 200 字节的内存块的指针。
3. `dlfree(ptr1)` 会将 `ptr1` 指向的内存块标记为空闲，并可能尝试与相邻的空闲块合并。
4. `dlmalloc(50)` 可能会重用之前 `free` 掉的 100 字节的内存块（如果大小合适且没有被合并到更大的块中），或者分配一个新的块。

**涉及用户或编程常见的使用错误及举例说明：**

`dlmalloc` 是一个底层的内存分配器，用户在使用时容易犯以下错误：

1. **内存泄漏:** 分配了内存但忘记释放。
   ```c
   void foo() {
       void *p = dlmalloc(1024);
       // ... 使用 p，但是没有 dlfree(p);
   }
   ```
   如果 `foo` 函数被多次调用，将会导致内存持续增长。
2. **重复释放 (Double Free):**  多次释放同一个内存块。
   ```c
   void *p = dlmalloc(1024);
   dlfree(p);
   dlfree(p); // 错误：重复释放
   ```
   这会导致内存分配器内部数据结构的损坏，可能导致程序崩溃或安全漏洞。
3. **释放未分配的内存:** 尝试释放不是由 `dlmalloc` 分配的内存，或者已经释放过的内存。
   ```c
   int a;
   dlfree(&a); // 错误：释放栈上的变量
   ```
4. **缓冲区溢出:** 写入超过已分配内存块大小的数据。
   ```c
   void *p = dlmalloc(10);
   strcpy(p, "This is a long string"); // 错误：溢出 p 的缓冲区
   ```
   这会覆盖相邻的内存区域，可能导致程序崩溃或安全漏洞。
5. **Use-After-Free:**  释放内存后继续使用指向该内存的指针。
   ```c
   void *p = dlmalloc(1024);
   // ... 使用 p ...
   dlfree(p);
   // ... 再次使用 p ... // 错误：释放后使用
   ```
   这会导致访问已释放的内存，其内容可能已被修改或重新分配。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

作为 Frida 的一部分，用户不会直接操作 `dlmalloc.c` 的代码。但是，当 Frida 对目标进程进行动态插桩时，它会在目标进程的地址空间中分配内存来存储 hook 代码、传递参数、存储结果等。

1. **用户启动 Frida 并连接到目标进程:** 用户使用 Frida 命令行工具或 API 连接到想要分析的目标进程。
2. **用户编写和执行 Frida 脚本:**  用户编写 JavaScript 代码，使用 Frida 提供的 API 来 hook 目标进程的函数。例如，用户可能使用 `Interceptor.attach` 来 hook 某个函数。
3. **Frida 在目标进程中分配内存:** 当 Frida 执行用户的 hook 代码时，`frida-gum` 组件会调用目标进程中的内存分配器（很可能就是 `dlmalloc`，或者目标进程链接的其他分配器）来分配内存。
    *  例如，当 `Interceptor.attach` 时，Frida 需要在目标函数入口处插入 jump 指令，并将原始指令保存起来，这需要分配内存。
    *  当 hook 函数有参数或返回值时，Frida 需要分配内存来传递这些数据。
    *  Frida 自身的一些数据结构也需要动态分配内存。
4. **`dlmalloc.c` 中的代码被执行:**  当目标进程需要分配内存时，如果它使用的是 `dlmalloc`，那么 `dlmalloc.c` 中的代码就会被执行，来完成内存的分配操作。

**调试线索:**

如果用户在使用 Frida 时遇到与内存相关的问题（例如，目标进程崩溃、Frida 脚本运行异常），可以考虑以下调试线索，这可能与 `dlmalloc` 的行为有关：

* **目标进程的内存使用情况异常增长:**  可能是 Frida 的某些 hook 导致了内存泄漏。
* **Frida 脚本尝试访问无效内存地址:**  可能是 hook 代码中使用了已被释放的内存。
* **目标进程在执行 Frida hook 代码时崩溃:**  可能是 Frida 分配的内存与目标进程的内存布局冲突，或者 hook 代码本身存在内存错误。

通过分析 Frida 的日志、目标进程的崩溃信息，并结合对 `dlmalloc` 原理的理解，可以帮助定位问题。

总而言之，`frida/subprojects/frida-gum/gum/dlmalloc.c` 的这段代码是 `dlmalloc` 内存分配器的核心组成部分，定义了其配置、数据结构和公共接口，为 Frida 在目标进程中进行动态插桩提供了必要的内存管理功能。理解这段代码对于深入理解 Frida 的工作原理以及排查与内存相关的错误至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/dlmalloc.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
IZE_T
#endif  /* HAVE_MMAP */
#endif  /* DEFAULT_MMAP_THRESHOLD */
#ifndef MAX_RELEASE_CHECK_RATE
#if HAVE_MMAP
#define MAX_RELEASE_CHECK_RATE 4095
#else
#define MAX_RELEASE_CHECK_RATE MAX_SIZE_T
#endif /* HAVE_MMAP */
#endif /* MAX_RELEASE_CHECK_RATE */
#ifndef USE_BUILTIN_FFS
#define USE_BUILTIN_FFS 0
#endif  /* USE_BUILTIN_FFS */
#ifndef USE_DEV_RANDOM
#define USE_DEV_RANDOM 0
#endif  /* USE_DEV_RANDOM */
#ifndef NO_MALLINFO
#define NO_MALLINFO 0
#endif  /* NO_MALLINFO */
#ifndef MALLINFO_FIELD_TYPE
#define MALLINFO_FIELD_TYPE size_t
#endif  /* MALLINFO_FIELD_TYPE */
#ifndef NO_MALLOC_STATS
#define NO_MALLOC_STATS 0
#endif  /* NO_MALLOC_STATS */
#ifndef NO_SEGMENT_TRAVERSAL
#define NO_SEGMENT_TRAVERSAL 0
#endif /* NO_SEGMENT_TRAVERSAL */

/*
  mallopt tuning options.  SVID/XPG defines four standard parameter
  numbers for mallopt, normally defined in malloc.h.  None of these
  are used in this malloc, so setting them has no effect. But this
  malloc does support the following options.
*/

#undef M_TRIM_THRESHOLD
#undef M_GRANULARITY
#undef M_MMAP_THRESHOLD
#define M_TRIM_THRESHOLD     (-1)
#define M_GRANULARITY        (-2)
#define M_MMAP_THRESHOLD     (-3)

/* ------------------------ Mallinfo declarations ------------------------ */

#if !NO_MALLINFO
/*
  This version of malloc supports the standard SVID/XPG mallinfo
  routine that returns a struct containing usage properties and
  statistics. It should work on any system that has a
  /usr/include/malloc.h defining struct mallinfo.  The main
  declaration needed is the mallinfo struct that is returned (by-copy)
  by mallinfo().  The malloinfo struct contains a bunch of fields that
  are not even meaningful in this version of malloc.  These fields are
  are instead filled by mallinfo() with other numbers that might be of
  interest.

  HAVE_USR_INCLUDE_MALLOC_H should be set if you have a
  /usr/include/malloc.h file that includes a declaration of struct
  mallinfo.  If so, it is included; else a compliant version is
  declared below.  These must be precisely the same for mallinfo() to
  work.  The original SVID version of this struct, defined on most
  systems with mallinfo, declares all fields as ints. But some others
  define as unsigned long. If your system defines the fields using a
  type of different width than listed here, you MUST #include your
  system version and #define HAVE_USR_INCLUDE_MALLOC_H.
*/

/* #define HAVE_USR_INCLUDE_MALLOC_H */

#ifdef HAVE_USR_INCLUDE_MALLOC_H
#include "/usr/include/malloc.h"
#else /* HAVE_USR_INCLUDE_MALLOC_H */
#ifndef STRUCT_MALLINFO_DECLARED
/* HP-UX (and others?) redefines mallinfo unless _STRUCT_MALLINFO is defined */
#define _STRUCT_MALLINFO
#define STRUCT_MALLINFO_DECLARED 1
struct mallinfo {
  MALLINFO_FIELD_TYPE arena;    /* non-mmapped space allocated from system */
  MALLINFO_FIELD_TYPE ordblks;  /* number of free chunks */
  MALLINFO_FIELD_TYPE smblks;   /* always 0 */
  MALLINFO_FIELD_TYPE hblks;    /* always 0 */
  MALLINFO_FIELD_TYPE hblkhd;   /* space in mmapped regions */
  MALLINFO_FIELD_TYPE usmblks;  /* maximum total allocated space */
  MALLINFO_FIELD_TYPE fsmblks;  /* always 0 */
  MALLINFO_FIELD_TYPE uordblks; /* total allocated space */
  MALLINFO_FIELD_TYPE fordblks; /* total free space */
  MALLINFO_FIELD_TYPE keepcost; /* releasable (via malloc_trim) space */
};
#endif /* STRUCT_MALLINFO_DECLARED */
#endif /* HAVE_USR_INCLUDE_MALLOC_H */
#endif /* NO_MALLINFO */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if !ONLY_MSPACES

/* ------------------- Declarations of public routines ------------------- */

#ifndef USE_DL_PREFIX
#define dlcalloc               calloc
#define dlfree                 free
#define dlmalloc               malloc
#define dlmemalign             memalign
#define dlposix_memalign       posix_memalign
#define dlrealloc              realloc
#define dlrealloc_in_place     realloc_in_place
#define dlvalloc               valloc
#define dlpvalloc              pvalloc
#define dlmallinfo             mallinfo
#define dlmallopt              mallopt
#define dlmalloc_trim          malloc_trim
#define dlmalloc_stats         malloc_stats
#define dlmalloc_usable_size   malloc_usable_size
#define dlmalloc_footprint     malloc_footprint
#define dlmalloc_max_footprint malloc_max_footprint
#define dlmalloc_footprint_limit malloc_footprint_limit
#define dlmalloc_set_footprint_limit malloc_set_footprint_limit
#define dlmalloc_inspect_all   malloc_inspect_all
#define dlindependent_calloc   independent_calloc
#define dlindependent_comalloc independent_comalloc
#define dlbulk_free            bulk_free
#endif /* USE_DL_PREFIX */

/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or
  null if no space is available, in which case errno is set to ENOMEM
  on ANSI C systems.

  If n is zero, malloc returns a minimum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 32 bytes on 64bit
  systems.)  Note that size_t is an unsigned type, so calls with
  arguments that would be negative if signed are interpreted as
  requests for huge amounts of space, which will often fail. The
  maximum supported value of n differs across systems, but is in all
  cases less than the maximum representable value of a size_t.
*/
DLMALLOC_EXPORT void* dlmalloc(size_t);

/*
  free(void* p)
  Releases the chunk of memory pointed to by p, that had been previously
  allocated using malloc or a related routine such as realloc.
  It has no effect if p is null. If p was not malloced or already
  freed, free(p) will by default cause the current program to abort.
*/
DLMALLOC_EXPORT void  dlfree(void*);

/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
DLMALLOC_EXPORT void* dlcalloc(size_t, size_t);

/*
  realloc(void* p, size_t n)
  Returns a pointer to a chunk of size n that contains the same data
  as does chunk p up to the minimum of (n, p's size) bytes, or null
  if no space is available.

  The returned pointer may or may not be the same as p. The algorithm
  prefers extending p in most cases when possible, otherwise it
  employs the equivalent of a malloc-copy-free sequence.

  If p is null, realloc is equivalent to malloc.

  If space is not available, realloc returns null, errno is set (if on
  ANSI) and p is NOT freed.

  if n is for fewer bytes than already held by p, the newly unused
  space is lopped off and freed if possible.  realloc with a size
  argument of zero (re)allocates a minimum-sized chunk.

  The old unix realloc convention of allowing the last-free'd chunk
  to be used as an argument to realloc is not supported.
*/
DLMALLOC_EXPORT void* dlrealloc(void*, size_t);

/*
  realloc_in_place(void* p, size_t n)
  Resizes the space allocated for p to size n, only if this can be
  done without moving p (i.e., only if there is adjacent space
  available if n is greater than p's current allocated size, or n is
  less than or equal to p's size). This may be used instead of plain
  realloc if an alternative allocation strategy is needed upon failure
  to expand space; for example, reallocation of a buffer that must be
  memory-aligned or cleared. You can use realloc_in_place to trigger
  these alternatives only when needed.

  Returns p if successful; otherwise null.
*/
DLMALLOC_EXPORT void* dlrealloc_in_place(void*, size_t);

/*
  memalign(size_t alignment, size_t n);
  Returns a pointer to a newly allocated chunk of n bytes, aligned
  in accord with the alignment argument.

  The alignment argument should be a power of two. If the argument is
  not a power of two, the nearest greater power is used.
  8-byte alignment is guaranteed by normal malloc calls, so don't
  bother calling memalign with an argument of 8 or less.

  Overreliance on memalign is a sure way to fragment space.
*/
DLMALLOC_EXPORT void* dlmemalign(size_t, size_t);

/*
  int posix_memalign(void** pp, size_t alignment, size_t n);
  Allocates a chunk of n bytes, aligned in accord with the alignment
  argument. Differs from memalign only in that it (1) assigns the
  allocated memory to *pp rather than returning it, (2) fails and
  returns EINVAL if the alignment is not a power of two (3) fails and
  returns ENOMEM if memory cannot be allocated.
*/
DLMALLOC_EXPORT int dlposix_memalign(void**, size_t, size_t);

/*
  valloc(size_t n);
  Equivalent to memalign(pagesize, n), where pagesize is the page
  size of the system. If the pagesize is unknown, 4096 is used.
*/
DLMALLOC_EXPORT void* dlvalloc(size_t);

/*
  mallopt(int parameter_number, int parameter_value)
  Sets tunable parameters The format is to provide a
  (parameter-number, parameter-value) pair.  mallopt then sets the
  corresponding parameter to the argument value if it can (i.e., so
  long as the value is meaningful), and returns 1 if successful else
  0.  To workaround the fact that mallopt is specified to use int,
  not size_t parameters, the value -1 is specially treated as the
  maximum unsigned size_t value.

  SVID/XPG/ANSI defines four standard param numbers for mallopt,
  normally defined in malloc.h.  None of these are use in this malloc,
  so setting them has no effect. But this malloc also supports other
  options in mallopt. See below for details.  Briefly, supported
  parameters are as follows (listed defaults are for "typical"
  configurations).

  Symbol            param #  default    allowed param values
  M_TRIM_THRESHOLD     -1   2*1024*1024   any   (-1 disables)
  M_GRANULARITY        -2     page size   any power of 2 >= page size
  M_MMAP_THRESHOLD     -3      256*1024   any   (or 0 if no MMAP support)
*/
DLMALLOC_EXPORT int dlmallopt(int, int);

/*
  malloc_footprint();
  Returns the number of bytes obtained from the system.  The total
  number of bytes allocated by malloc, realloc etc., is less than this
  value. Unlike mallinfo, this function returns only a precomputed
  result, so can be called frequently to monitor memory consumption.
  Even if locks are otherwise defined, this function does not use them,
  so results might not be up to date.
*/
DLMALLOC_EXPORT size_t dlmalloc_footprint(void);

/*
  malloc_max_footprint();
  Returns the maximum number of bytes obtained from the system. This
  value will be greater than current footprint if deallocated space
  has been reclaimed by the system. The peak number of bytes allocated
  by malloc, realloc etc., is less than this value. Unlike mallinfo,
  this function returns only a precomputed result, so can be called
  frequently to monitor memory consumption.  Even if locks are
  otherwise defined, this function does not use them, so results might
  not be up to date.
*/
DLMALLOC_EXPORT size_t dlmalloc_max_footprint(void);

/*
  malloc_footprint_limit();
  Returns the number of bytes that the heap is allowed to obtain from
  the system, returning the last value returned by
  malloc_set_footprint_limit, or the maximum size_t value if
  never set. The returned value reflects a permission. There is no
  guarantee that this number of bytes can actually be obtained from
  the system.
*/
DLMALLOC_EXPORT size_t dlmalloc_footprint_limit();

/*
  malloc_set_footprint_limit();
  Sets the maximum number of bytes to obtain from the system, causing
  failure returns from malloc and related functions upon attempts to
  exceed this value. The argument value may be subject to page
  rounding to an enforceable limit; this actual value is returned.
  Using an argument of the maximum possible size_t effectively
  disables checks. If the argument is less than or equal to the
  current malloc_footprint, then all future allocations that require
  additional system memory will fail. However, invocation cannot
  retroactively deallocate existing used memory.
*/
DLMALLOC_EXPORT size_t dlmalloc_set_footprint_limit(size_t bytes);

#if MALLOC_INSPECT_ALL
/*
  malloc_inspect_all(void(*handler)(void *start,
                                    void *end,
                                    size_t used_bytes,
                                    void* callback_arg),
                      void* arg);
  Traverses the heap and calls the given handler for each managed
  region, skipping all bytes that are (or may be) used for bookkeeping
  purposes.  Traversal does not include include chunks that have been
  directly memory mapped. Each reported region begins at the start
  address, and continues up to but not including the end address.  The
  first used_bytes of the region contain allocated data. If
  used_bytes is zero, the region is unallocated. The handler is
  invoked with the given callback argument. If locks are defined, they
  are held during the entire traversal. It is a bad idea to invoke
  other malloc functions from within the handler.

  For example, to count the number of in-use chunks with size greater
  than 1000, you could write:
  static int count = 0;
  void count_chunks(void* start, void* end, size_t used, void* arg) {
    if (used >= 1000) ++count;
  }
  then:
    malloc_inspect_all(count_chunks, NULL);

  malloc_inspect_all is compiled only if MALLOC_INSPECT_ALL is defined.
*/
DLMALLOC_EXPORT void dlmalloc_inspect_all(void(*handler)(void*, void *, size_t, void*),
                           void* arg);

#endif /* MALLOC_INSPECT_ALL */

#if !NO_MALLINFO
/*
  mallinfo()
  Returns (by copy) a struct containing various summary statistics:

  arena:     current total non-mmapped bytes allocated from system
  ordblks:   the number of free chunks
  smblks:    always zero.
  hblks:     current number of mmapped regions
  hblkhd:    total bytes held in mmapped regions
  usmblks:   the maximum total allocated space. This will be greater
                than current total if trimming has occurred.
  fsmblks:   always zero
  uordblks:  current total allocated space (normal or mmapped)
  fordblks:  total free space
  keepcost:  the maximum number of bytes that could ideally be released
               back to system via malloc_trim. ("ideally" means that
               it ignores page restrictions etc.)

  Because these fields are ints, but internal bookkeeping may
  be kept as longs, the reported values may wrap around zero and
  thus be inaccurate.
*/
DLMALLOC_EXPORT struct mallinfo dlmallinfo(void);
#endif /* NO_MALLINFO */

/*
  independent_calloc(size_t n_elements, size_t element_size, void* chunks[]);

  independent_calloc is similar to calloc, but instead of returning a
  single cleared space, it returns an array of pointers to n_elements
  independent elements that can hold contents of size elem_size, each
  of which starts out cleared, and can be independently freed,
  realloc'ed etc. The elements are guaranteed to be adjacently
  allocated (this is not guaranteed to occur with multiple callocs or
  mallocs), which may also improve cache locality in some
  applications.

  The "chunks" argument is optional (i.e., may be null, which is
  probably the most typical usage). If it is null, the returned array
  is itself dynamically allocated and should also be freed when it is
  no longer needed. Otherwise, the chunks array must be of at least
  n_elements in length. It is filled in with the pointers to the
  chunks.

  In either case, independent_calloc returns this pointer array, or
  null if the allocation failed.  If n_elements is zero and "chunks"
  is null, it returns a chunk representing an array with zero elements
  (which should be freed if not wanted).

  Each element must be freed when it is no longer needed. This can be
  done all at once using bulk_free.

  independent_calloc simplifies and speeds up implementations of many
  kinds of pools.  It may also be useful when constructing large data
  structures that initially have a fixed number of fixed-sized nodes,
  but the number is not known at compile time, and some of the nodes
  may later need to be freed. For example:

  struct Node { int item; struct Node* next; };

  struct Node* build_list() {
    struct Node** pool;
    int n = read_number_of_nodes_needed();
    if (n <= 0) return 0;
    pool = (struct Node**)(independent_calloc(n, sizeof(struct Node), 0);
    if (pool == 0) die();
    // organize into a linked list...
    struct Node* first = pool[0];
    for (i = 0; i < n-1; ++i)
      pool[i]->next = pool[i+1];
    free(pool);     // Can now free the array (or not, if it is needed later)
    return first;
  }
*/
DLMALLOC_EXPORT void** dlindependent_calloc(size_t, size_t, void**);

/*
  independent_comalloc(size_t n_elements, size_t sizes[], void* chunks[]);

  independent_comalloc allocates, all at once, a set of n_elements
  chunks with sizes indicated in the "sizes" array.    It returns
  an array of pointers to these elements, each of which can be
  independently freed, realloc'ed etc. The elements are guaranteed to
  be adjacently allocated (this is not guaranteed to occur with
  multiple callocs or mallocs), which may also improve cache locality
  in some applications.

  The "chunks" argument is optional (i.e., may be null). If it is null
  the returned array is itself dynamically allocated and should also
  be freed when it is no longer needed. Otherwise, the chunks array
  must be of at least n_elements in length. It is filled in with the
  pointers to the chunks.

  In either case, independent_comalloc returns this pointer array, or
  null if the allocation failed.  If n_elements is zero and chunks is
  null, it returns a chunk representing an array with zero elements
  (which should be freed if not wanted).

  Each element must be freed when it is no longer needed. This can be
  done all at once using bulk_free.

  independent_comallac differs from independent_calloc in that each
  element may have a different size, and also that it does not
  automatically clear elements.

  independent_comalloc can be used to speed up allocation in cases
  where several structs or objects must always be allocated at the
  same time.  For example:

  struct Head { ... }
  struct Foot { ... }

  void send_message(char* msg) {
    int msglen = strlen(msg);
    size_t sizes[3] = { sizeof(struct Head), msglen, sizeof(struct Foot) };
    void* chunks[3];
    if (independent_comalloc(3, sizes, chunks) == 0)
      die();
    struct Head* head = (struct Head*)(chunks[0]);
    char*        body = (char*)(chunks[1]);
    struct Foot* foot = (struct Foot*)(chunks[2]);
    // ...
  }

  In general though, independent_comalloc is worth using only for
  larger values of n_elements. For small values, you probably won't
  detect enough difference from series of malloc calls to bother.

  Overuse of independent_comalloc can increase overall memory usage,
  since it cannot reuse existing noncontiguous small chunks that
  might be available for some of the elements.
*/
DLMALLOC_EXPORT void** dlindependent_comalloc(size_t, size_t*, void**);

/*
  bulk_free(void* array[], size_t n_elements)
  Frees and clears (sets to null) each non-null pointer in the given
  array.  This is likely to be faster than freeing them one-by-one.
  If footers are used, pointers that have been allocated in different
  mspaces are not freed or cleared, and the count of all such pointers
  is returned.  For large arrays of pointers with poor locality, it
  may be worthwhile to sort this array before calling bulk_free.
*/
DLMALLOC_EXPORT size_t  dlbulk_free(void**, size_t n_elements);

/*
  pvalloc(size_t n);
  Equivalent to valloc(minimum-page-that-holds(n)), that is,
  round up n to nearest pagesize.
 */
DLMALLOC_EXPORT void*  dlpvalloc(size_t);

/*
  malloc_trim(size_t pad);

  If possible, gives memory back to the system (via negative arguments
  to sbrk) if there is unused memory at the `high' end of the malloc
  pool or in unused MMAP segments. You can call this after freeing
  large blocks of memory to potentially reduce the system-level memory
  requirements of a program. However, it cannot guarantee to reduce
  memory. Under some allocation patterns, some large free blocks of
  memory will be locked between two used chunks, so they cannot be
  given back to the system.

  The `pad' argument to malloc_trim represents the amount of free
  trailing space to leave untrimmed. If this argument is zero, only
  the minimum amount of memory to maintain internal data structures
  will be left. Non-zero arguments can be supplied to maintain enough
  trailing space to service future expected allocations without having
  to re-obtain memory from the system.

  Malloc_trim returns 1 if it actually released any memory, else 0.
*/
DLMALLOC_EXPORT int  dlmalloc_trim(size_t);

/*
  malloc_stats();
  Prints on stderr the amount of space obtained from the system (both
  via sbrk and mmap), the maximum amount (which may be more than
  current if malloc_trim and/or munmap got called), and the current
  number of bytes allocated via malloc (or realloc, etc) but not yet
  freed. Note that this is the number of bytes allocated, not the
  number requested. It will be larger than the number requested
  because of alignment and bookkeeping overhead. Because it includes
  alignment wastage as being in use, this figure may be greater than
  zero even when no user-level chunks are allocated.

  The reported current and maximum system memory can be inaccurate if
  a program makes other calls to system memory allocation functions
  (normally sbrk) outside of malloc.

  malloc_stats prints only the most commonly interesting statistics.
  More information can be obtained by calling mallinfo.
*/
DLMALLOC_EXPORT void  dlmalloc_stats(void);

/*
  malloc_usable_size(void* p);

  Returns the number of bytes you can actually use in
  an allocated chunk, which may be more than you requested (although
  often not) due to alignment and minimum size constraints.
  You can use this many bytes without worrying about
  overwriting other allocated objects. This is not a particularly great
  programming practice. malloc_usable_size can be more useful in
  debugging and assertions, for example:

  p = malloc(n);
  assert(malloc_usable_size(p) >= 256);
*/
size_t dlmalloc_usable_size(void*);

#endif /* ONLY_MSPACES */

#if MSPACES

/*
  mspace is an opaque type representing an independent
  region of space that supports mspace_malloc, etc.
*/
typedef void* mspace;

/*
  create_mspace creates and returns a new independent space with the
  given initial capacity, or, if 0, the default granularity size.  It
  returns null if there is no system memory available to create the
  space.  If argument locked is non-zero, the space uses a separate
  lock to control access. The capacity of the space will grow
  dynamically as needed to service mspace_malloc requests.  You can
  control the sizes of incremental increases of this space by
  compiling with a different DEFAULT_GRANULARITY or dynamically
  setting with mallopt(M_GRANULARITY, value).
*/
DLMALLOC_EXPORT mspace create_mspace(size_t capacity, int locked);

/*
  destroy_mspace destroys the given space, and attempts to return all
  of its memory back to the system, returning the total number of
  bytes freed. After destruction, the results of access to all memory
  used by the space become undefined.
*/
DLMALLOC_EXPORT size_t destroy_mspace(mspace msp);

/*
  create_mspace_with_base uses the memory supplied as the initial base
  of a new mspace. Part (less than 128*sizeof(size_t) bytes) of this
  space is used for bookkeeping, so the capacity must be at least this
  large. (Otherwise 0 is returned.) When this initial space is
  exhausted, additional memory will be obtained from the system.
  Destroying this space will deallocate all additionally allocated
  space (if possible) but not the initial base.
*/
DLMALLOC_EXPORT mspace create_mspace_with_base(void* base, size_t capacity, int locked);

/*
  mspace_track_large_chunks controls whether requests for large chunks
  are allocated in their own untracked mmapped regions, separate from
  others in this mspace. By default large chunks are not tracked,
  which reduces fragmentation. However, such chunks are not
  necessarily released to the system upon destroy_mspace.  Enabling
  tracking by setting to true may increase fragmentation, but avoids
  leakage when relying on destroy_mspace to release all memory
  allocated using this space.  The function returns the previous
  setting.
*/
DLMALLOC_EXPORT int mspace_track_large_chunks(mspace msp, int enable);


/*
  mspace_malloc behaves as malloc, but operates within
  the given space.
*/
DLMALLOC_EXPORT void* mspace_malloc(mspace msp, size_t bytes);

/*
  mspace_free behaves as free, but operates within
  the given space.

  If compiled with FOOTERS==1, mspace_free is not actually needed.
  free may be called instead of mspace_free because freed chunks from
  any space are handled by their originating spaces.
*/
DLMALLOC_EXPORT void mspace_free(mspace msp, void* mem);

/*
  mspace_realloc behaves as realloc, but operates within
  the given space.

  If compiled with FOOTERS==1, mspace_realloc is not actually
  needed.  realloc may be called instead of mspace_realloc because
  realloced chunks from any space are handled by their originating
  spaces.
*/
DLMALLOC_EXPORT void* mspace_realloc(mspace msp, void* mem, size_t newsize);

/*
  mspace_calloc behaves as calloc, but operates within
  the given space.
*/
DLMALLOC_EXPORT void* mspace_calloc(mspace msp, size_t n_elements, size_t elem_size);

/*
  mspace_memalign behaves as memalign, but operates within
  the given space.
*/
DLMALLOC_EXPORT void* mspace_memalign(mspace msp, size_t alignment, size_t bytes);

/*
  mspace_independent_calloc behaves as independent_calloc, but
  operates within the given space.
*/
DLMALLOC_EXPORT void** mspace_independent_calloc(mspace msp, size_t n_elements,
                                 size_t elem_size, void* chunks[]);

/*
  mspace_independent_comalloc behaves as independent_comalloc, but
  operates within the given space.
*/
DLMALLOC_EXPORT void** mspace_independent_comalloc(mspace msp, size_t n_elements,
                                   size_t sizes[], void* chunks[]);

/*
  mspace_footprint() returns the number of bytes obtained from the
  system for this space.
*/
DLMALLOC_EXPORT size_t mspace_footprint(mspace msp);

/*
  mspace_max_footprint() returns the peak number of bytes obtained from the
  system for this space.
*/
DLMALLOC_EXPORT size_t mspace_max_footprint(mspace msp);


#if !NO_MALLINFO
/*
  mspace_mallinfo behaves as mallinfo, but reports properties of
  the given space.
*/
DLMALLOC_EXPORT struct mallinfo mspace_mallinfo(mspace msp);
#endif /* NO_MALLINFO */

/*
  malloc_usable_size(void* p) behaves the same as malloc_usable_size;
*/
DLMALLOC_EXPORT size_t mspace_usable_size(const void* mem);

/*
  mspace_malloc_stats behaves as malloc_stats, but reports
  properties of the given space.
*/
DLMALLOC_EXPORT void mspace_malloc_stats(mspace msp);

/*
  mspace_trim behaves as malloc_trim, but
  operates within the given space.
*/
DLMALLOC_EXPORT int mspace_trim(mspace msp, size_t pad);

/*
  An alias for mallopt.
*/
DLMALLOC_EXPORT int mspace_mallopt(int, int);

#endif /* MSPACES */

#ifdef __cplusplus
}  /* end of extern "C" */
#endif /* __cplusplus */

/*
  ========================================================================
  To make a fully customizable malloc.h header file, cut everything
  above this line, put into file malloc.h, edit to suit, and #include it
  on the next line, as well as in programs that use this malloc.
  ========================================================================
*/

/* #include "malloc.h" */

/*------------------------------ internal #includes ---------------------- */

#ifdef _MSC_VER
#pragma warning( disable : 4146 ) /* no "unsigned" warnings */
#endif /* _MSC_VER */
#if !NO_MALLOC_STATS
#include <stdio.h>       /* for printing in malloc_stats */
#endif /* NO_MALLOC_STATS */
#ifndef LACKS_ERRNO_H
#include <errno.h>       /* for MALLOC_FAILURE_ACTION */
#endif /* LACKS_ERRNO_H */
#ifdef DEBUG
#if ABORT_ON_ASSERT_FAILURE
#undef assert
#define assert(x) if(!(x)) ABORT
#else /* ABORT_ON_ASSERT_FAILURE */
#include <assert.h>
#endif /* ABORT_ON_ASSERT_FAILURE */
#else  /* DEBUG */
#ifndef assert
#define assert(x)
#endif
#define DEBUG 0
#endif /* DEBUG */
#if !defined(WIN32) && !defined(LACKS_TIME_H)
#include <time.h>        /* for magic initialization */
#endif /* WIN32 */
#ifndef LACKS_STDLIB_H
#include <stdlib.h>      /* for abort() */
#endif /* LACKS_STDLIB_H */
#ifndef LACKS_STRING_H
#include <string.h>      /* for memset etc */
#endif  /* LACKS_STRING_H */
#if USE_BUILTIN_FFS
#ifndef LACKS_STRINGS_H
#include <strings.h>     /* for ffs */
#endif /* LACKS_STRINGS_H */
#endif /* USE_BUILTIN_FFS */
#if HAVE_MMAP
#ifndef LACKS_SYS_MMAN_H
/* On some versions of linux, mremap decl in mman.h needs __USE_GNU set */
#if (defined(linux) && !defined(__USE_GNU))
#define __USE_GNU 1
#include <sys/mman.h>    /* for mmap */
#undef __USE_GNU
#else
#include <sys/mman.h>    /* for mmap */
#endif /* linux */
#endif /* LACKS_SYS_MMAN_H */
#ifndef LACKS_FCNTL_H
#include <fcntl.h>
#endif /* LACKS_FCNTL_H */
#endif /* HAVE_MMAP */
#ifndef LACKS_UNISTD_H
#include <unistd.h>     /* for sbrk, sysconf */
#else /* LACKS_UNISTD_H */
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
extern void*     sbrk(ptrdiff_t);
#endif /* FreeBSD etc */
#endif /* LACKS_UNISTD_H */

/* Declarations for locking */
#if USE_LOCKS
#ifndef WIN32
#if defined (__SVR4) && defined (__sun)  /* solaris */
#include <thread.h>
#elif !defined(LACKS_SCHED_H)
#include <sched.h>
#endif /* solaris or LACKS_SCHED_H */
#if (defined(USE_RECURSIVE_LOCKS) && USE_RECURSIVE_LOCKS != 0) || !USE_SPIN_LOCKS
#include <pthread.h>
#endif /* USE_RECURSIVE_LOCKS ... */
#elif defined(_MSC_VER)
#ifndef _M_AMD64
/* These are already defined on AMD64 builds */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
LONG __cdecl _InterlockedCompareExchange(LONG volatile *Dest, LONG Exchange, LONG Comp);
LONG __cdecl _InterlockedExchange(LONG volatile *Target, LONG Value);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _M_AMD64 */
#pragma intrinsic (_InterlockedCompareExchange)
#pragma intrinsic (_InterlockedExchange)
#define interlockedcompareexchange _InterlockedCompareExchange
#define interlockedexchange _InterlockedExchange
#elif defined(WIN32) && defined(__GNUC__)
#define interlockedcompareexchange(a, b, c) __sync_val_compare_and_swap(a, c, b)
#define interlockedexchange __sync_lock_test_and_set
#endif /* Win32 */
#else /* USE_LOCKS */
#endif /* USE_LOCKS */

#ifndef LOCK_AT_FORK
#define LOCK_AT_FORK 0
#endif

/* Declarations for bit scanning on win32 */
#if defined(_MSC_VER) && _MSC_VER>=1300
#ifndef BitScanForward /* Try to avoid pulling in WinNT.h */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
unsigned char _BitScanForward(unsigned long *index, unsigned long mask);
unsigned char _BitScanReverse(unsigned long *index, unsigned long mask);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse
#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)
#endif /* BitScanForward */
#endif /* defined(_MSC_VER) && _MSC_VER>=1300 */

#ifndef WIN32
#ifndef malloc_getpagesize
#  ifdef _SC_PAGESIZE         /* some SVR4 systems omit an underscore */
#    ifndef _SC_PAGE_SIZE
#      define _SC_PAGE_SIZE _SC_PAGESIZE
#    endif
#  endif
#  ifdef _SC_PAGE_SIZE
#    define malloc_getpagesize sysconf(_SC_PAGE_SIZE)
#  else
#    if defined(BSD) || defined(DGUX) || defined(HAVE_GETPAGESIZE)
       extern size_t getpagesize();
#      define malloc_getpagesize getpagesize()
#    else
#      ifdef WIN32 /* use supplied emulation of getpagesize */
#        define malloc_getpagesize getpagesize()
#      else
#        ifndef LACKS_SYS_PARAM_H
#          include <sys/param.h>
#        endif
#        ifdef EXEC_PAGESIZE
#          define malloc_getpagesize EXEC_PAGESIZE
#        else
#          ifdef NBPG
#            ifndef CLSIZE
#              define malloc_getpagesize NBPG
#            else
#              define malloc_getpagesize (NBPG * CLSIZE)
#            endif
#          else
#            ifdef NBPC
#              define malloc_getpagesize NBPC
#            else
#              ifdef PAGESIZE
#                define malloc_getpagesize PAGESIZE
#              else /* just guess */
#                define malloc_getpagesize ((size_t)4096U)
#              endif
#            endif
#          endif
#        endif
#      endif
#    endif
#  endif
#endif
#endif

/* ------------------- size_t and alignment properties -------------------- */

/* The byte and bit size of a size_t */
#define SIZE_T_SIZE         (sizeof(size
```