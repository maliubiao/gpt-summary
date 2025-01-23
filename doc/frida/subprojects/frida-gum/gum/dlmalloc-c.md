Response:
Let's break down the thought process for analyzing this C code snippet, especially within the context of the user's request.

**1. Initial Understanding of the Request:**

The core request is to understand the *functionality* of this `dlmalloc.c` file from the Frida dynamic instrumentation tool. Keywords like "frida," "dynamic instrumentation," "reverse engineering," "binary level," "Linux/Android kernel/framework," "logical reasoning," "user errors," and "debugging" provide the necessary context. The user also emphasizes that this is *part 1 of 7*, suggesting a modular structure and the need for a summarized overview in this part.

**2. High-Level Scan and Keyword Identification:**

The first step is to quickly skim the code and identify prominent features. I'd look for:

* **Comments:** The initial block of comments is crucial. It describes the purpose, version, quickstart guide, vital statistics, security features, thread-safety, system requirements, algorithm overview, and compile-time options. This is a goldmine of information.
* **Function Names (even if not the full code):**  The comments mention `malloc`, `free`, `realloc`, `calloc`, `mspace_malloc`, `mspace_free`, `create_mspace`, `malloc_stats`, `mallinfo`, `malloc_trim`, `mallopt`, `malloc_set_footprint_limit`, etc. These names immediately suggest memory management functionality.
* **Preprocessor Directives (`#define`, `#ifdef`, `#ifndef`):**  The extensive use of these directives indicates configurable behavior and platform-specific adaptations. Looking at the defined macros like `WIN32`, `DLMALLOC_EXPORT`, `MALLOC_ALIGNMENT`, `MSPACES`, `USE_LOCKS`, `FOOTERS`, `INSECURE`, `HAVE_MMAP`, `DEFAULT_GRANULARITY`, etc., reveals various features and configuration options.
* **Data Types:**  `size_t`, `void *`, and mentions of pointers and sizes suggest memory manipulation at a low level.
* **Security-Related Terms:** "security," "corruption," "errors," "checks," "footers" highlight the code's attention to robustness and error handling.
* **Concurrency-Related Terms:** "thread-safety," "locks," "mutex," "spin-locks" indicate support for multi-threaded environments.
* **System-Level Terms:** "sbrk," "mmap," "munmap," "pagesize," "kernel" hint at interaction with the operating system.

**3. Categorizing Functionality based on Identified Keywords:**

Based on the initial scan, I can start grouping the functionalities:

* **Core Memory Management:** `malloc`, `free`, `realloc`, `calloc` – This is the primary purpose.
* **Advanced Memory Management (MSPACES):** `mspace_malloc`, `mspace_free`, `create_mspace` –  For creating isolated memory heaps.
* **Configuration and Tuning:**  The numerous `#define` options and functions like `mallopt` and `malloc_set_footprint_limit` fall into this category.
* **Error Handling and Security:**  The comments about checks, `FOOTERS`, `INSECURE`, `PROCEED_ON_ERROR`, and actions like `ABORT` are relevant here.
* **Multi-threading Support:**  `USE_LOCKS`, `USE_SPIN_LOCKS`, `USE_RECURSIVE_LOCKS`, `LOCK_AT_FORK`.
* **System Interaction:**  `HAVE_MORECORE`, `MORECORE`, `HAVE_MMAP`, `MMAP_CLEARS`, `malloc_getpagesize`.
* **Debugging and Inspection:** `malloc_stats`, `mallinfo`, `MALLOC_INSPECT_ALL`, `DEBUG`.

**4. Relating Functionality to Reverse Engineering and Frida:**

Now, I need to connect the dots to the user's context.

* **Dynamic Instrumentation (Frida):**  A custom `malloc` implementation like this allows Frida to potentially intercept and monitor memory allocations within a target process. This is crucial for understanding how the target application uses memory, identifying memory leaks, and potentially even modifying memory behavior.
* **Reverse Engineering:** Understanding the memory allocation strategy of an application is a fundamental part of reverse engineering. This code reveals the underlying mechanisms of how memory is managed. Recognizing concepts like chunk headers, free lists, and the use of `mmap` provides valuable insights.

**5. Addressing Binary Level, Linux/Android Kernel/Framework:**

* **Binary Level:** The code directly deals with memory addresses, sizes, and bit manipulation (implied by alignment considerations). The concept of chunk overhead and metadata is inherently binary-level.
* **Linux/Android Kernel:** The use of `sbrk` and `mmap` directly interfaces with kernel system calls for memory management. Understanding page sizes and memory regions is also relevant to kernel concepts.

**6. Considering Logical Reasoning (Hypothetical Input/Output):**

While the full code isn't provided, I can make some basic assumptions:

* **Input:** A call to `malloc(100)`
* **Output:**  A pointer to a memory region of at least 100 bytes (plus overhead). The internal state of the allocator (free lists, etc.) will be updated.
* **Input:** A call to `free(ptr)` where `ptr` was previously returned by `malloc`.
* **Output:** The memory region pointed to by `ptr` is marked as free and potentially merged with adjacent free blocks.

**7. Identifying Common Usage Errors:**

The comments themselves highlight potential errors:

* **Double Free:** Freeing the same memory twice.
* **Use After Free:** Accessing memory after it has been freed.
* **Heap Overflow:** Writing beyond the allocated bounds of a chunk.
* **Freeing Unallocated Memory:** Attempting to free a pointer that was not returned by `malloc`.

**8. Tracing User Operations (Debugging Clues):**

How might a user end up debugging *this* code within Frida?

* **Investigating Memory Corruption:** A user observes crashes or unexpected behavior in a target application and suspects memory corruption. They might use Frida to hook `malloc` and `free` calls to track allocations and identify potential issues.
* **Analyzing Memory Usage:**  A user wants to understand the memory footprint of an application. They might use Frida to log allocation sizes and addresses.
* **Reverse Engineering Memory Layout:** A user wants to understand how an application organizes its data in memory. Examining the behavior of the allocator can provide clues.

**9. Summarizing Functionality for Part 1:**

Finally, I synthesize the identified functionalities into a concise summary, emphasizing the core purpose and highlighting the key capabilities. This involves extracting the most important points from the detailed analysis.

**Self-Correction/Refinement During the Process:**

* **Initial Overemphasis on Code Details:**  I might initially focus too much on the specific macros and less on the overarching purpose. I would then step back and prioritize the high-level functions and their implications.
* **Missing the Frida Connection:** If I initially analyze it purely as a standalone `malloc` implementation, I need to consciously bring in the Frida context and consider its role in dynamic instrumentation.
* **Not Explicitly Addressing All User Prompts:**  I would double-check that I've touched upon all the user's specific requests (reverse engineering, binary level, etc.).

By following this structured thought process, moving from a general understanding to specific details and then back to a summarized overview, I can effectively analyze the code snippet and provide a comprehensive answer that addresses all aspects of the user's request.
This is the first part of the `dlmalloc.c` source code, a well-known and widely used implementation of the `malloc`, `free`, `realloc`, and `calloc` memory allocation functions. It's designed to be a general-purpose allocator balancing speed, space efficiency, portability, and tunability.

Here's a breakdown of its functionality based on this first part:

**Core Functionality: Dynamic Memory Allocation**

The primary function of this code is to provide dynamic memory management for C/C++ programs. This involves:

* **`malloc(size_t size)`:**  Allocates a block of memory of at least the requested `size` bytes.
* **`free(void *ptr)`:** Releases a previously allocated block of memory back to the heap, making it available for future allocations.
* **`realloc(void *ptr, size_t size)`:**  Changes the size of a previously allocated block of memory. It might move the block if necessary.
* **`calloc(size_t num, size_t size)`:** Allocates a block of memory for an array of `num` elements, each of `size` bytes, and initializes all bytes to zero.

**Key Features and Characteristics Highlighted in Part 1:**

* **Public Domain:**  The code is explicitly released to the public domain, allowing for free use and modification.
* **Configurable:** The code uses a significant number of compile-time options (via `#define`) to customize its behavior for different platforms, performance needs, and security considerations. This is a major feature for adapting to various environments.
* **Alignment:** Enforces a minimum alignment (default 8 bytes) for allocated memory blocks. This is crucial for satisfying the requirements of various data types and architectures.
* **Overhead:**  Acknowledges the presence of internal overhead associated with each allocated chunk (for storing size and status information).
* **Minimum Allocation Size:** Defines the smallest possible block that can be allocated.
* **Security Features (Optional):**
    * **Static Safety:**  Guarantees not to modify memory below the heap base, protecting static variables.
    * **Error Detection:** Includes checks for improper `free` and `realloc` calls.
    * **Footers (Optional):**  Adding extra metadata at the end of chunks for more robust error checking.
    * **Options for Error Handling:**  Allows configuring the action taken upon detecting errors (abort, proceed, custom action).
* **Thread Safety (Optional):** Provides optional locking mechanisms (mutexes or spin locks) for use in multithreaded environments.
* **System Requirements:**  Can use either `sbrk` (or an equivalent) and/or `mmap`/`munmap` to obtain and release memory from the operating system.
* **Algorithm Overview:**  Mentions that it's primarily a "best-fit" allocator, but with optimizations for small allocations (locality) and large allocations (`mmap`).
* **Performance Considerations:**  States that operations are generally bounded by a constant factor related to the size of `size_t`. Discusses trade-offs related to segment traversal.
* **MSPACES (Optional):**  Provides support for creating multiple independent memory allocation spaces.
* **Compile-time Options (Extensive):** A significant portion of this first part is dedicated to explaining the various `#define` options that control aspects like:
    * Platform-specific settings (`WIN32`, `DARWIN`).
    * Exporting symbols (`DLMALLOC_EXPORT`).
    * Alignment (`MALLOC_ALIGNMENT`).
    * Enabling features like `MSPACES`, `USE_LOCKS`, `FOOTERS`, `INSECURE`.
    * System interaction (`HAVE_MORECORE`, `HAVE_MMAP`).
    * Tuning parameters (`DEFAULT_GRANULARITY`, `DEFAULT_TRIM_THRESHOLD`, `DEFAULT_MMAP_THRESHOLD`).
    * Debugging and error handling (`DEBUG`, `PROCEED_ON_ERROR`, `ABORT`).

**Relationship to Reverse Engineering:**

Understanding the underlying memory allocator is crucial in reverse engineering for several reasons:

* **Memory Layout Analysis:**  Knowing how memory is allocated and managed can help in understanding the layout of data structures within a program's memory. This code reveals details about chunk headers, free lists (though not explicitly shown here, they are part of dlmalloc's internal implementation), and how large allocations are handled.
* **Identifying Memory Leaks and Corruption:** By understanding how `malloc` and `free` are implemented, reverse engineers can better analyze memory dumps or use dynamic analysis tools like Frida to identify memory leaks (allocations without corresponding frees) or memory corruption issues (e.g., writing beyond allocated boundaries).
* **Exploiting Vulnerabilities:**  Knowledge of the memory allocator can be crucial for understanding and exploiting memory-related vulnerabilities like heap overflows. Understanding the structure of allocated chunks and the metadata involved is essential.

**Example in Reverse Engineering with Frida:**

Imagine you're reverse engineering a closed-source application and suspect a memory leak. You could use Frida to hook the `malloc` and `free` functions provided by this `dlmalloc.c` implementation (if the application uses it):

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['function'], message['payload']['details']))
    else:
        print(message)

def main():
    package_name = sys.argv[1] if len(sys.argv) > 1 else None
    if not package_name:
        print("Please provide the package name as an argument.")
        return

    try:
        session = frida.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process '{package_name}' not found. Are you sure it's running?")
        return

    script_code = """
    const mallocPtr = Module.findExportByName(null, 'malloc');
    const freePtr = Module.findExportByName(null, 'free');

    if (mallocPtr) {
        Interceptor.attach(mallocPtr, {
            onEnter: function(args) {
                const size = args[0].toInt();
                this.size = size;
            },
            onLeave: function(retval) {
                if (retval.isNull()) {
                    send({ function: 'malloc', details: 'Allocation failed for size: ' + this.size });
                } else {
                    send({ function: 'malloc', details: 'Allocated ' + this.size + ' bytes at: ' + retval });
                }
            }
        });
    } else {
        send({ function: 'malloc', details: 'Not found' });
    }

    if (freePtr) {
        Interceptor.attach(freePtr, {
            onEnter: function(args) {
                const ptr = args[0];
                send({ function: 'free', details: 'Freeing memory at: ' + ptr });
            }
        });
    } else {
        send({ function: 'free', details: 'Not found' });
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    input() # Keep the script running
    session.detach()

if __name__ == "__main__":
    main()
```

This Frida script hooks the `malloc` and `free` functions. By running this script against the target application, you could monitor the allocation and deallocation patterns, potentially revealing memory leaks (calls to `malloc` without corresponding `free`).

**Binary Level, Linux, Android Kernel & Framework:**

* **Binary Level:** The code manipulates memory addresses and sizes directly, which are fundamental concepts at the binary level. The alignment requirements and overhead calculations are also binary-level considerations.
* **Linux Kernel:** The code interacts with the Linux kernel through system calls like `sbrk` (historically) and `mmap`. The concepts of memory pages and virtual memory are relevant here. The `HAVE_MREMAP` option specifically targets the `mremap` system call available on Linux.
* **Android Kernel:** Android's kernel is based on Linux, so the same principles apply regarding memory management.
* **Android Framework:** While this code itself is a low-level memory allocator, the Android framework heavily relies on dynamic memory allocation. Understanding the underlying allocator can be helpful in analyzing framework components or debugging memory-related issues within Android applications.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider a simplified scenario:

**Hypothetical Input:**

1. `malloc(100)` is called.
2. `malloc(50)` is called shortly after.
3. `free` is *not* called on either of these allocations.

**Logical Output (Internal State):**

* The allocator would have allocated two chunks of memory, one of at least 100 bytes and another of at least 50 bytes.
* The internal data structures (likely free lists, though not directly visible in this part) would be updated to reflect these allocations.
* If `FOOTERS` were enabled, each allocated chunk would likely have a footer containing metadata.
* Because `free` wasn't called, these memory blocks would be considered "in use" and would not be available for future allocations unless `realloc` were used to expand an adjacent block. This scenario exemplifies a potential memory leak.

**User or Programming Common Usage Errors:**

This code (and the `malloc`/`free` interface in general) is susceptible to common errors:

* **Double Free:** Calling `free` on the same memory address twice. This can lead to heap corruption.
* **Use After Free:** Accessing memory that has already been freed. This can lead to unpredictable behavior and security vulnerabilities.
* **Heap Overflow:** Writing data beyond the allocated boundaries of a chunk. This can overwrite adjacent chunks' metadata or other program data, causing crashes or unexpected behavior.
* **Memory Leaks:** Failing to call `free` on allocated memory when it's no longer needed. This can lead to excessive memory consumption and eventually program failure.
* **Freeing Unallocated Memory:** Attempting to `free` a pointer that was not returned by `malloc` (or a related function).

**User Operations Leading to This Code (Debugging Scenario):**

A developer or reverse engineer might arrive at this code in several ways during debugging:

1. **Crash Analysis:** A program crashes with a memory-related error (e.g., segmentation fault, heap corruption). The debugger's call stack might lead to functions within this `dlmalloc.c` file, indicating the source of the problem.
2. **Memory Leak Detection:** Using memory profiling tools or observing increasing memory usage over time, a developer might suspect a memory leak. Stepping through the code in a debugger or using dynamic analysis tools (like Frida, as shown earlier) can lead to investigating the behavior of `malloc` and `free`.
3. **Reverse Engineering:** A reverse engineer might be examining the inner workings of a program and delve into the implementation of its memory allocator to understand its behavior and potential vulnerabilities. They might disassemble the compiled code or examine the source code if available (as in this case).
4. **Customizing Memory Allocation:** A developer might need a custom memory allocation strategy and decide to modify or understand this well-known implementation as a starting point.
5. **Porting to a New Platform:**  When porting software to a new operating system or architecture, understanding the memory allocation implementation is crucial, and this code might be examined or adapted.

**Summary of Functionality (Part 1):**

This first part of `dlmalloc.c` introduces a highly configurable and widely used implementation of the standard C memory allocation functions (`malloc`, `free`, `realloc`, `calloc`). It outlines the core principles of dynamic memory management, highlights optional security and thread-safety features, and emphasizes the extensive compile-time options for tailoring the allocator to specific needs and environments. It sets the stage for the detailed implementation of the allocation algorithms that will follow in subsequent parts of the code.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/dlmalloc.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
/*
  This is a version (aka dlmalloc) of malloc/free/realloc written by
  Doug Lea and released to the public domain, as explained at
  http://creativecommons.org/publicdomain/zero/1.0/ Send questions,
  comments, complaints, performance data, etc to dl@cs.oswego.edu

* Version 2.8.6 Wed Aug 29 06:57:58 2012  Doug Lea
   Note: There may be an updated version of this malloc obtainable at
           ftp://gee.cs.oswego.edu/pub/misc/malloc.c
         Check before installing!

* Quickstart

  This library is all in one file to simplify the most common usage:
  ftp it, compile it (-O3), and link it into another program. All of
  the compile-time options default to reasonable values for use on
  most platforms.  You might later want to step through various
  compile-time and dynamic tuning options.

  For convenience, an include file for code using this malloc is at:
     ftp://gee.cs.oswego.edu/pub/misc/malloc-2.8.6.h
  You don't really need this .h file unless you call functions not
  defined in your system include files.  The .h file contains only the
  excerpts from this file needed for using this malloc on ANSI C/C++
  systems, so long as you haven't changed compile-time options about
  naming and tuning parameters.  If you do, then you can create your
  own malloc.h that does include all settings by cutting at the point
  indicated below. Note that you may already by default be using a C
  library containing a malloc that is based on some version of this
  malloc (for example in linux). You might still want to use the one
  in this file to customize settings or to avoid overheads associated
  with library versions.

* Vital statistics:

  Supported pointer/size_t representation:       4 or 8 bytes
       size_t MUST be an unsigned type of the same width as
       pointers. (If you are using an ancient system that declares
       size_t as a signed type, or need it to be a different width
       than pointers, you can use a previous release of this malloc
       (e.g. 2.7.2) supporting these.)

  Alignment:                                     8 bytes (minimum)
       This suffices for nearly all current machines and C compilers.
       However, you can define MALLOC_ALIGNMENT to be wider than this
       if necessary (up to 128bytes), at the expense of using more space.

  Minimum overhead per allocated chunk:   4 or  8 bytes (if 4byte sizes)
                                          8 or 16 bytes (if 8byte sizes)
       Each malloced chunk has a hidden word of overhead holding size
       and status information, and additional cross-check word
       if FOOTERS is defined.

  Minimum allocated size: 4-byte ptrs:  16 bytes    (including overhead)
                          8-byte ptrs:  32 bytes    (including overhead)

       Even a request for zero bytes (i.e., malloc(0)) returns a
       pointer to something of the minimum allocatable size.
       The maximum overhead wastage (i.e., number of extra bytes
       allocated than were requested in malloc) is less than or equal
       to the minimum size, except for requests >= mmap_threshold that
       are serviced via mmap(), where the worst case wastage is about
       32 bytes plus the remainder from a system page (the minimal
       mmap unit); typically 4096 or 8192 bytes.

  Security: static-safe; optionally more or less
       The "security" of malloc refers to the ability of malicious
       code to accentuate the effects of errors (for example, freeing
       space that is not currently malloc'ed or overwriting past the
       ends of chunks) in code that calls malloc.  This malloc
       guarantees not to modify any memory locations below the base of
       heap, i.e., static variables, even in the presence of usage
       errors.  The routines additionally detect most improper frees
       and reallocs.  All this holds as long as the static bookkeeping
       for malloc itself is not corrupted by some other means.  This
       is only one aspect of security -- these checks do not, and
       cannot, detect all possible programming errors.

       If FOOTERS is defined nonzero, then each allocated chunk
       carries an additional check word to verify that it was malloced
       from its space.  These check words are the same within each
       execution of a program using malloc, but differ across
       executions, so externally crafted fake chunks cannot be
       freed. This improves security by rejecting frees/reallocs that
       could corrupt heap memory, in addition to the checks preventing
       writes to statics that are always on.  This may further improve
       security at the expense of time and space overhead.  (Note that
       FOOTERS may also be worth using with MSPACES.)

       By default detected errors cause the program to abort (calling
       "abort()"). You can override this to instead proceed past
       errors by defining PROCEED_ON_ERROR.  In this case, a bad free
       has no effect, and a malloc that encounters a bad address
       caused by user overwrites will ignore the bad address by
       dropping pointers and indices to all known memory. This may
       be appropriate for programs that should continue if at all
       possible in the face of programming errors, although they may
       run out of memory because dropped memory is never reclaimed.

       If you don't like either of these options, you can define
       CORRUPTION_ERROR_ACTION and USAGE_ERROR_ACTION to do anything
       else. And if if you are sure that your program using malloc has
       no errors or vulnerabilities, you can define INSECURE to 1,
       which might (or might not) provide a small performance improvement.

       It is also possible to limit the maximum total allocatable
       space, using malloc_set_footprint_limit. This is not
       designed as a security feature in itself (calls to set limits
       are not screened or privileged), but may be useful as one
       aspect of a secure implementation.

  Thread-safety: NOT thread-safe unless USE_LOCKS defined non-zero
       When USE_LOCKS is defined, each public call to malloc, free,
       etc is surrounded with a lock. By default, this uses a plain
       pthread mutex, win32 critical section, or a spin-lock if if
       available for the platform and not disabled by setting
       USE_SPIN_LOCKS=0.  However, if USE_RECURSIVE_LOCKS is defined,
       recursive versions are used instead (which are not required for
       base functionality but may be needed in layered extensions).
       Using a global lock is not especially fast, and can be a major
       bottleneck.  It is designed only to provide minimal protection
       in concurrent environments, and to provide a basis for
       extensions.  If you are using malloc in a concurrent program,
       consider instead using nedmalloc
       (http://www.nedprod.com/programs/portable/nedmalloc/) or
       ptmalloc (See http://www.malloc.de), which are derived from
       versions of this malloc.

  System requirements: Any combination of MORECORE and/or MMAP/MUNMAP
       This malloc can use unix sbrk or any emulation (invoked using
       the CALL_MORECORE macro) and/or mmap/munmap or any emulation
       (invoked using CALL_MMAP/CALL_MUNMAP) to get and release system
       memory.  On most unix systems, it tends to work best if both
       MORECORE and MMAP are enabled.  On Win32, it uses emulations
       based on VirtualAlloc. It also uses common C library functions
       like memset.

  Compliance: I believe it is compliant with the Single Unix Specification
       (See http://www.unix.org). Also SVID/XPG, ANSI C, and probably
       others as well.

* Overview of algorithms

  This is not the fastest, most space-conserving, most portable, or
  most tunable malloc ever written. However it is among the fastest
  while also being among the most space-conserving, portable and
  tunable.  Consistent balance across these factors results in a good
  general-purpose allocator for malloc-intensive programs.

  In most ways, this malloc is a best-fit allocator. Generally, it
  chooses the best-fitting existing chunk for a request, with ties
  broken in approximately least-recently-used order. (This strategy
  normally maintains low fragmentation.) However, for requests less
  than 256bytes, it deviates from best-fit when there is not an
  exactly fitting available chunk by preferring to use space adjacent
  to that used for the previous small request, as well as by breaking
  ties in approximately most-recently-used order. (These enhance
  locality of series of small allocations.)  And for very large requests
  (>= 256Kb by default), it relies on system memory mapping
  facilities, if supported.  (This helps avoid carrying around and
  possibly fragmenting memory used only for large chunks.)

  All operations (except malloc_stats and mallinfo) have execution
  times that are bounded by a constant factor of the number of bits in
  a size_t, not counting any clearing in calloc or copying in realloc,
  or actions surrounding MORECORE and MMAP that have times
  proportional to the number of non-contiguous regions returned by
  system allocation routines, which is often just 1. In real-time
  applications, you can optionally suppress segment traversals using
  NO_SEGMENT_TRAVERSAL, which assures bounded execution even when
  system allocators return non-contiguous spaces, at the typical
  expense of carrying around more memory and increased fragmentation.

  The implementation is not very modular and seriously overuses
  macros. Perhaps someday all C compilers will do as good a job
  inlining modular code as can now be done by brute-force expansion,
  but now, enough of them seem not to.

  Some compilers issue a lot of warnings about code that is
  dead/unreachable only on some platforms, and also about intentional
  uses of negation on unsigned types. All known cases of each can be
  ignored.

  For a longer but out of date high-level description, see
     http://gee.cs.oswego.edu/dl/html/malloc.html

* MSPACES
  If MSPACES is defined, then in addition to malloc, free, etc.,
  this file also defines mspace_malloc, mspace_free, etc. These
  are versions of malloc routines that take an "mspace" argument
  obtained using create_mspace, to control all internal bookkeeping.
  If ONLY_MSPACES is defined, only these versions are compiled.
  So if you would like to use this allocator for only some allocations,
  and your system malloc for others, you can compile with
  ONLY_MSPACES and then do something like...
    static mspace mymspace = create_mspace(0,0); // for example
    #define mymalloc(bytes)  mspace_malloc(mymspace, bytes)

  (Note: If you only need one instance of an mspace, you can instead
  use "USE_DL_PREFIX" to relabel the global malloc.)

  You can similarly create thread-local allocators by storing
  mspaces as thread-locals. For example:
    static __thread mspace tlms = 0;
    void*  tlmalloc(size_t bytes) {
      if (tlms == 0) tlms = create_mspace(0, 0);
      return mspace_malloc(tlms, bytes);
    }
    void  tlfree(void* mem) { mspace_free(tlms, mem); }

  Unless FOOTERS is defined, each mspace is completely independent.
  You cannot allocate from one and free to another (although
  conformance is only weakly checked, so usage errors are not always
  caught). If FOOTERS is defined, then each chunk carries around a tag
  indicating its originating mspace, and frees are directed to their
  originating spaces. Normally, this requires use of locks.

 -------------------------  Compile-time options ---------------------------

Be careful in setting #define values for numerical constants of type
size_t. On some systems, literal values are not automatically extended
to size_t precision unless they are explicitly casted. You can also
use the symbolic values MAX_SIZE_T, SIZE_T_ONE, etc below.

WIN32                    default: defined if _WIN32 defined
  Defining WIN32 sets up defaults for MS environment and compilers.
  Otherwise defaults are for unix. Beware that there seem to be some
  cases where this malloc might not be a pure drop-in replacement for
  Win32 malloc: Random-looking failures from Win32 GDI API's (eg;
  SetDIBits()) may be due to bugs in some video driver implementations
  when pixel buffers are malloc()ed, and the region spans more than
  one VirtualAlloc()ed region. Because dlmalloc uses a small (64Kb)
  default granularity, pixel buffers may straddle virtual allocation
  regions more often than when using the Microsoft allocator.  You can
  avoid this by using VirtualAlloc() and VirtualFree() for all pixel
  buffers rather than using malloc().  If this is not possible,
  recompile this malloc with a larger DEFAULT_GRANULARITY. Note:
  in cases where MSC and gcc (cygwin) are known to differ on WIN32,
  conditions use _MSC_VER to distinguish them.

DLMALLOC_EXPORT       default: extern
  Defines how public APIs are declared. If you want to export via a
  Windows DLL, you might define this as
    #define DLMALLOC_EXPORT extern  __declspec(dllexport)
  If you want a POSIX ELF shared object, you might use
    #define DLMALLOC_EXPORT extern __attribute__((visibility("default")))

MALLOC_ALIGNMENT         default: (size_t)(2 * sizeof(void *))
  Controls the minimum alignment for malloc'ed chunks.  It must be a
  power of two and at least 8, even on machines for which smaller
  alignments would suffice. It may be defined as larger than this
  though. Note however that code and data structures are optimized for
  the case of 8-byte alignment.

MSPACES                  default: 0 (false)
  If true, compile in support for independent allocation spaces.
  This is only supported if HAVE_MMAP is true.

ONLY_MSPACES             default: 0 (false)
  If true, only compile in mspace versions, not regular versions.

USE_LOCKS                default: 0 (false)
  Causes each call to each public routine to be surrounded with
  pthread or WIN32 mutex lock/unlock. (If set true, this can be
  overridden on a per-mspace basis for mspace versions.) If set to a
  non-zero value other than 1, locks are used, but their
  implementation is left out, so lock functions must be supplied manually,
  as described below.

USE_SPIN_LOCKS           default: 1 iff USE_LOCKS and spin locks available
  If true, uses custom spin locks for locking. This is currently
  supported only gcc >= 4.1, older gccs on x86 platforms, and recent
  MS compilers.  Otherwise, posix locks or win32 critical sections are
  used.

USE_RECURSIVE_LOCKS      default: not defined
  If defined nonzero, uses recursive (aka reentrant) locks, otherwise
  uses plain mutexes. This is not required for malloc proper, but may
  be needed for layered allocators such as nedmalloc.

LOCK_AT_FORK            default: not defined
  If defined nonzero, performs pthread_atfork upon initialization
  to initialize child lock while holding parent lock. The implementation
  assumes that pthread locks (not custom locks) are being used. In other
  cases, you may need to customize the implementation.

FOOTERS                  default: 0
  If true, provide extra checking and dispatching by placing
  information in the footers of allocated chunks. This adds
  space and time overhead.

INSECURE                 default: 0
  If true, omit checks for usage errors and heap space overwrites.

USE_DL_PREFIX            default: NOT defined
  Causes compiler to prefix all public routines with the string 'dl'.
  This can be useful when you only want to use this malloc in one part
  of a program, using your regular system malloc elsewhere.

MALLOC_INSPECT_ALL       default: NOT defined
  If defined, compiles malloc_inspect_all and mspace_inspect_all, that
  perform traversal of all heap space.  Unless access to these
  functions is otherwise restricted, you probably do not want to
  include them in secure implementations.

ABORT                    default: defined as abort()
  Defines how to abort on failed checks.  On most systems, a failed
  check cannot die with an "assert" or even print an informative
  message, because the underlying print routines in turn call malloc,
  which will fail again.  Generally, the best policy is to simply call
  abort(). It's not very useful to do more than this because many
  errors due to overwriting will show up as address faults (null, odd
  addresses etc) rather than malloc-triggered checks, so will also
  abort.  Also, most compilers know that abort() does not return, so
  can better optimize code conditionally calling it.

PROCEED_ON_ERROR           default: defined as 0 (false)
  Controls whether detected bad addresses cause them to bypassed
  rather than aborting. If set, detected bad arguments to free and
  realloc are ignored. And all bookkeeping information is zeroed out
  upon a detected overwrite of freed heap space, thus losing the
  ability to ever return it from malloc again, but enabling the
  application to proceed. If PROCEED_ON_ERROR is defined, the
  static variable malloc_corruption_error_count is compiled in
  and can be examined to see if errors have occurred. This option
  generates slower code than the default abort policy.

DEBUG                    default: NOT defined
  The DEBUG setting is mainly intended for people trying to modify
  this code or diagnose problems when porting to new platforms.
  However, it may also be able to better isolate user errors than just
  using runtime checks.  The assertions in the check routines spell
  out in more detail the assumptions and invariants underlying the
  algorithms.  The checking is fairly extensive, and will slow down
  execution noticeably. Calling malloc_stats or mallinfo with DEBUG
  set will attempt to check every non-mmapped allocated and free chunk
  in the course of computing the summaries.

ABORT_ON_ASSERT_FAILURE   default: defined as 1 (true)
  Debugging assertion failures can be nearly impossible if your
  version of the assert macro causes malloc to be called, which will
  lead to a cascade of further failures, blowing the runtime stack.
  ABORT_ON_ASSERT_FAILURE cause assertions failures to call abort(),
  which will usually make debugging easier.

MALLOC_FAILURE_ACTION     default: sets errno to ENOMEM, or no-op on win32
  The action to take before "return 0" when malloc fails to be able to
  return memory because there is none available.

HAVE_MORECORE             default: 1 (true) unless win32 or ONLY_MSPACES
  True if this system supports sbrk or an emulation of it.

MORECORE                  default: sbrk
  The name of the sbrk-style system routine to call to obtain more
  memory.  See below for guidance on writing custom MORECORE
  functions. The type of the argument to sbrk/MORECORE varies across
  systems.  It cannot be size_t, because it supports negative
  arguments, so it is normally the signed type of the same width as
  size_t (sometimes declared as "intptr_t").  It doesn't much matter
  though. Internally, we only call it with arguments less than half
  the max value of a size_t, which should work across all reasonable
  possibilities, although sometimes generating compiler warnings.

MORECORE_CONTIGUOUS       default: 1 (true) if HAVE_MORECORE
  If true, take advantage of fact that consecutive calls to MORECORE
  with positive arguments always return contiguous increasing
  addresses.  This is true of unix sbrk. It does not hurt too much to
  set it true anyway, since malloc copes with non-contiguities.
  Setting it false when definitely non-contiguous saves time
  and possibly wasted space it would take to discover this though.

MORECORE_CANNOT_TRIM      default: NOT defined
  True if MORECORE cannot release space back to the system when given
  negative arguments. This is generally necessary only if you are
  using a hand-crafted MORECORE function that cannot handle negative
  arguments.

NO_SEGMENT_TRAVERSAL       default: 0
  If non-zero, suppresses traversals of memory segments
  returned by either MORECORE or CALL_MMAP. This disables
  merging of segments that are contiguous, and selectively
  releasing them to the OS if unused, but bounds execution times.

HAVE_MMAP                 default: 1 (true)
  True if this system supports mmap or an emulation of it.  If so, and
  HAVE_MORECORE is not true, MMAP is used for all system
  allocation. If set and HAVE_MORECORE is true as well, MMAP is
  primarily used to directly allocate very large blocks. It is also
  used as a backup strategy in cases where MORECORE fails to provide
  space from system. Note: A single call to MUNMAP is assumed to be
  able to unmap memory that may have be allocated using multiple calls
  to MMAP, so long as they are adjacent.

HAVE_MREMAP               default: 1 on linux, else 0
  If true realloc() uses mremap() to re-allocate large blocks and
  extend or shrink allocation spaces.

MMAP_CLEARS               default: 1 except on WINCE.
  True if mmap clears memory so calloc doesn't need to. This is true
  for standard unix mmap using /dev/zero and on WIN32 except for WINCE.

USE_BUILTIN_FFS            default: 0 (i.e., not used)
  Causes malloc to use the builtin ffs() function to compute indices.
  Some compilers may recognize and intrinsify ffs to be faster than the
  supplied C version. Also, the case of x86 using gcc is special-cased
  to an asm instruction, so is already as fast as it can be, and so
  this setting has no effect. Similarly for Win32 under recent MS compilers.
  (On most x86s, the asm version is only slightly faster than the C version.)

malloc_getpagesize         default: derive from system includes, or 4096.
  The system page size. To the extent possible, this malloc manages
  memory from the system in page-size units.  This may be (and
  usually is) a function rather than a constant. This is ignored
  if WIN32, where page size is determined using getSystemInfo during
  initialization.

USE_DEV_RANDOM             default: 0 (i.e., not used)
  Causes malloc to use /dev/random to initialize secure magic seed for
  stamping footers. Otherwise, the current time is used.

NO_MALLINFO                default: 0
  If defined, don't compile "mallinfo". This can be a simple way
  of dealing with mismatches between system declarations and
  those in this file.

MALLINFO_FIELD_TYPE        default: size_t
  The type of the fields in the mallinfo struct. This was originally
  defined as "int" in SVID etc, but is more usefully defined as
  size_t. The value is used only if  HAVE_USR_INCLUDE_MALLOC_H is not set

NO_MALLOC_STATS            default: 0
  If defined, don't compile "malloc_stats". This avoids calls to
  fprintf and bringing in stdio dependencies you might not want.

REALLOC_ZERO_BYTES_FREES    default: not defined
  This should be set if a call to realloc with zero bytes should
  be the same as a call to free. Some people think it should. Otherwise,
  since this malloc returns a unique pointer for malloc(0), so does
  realloc(p, 0).

LACKS_UNISTD_H, LACKS_FCNTL_H, LACKS_SYS_PARAM_H, LACKS_SYS_MMAN_H
LACKS_STRINGS_H, LACKS_STRING_H, LACKS_SYS_TYPES_H,  LACKS_ERRNO_H
LACKS_STDLIB_H LACKS_SCHED_H LACKS_TIME_H  default: NOT defined unless on WIN32
  Define these if your system does not have these header files.
  You might need to manually insert some of the declarations they provide.

DEFAULT_GRANULARITY        default: page size if MORECORE_CONTIGUOUS,
                                system_info.dwAllocationGranularity in WIN32,
                                otherwise 64K.
      Also settable using mallopt(M_GRANULARITY, x)
  The unit for allocating and deallocating memory from the system.  On
  most systems with contiguous MORECORE, there is no reason to
  make this more than a page. However, systems with MMAP tend to
  either require or encourage larger granularities.  You can increase
  this value to prevent system allocation functions to be called so
  often, especially if they are slow.  The value must be at least one
  page and must be a power of two.  Setting to 0 causes initialization
  to either page size or win32 region size.  (Note: In previous
  versions of malloc, the equivalent of this option was called
  "TOP_PAD")

DEFAULT_TRIM_THRESHOLD    default: 2MB
      Also settable using mallopt(M_TRIM_THRESHOLD, x)
  The maximum amount of unused top-most memory to keep before
  releasing via malloc_trim in free().  Automatic trimming is mainly
  useful in long-lived programs using contiguous MORECORE.  Because
  trimming via sbrk can be slow on some systems, and can sometimes be
  wasteful (in cases where programs immediately afterward allocate
  more large chunks) the value should be high enough so that your
  overall system performance would improve by releasing this much
  memory.  As a rough guide, you might set to a value close to the
  average size of a process (program) running on your system.
  Releasing this much memory would allow such a process to run in
  memory.  Generally, it is worth tuning trim thresholds when a
  program undergoes phases where several large chunks are allocated
  and released in ways that can reuse each other's storage, perhaps
  mixed with phases where there are no such chunks at all. The trim
  value must be greater than page size to have any useful effect.  To
  disable trimming completely, you can set to MAX_SIZE_T. Note that the trick
  some people use of mallocing a huge space and then freeing it at
  program startup, in an attempt to reserve system memory, doesn't
  have the intended effect under automatic trimming, since that memory
  will immediately be returned to the system.

DEFAULT_MMAP_THRESHOLD       default: 256K
      Also settable using mallopt(M_MMAP_THRESHOLD, x)
  The request size threshold for using MMAP to directly service a
  request. Requests of at least this size that cannot be allocated
  using already-existing space will be serviced via mmap.  (If enough
  normal freed space already exists it is used instead.)  Using mmap
  segregates relatively large chunks of memory so that they can be
  individually obtained and released from the host system. A request
  serviced through mmap is never reused by any other request (at least
  not directly; the system may just so happen to remap successive
  requests to the same locations).  Segregating space in this way has
  the benefits that: Mmapped space can always be individually released
  back to the system, which helps keep the system level memory demands
  of a long-lived program low.  Also, mapped memory doesn't become
  `locked' between other chunks, as can happen with normally allocated
  chunks, which means that even trimming via malloc_trim would not
  release them.  However, it has the disadvantage that the space
  cannot be reclaimed, consolidated, and then used to service later
  requests, as happens with normal chunks.  The advantages of mmap
  nearly always outweigh disadvantages for "large" chunks, but the
  value of "large" may vary across systems.  The default is an
  empirically derived value that works well in most systems. You can
  disable mmap by setting to MAX_SIZE_T.

MAX_RELEASE_CHECK_RATE   default: 4095 unless not HAVE_MMAP
  The number of consolidated frees between checks to release
  unused segments when freeing. When using non-contiguous segments,
  especially with multiple mspaces, checking only for topmost space
  doesn't always suffice to trigger trimming. To compensate for this,
  free() will, with a period of MAX_RELEASE_CHECK_RATE (or the
  current number of segments, if greater) try to release unused
  segments to the OS when freeing chunks that result in
  consolidation. The best value for this parameter is a compromise
  between slowing down frees with relatively costly checks that
  rarely trigger versus holding on to unused memory. To effectively
  disable, set to MAX_SIZE_T. This may lead to a very slight speed
  improvement at the expense of carrying around more memory.
*/

/* Version identifier to allow people to support multiple versions */
#ifndef DLMALLOC_VERSION
#define DLMALLOC_VERSION 20806
#endif /* DLMALLOC_VERSION */

#ifndef DLMALLOC_EXPORT
#define DLMALLOC_EXPORT extern
#endif

#ifndef WIN32
#ifdef _WIN32
#define WIN32 1
#endif  /* _WIN32 */
#ifdef _WIN32_WCE
#define LACKS_FCNTL_H
#define WIN32 1
#endif /* _WIN32_WCE */
#endif  /* WIN32 */
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#define HAVE_MMAP 1
#define HAVE_MORECORE 0
#define LACKS_UNISTD_H
#define LACKS_SYS_PARAM_H
#define LACKS_SYS_MMAN_H
#define LACKS_STRING_H
#define LACKS_STRINGS_H
#define LACKS_SYS_TYPES_H
#define LACKS_ERRNO_H
#define LACKS_SCHED_H
#ifndef MALLOC_FAILURE_ACTION
#define MALLOC_FAILURE_ACTION
#endif /* MALLOC_FAILURE_ACTION */
#ifndef MMAP_CLEARS
#ifdef _WIN32_WCE /* WINCE reportedly does not clear */
#define MMAP_CLEARS 0
#else
#define MMAP_CLEARS 1
#endif /* _WIN32_WCE */
#endif /*MMAP_CLEARS */
#endif  /* WIN32 */

#if defined(DARWIN) || defined(_DARWIN)
/* Mac OSX docs advise not to use sbrk; it seems better to use mmap */
#ifndef HAVE_MORECORE
#define HAVE_MORECORE 0
#define HAVE_MMAP 1
/* OSX allocators provide 16 byte alignment */
#ifndef MALLOC_ALIGNMENT
#define MALLOC_ALIGNMENT ((size_t)16U)
#endif
#endif  /* HAVE_MORECORE */
#endif  /* DARWIN */

#ifndef LACKS_SYS_TYPES_H
#include <sys/types.h>  /* For size_t */
#endif  /* LACKS_SYS_TYPES_H */

/* The maximum possible size_t value has all bits set */
#define MAX_SIZE_T           (~(size_t)0)

#ifndef USE_LOCKS /* ensure true if spin or recursive locks set */
#define USE_LOCKS  ((defined(USE_SPIN_LOCKS) && USE_SPIN_LOCKS != 0) || \
                    (defined(USE_RECURSIVE_LOCKS) && USE_RECURSIVE_LOCKS != 0))
#endif /* USE_LOCKS */

#if USE_LOCKS /* Spin locks for gcc >= 4.1, older gcc on x86, MSC >= 1310 */
#if ((defined(__GNUC__) &&                                              \
      ((__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1)) ||      \
       defined(__i386__) || defined(__x86_64__))) ||                    \
     (defined(_MSC_VER) && _MSC_VER>=1310))
#ifndef USE_SPIN_LOCKS
#define USE_SPIN_LOCKS 1
#endif /* USE_SPIN_LOCKS */
#elif USE_SPIN_LOCKS
#error "USE_SPIN_LOCKS defined without implementation"
#endif /* ... locks available... */
#elif !defined(USE_SPIN_LOCKS)
#define USE_SPIN_LOCKS 0
#endif /* USE_LOCKS */

#ifndef ONLY_MSPACES
#define ONLY_MSPACES 0
#endif  /* ONLY_MSPACES */
#ifndef MSPACES
#if ONLY_MSPACES
#define MSPACES 1
#else   /* ONLY_MSPACES */
#define MSPACES 0
#endif  /* ONLY_MSPACES */
#endif  /* MSPACES */
#ifndef MALLOC_ALIGNMENT
#define MALLOC_ALIGNMENT ((size_t)(2 * sizeof(void *)))
#endif  /* MALLOC_ALIGNMENT */
#ifndef FOOTERS
#define FOOTERS 0
#endif  /* FOOTERS */
#ifndef ABORT
#define ABORT  abort()
#endif  /* ABORT */
#ifndef ABORT_ON_ASSERT_FAILURE
#define ABORT_ON_ASSERT_FAILURE 1
#endif  /* ABORT_ON_ASSERT_FAILURE */
#ifndef PROCEED_ON_ERROR
#define PROCEED_ON_ERROR 0
#endif  /* PROCEED_ON_ERROR */

#ifndef INSECURE
#define INSECURE 0
#endif  /* INSECURE */
#ifndef MALLOC_INSPECT_ALL
#define MALLOC_INSPECT_ALL 0
#endif  /* MALLOC_INSPECT_ALL */
#ifndef HAVE_MMAP
#define HAVE_MMAP 1
#endif  /* HAVE_MMAP */
#ifndef MMAP_CLEARS
#define MMAP_CLEARS 1
#endif  /* MMAP_CLEARS */
#ifndef HAVE_MREMAP
#ifdef linux
#define HAVE_MREMAP 1
#define _GNU_SOURCE /* Turns on mremap() definition */
#else   /* linux */
#define HAVE_MREMAP 0
#endif  /* linux */
#endif  /* HAVE_MREMAP */
#ifndef MALLOC_FAILURE_ACTION
#define MALLOC_FAILURE_ACTION  errno = ENOMEM;
#endif  /* MALLOC_FAILURE_ACTION */
#ifndef HAVE_MORECORE
#if ONLY_MSPACES
#define HAVE_MORECORE 0
#else   /* ONLY_MSPACES */
#define HAVE_MORECORE 1
#endif  /* ONLY_MSPACES */
#endif  /* HAVE_MORECORE */
#if !HAVE_MORECORE
#define MORECORE_CONTIGUOUS 0
#else   /* !HAVE_MORECORE */
#define MORECORE_DEFAULT sbrk
#ifndef MORECORE_CONTIGUOUS
#define MORECORE_CONTIGUOUS 1
#endif  /* MORECORE_CONTIGUOUS */
#endif  /* HAVE_MORECORE */
#ifndef DEFAULT_GRANULARITY
#if (MORECORE_CONTIGUOUS || defined(WIN32))
#define DEFAULT_GRANULARITY (0)  /* 0 means to compute in init_mparams */
#else   /* MORECORE_CONTIGUOUS */
#define DEFAULT_GRANULARITY ((size_t)64U * (size_t)1024U)
#endif  /* MORECORE_CONTIGUOUS */
#endif  /* DEFAULT_GRANULARITY */
#ifndef DEFAULT_TRIM_THRESHOLD
#ifndef MORECORE_CANNOT_TRIM
#define DEFAULT_TRIM_THRESHOLD ((size_t)2U * (size_t)1024U * (size_t)1024U)
#else   /* MORECORE_CANNOT_TRIM */
#define DEFAULT_TRIM_THRESHOLD MAX_SIZE_T
#endif  /* MORECORE_CANNOT_TRIM */
#endif  /* DEFAULT_TRIM_THRESHOLD */
#ifndef DEFAULT_MMAP_THRESHOLD
#if HAVE_MMAP
#define DEFAULT_MMAP_THRESHOLD ((size_t)256U * (size_t)1024U)
#else   /* HAVE_MMAP */
#define DEFAULT_MMAP_THRESHOLD MAX_S
```