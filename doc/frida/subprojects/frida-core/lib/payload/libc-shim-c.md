Response:
Let's break down the thought process for analyzing the provided C code and answering the prompt.

**1. Understanding the Core Task:**

The primary goal is to analyze the `libc-shim.c` file from Frida and explain its functionality in the context of dynamic instrumentation and reverse engineering. This means identifying what it does, why it does it, and how it relates to lower-level system interactions.

**2. Initial Code Scan - Identifying Key Areas:**

The first step is to quickly scan the code and identify the major sections and functionalities. Keywords like `#define`, `#include`, function definitions (especially those that shadow standard library functions like `malloc`, `printf`, etc.), conditional compilation (`#ifdef`, `#ifndef`), and assembly code snippets stand out.

**3. Functionality Breakdown - Grouping Related Code:**

Now, let's group the code into logical units based on their apparent purpose:

* **Memory Management:**  The presence of `malloc`, `calloc`, `realloc`, `free`, `memalign`, `posix_memalign`, `malloc_size`, `malloc_usable_size` clearly indicates a custom memory management layer.
* **Output/Printing:**  `printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `vfprintf`, `vsnprintf`, `__sprintf_chk`, `__snprintf_chk`, `__vsnprintf_chk`, `sprintf_l`, `snprintf_l`, `asprintf_l` all point to handling formatted output.
* **Exit Handlers:** `frida_run_atexit_handlers`, `__cxa_atexit`, `atexit` deal with registering and executing functions upon program exit.
* **Platform Differences:**  The extensive use of `#ifdef HAVE_WINDOWS`, `#ifdef HAVE_ASAN`, `#else`, `#ifdef HAVE_DARWIN`, `#ifdef HAVE_LINUX` suggests the code handles platform-specific behavior.
* **System Calls (macOS):**  The `read`, `write`, `mmap`, `munmap` definitions with inline assembly on macOS indicate direct system call interception or replacement.
* **Resolv Stub (macOS):** The `res_9_init`, `res_9_ninit`, etc., functions on macOS appear to be stubs, likely to avoid linking dependencies.
* **Dup System Calls (Linux):**  `dup`, `dup2`, `dup3` on Linux relate to file descriptor duplication.
* **Error Handling (Linux):** `_frida_set_errno` relates to setting the `errno` value.
* **Initialization/Destruction:**  `frida_init_memory`, `frida_deinit_memory`, and the `constructor`/`destructor` attributes manage initialization and cleanup.
* **Spinlock:** `FRIDA_SHIM_LOCK`, `FRIDA_SHIM_UNLOCK`, and `GumSpinlock` suggest thread safety mechanisms.

**4. Connecting to Reverse Engineering:**

With the functionalities identified, the next step is to link them to reverse engineering concepts:

* **Hooking/Interception:** The shimming of standard library functions like `malloc` and `printf` is a classic technique for intercepting calls. This allows Frida to monitor or modify the behavior of the target process.
* **Memory Analysis:**  Custom memory management allows Frida to track allocations and potentially detect memory-related issues in the target.
* **Tracing/Logging:** Intercepting `printf` and related functions enables Frida to capture output from the target application.
* **System Call Monitoring:** Replacing system call wrappers on macOS allows Frida to observe low-level interactions.
* **Controlling Program Flow:**  The `atexit` handling allows Frida to inject code that executes during program shutdown.

**5. Relating to Binary/Kernel/Framework Knowledge:**

Now, connect the code to lower-level concepts:

* **Binary Instrumentation:** The entire purpose of Frida is binary instrumentation, and this shim library is a core component.
* **Shared Libraries/Loaders:**  The shim likely gets loaded into the target process as a shared library, intercepting calls through mechanisms like symbol interposition.
* **System Calls:**  The macOS and Linux-specific code directly interacts with the kernel via system calls.
* **Memory Management (OS Level):**  While Frida uses its own heap, understanding how the OS manages memory (virtual memory, heap allocation) is important context.
* **File Descriptors (Linux):** The `dup` family of functions directly manipulates file descriptors, a fundamental concept in Linux.
* **ASAN (AddressSanitizer):** The conditional compilation for ASAN indicates Frida's awareness and potential integration with memory error detection tools.
* **`__cxa_atexit`:** This is a C++ runtime function for registering exit handlers, showing interaction beyond standard C.

**6. Logical Reasoning and Examples:**

For logical reasoning, think about the *why* behind the code. For example, *why* would Frida replace `malloc`?  To track allocations. Then create a simple scenario to illustrate this. Similarly for `printf`.

**7. Identifying User/Programming Errors:**

Consider common mistakes related to the functions being shimmed. Memory leaks (not freeing `malloc`ed memory), buffer overflows (using `sprintf` without bounds checking), and incorrect usage of exit handlers are good examples.

**8. Tracing User Operations:**

Think about how a Frida user would interact with the target to trigger the execution of this shim library. Attaching to a process, injecting a payload, and that payload making standard library calls are the key steps.

**9. Structuring the Answer:**

Finally, organize the information logically, using clear headings and bullet points to make it easy to read and understand. Follow the prompt's request for specific examples and explanations.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just replaces standard functions."  **Correction:**  It's more nuanced. It *intercepts* them, often using Frida's own internal implementations or adding extra logic.
* **Overlooking details:**  Initially, I might focus too much on memory management and miss the significance of the `resolv` stubs on macOS. A closer reading and understanding of the comments helps to rectify this.
* **Being too technical:**  The explanation should be understandable to someone familiar with reverse engineering concepts, not necessarily a kernel developer. Balancing technical detail with clarity is important.

By following these steps, breaking down the code into manageable parts, and systematically connecting those parts to the concepts requested in the prompt, a comprehensive and accurate answer can be constructed.
This C code file, `libc-shim.c`, from the Frida dynamic instrumentation toolkit serves as a **shim library**, meaning it provides replacement implementations for standard C library functions. Its primary goal within Frida is to **intercept and potentially modify the behavior of these standard library calls made by the target process being instrumented.** This allows Frida to gain insights into the target's operation and influence its execution.

Let's break down its functionalities and their relation to various concepts:

**1. Function Interception (Hooking):**

* **Core Functionality:** The most prominent feature is the redefinition (using `#undef` and then providing a new definition) of several standard C library functions:
    * **Memory Management:** `malloc`, `calloc`, `realloc`, `free`, `memalign`, `posix_memalign`, `malloc_size`, `malloc_usable_size`.
    * **String Manipulation:** `strdup`.
    * **Formatted Output:** `printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `vfprintf`, `vsnprintf`, and their `_chk` and `_l` variants.
    * **(Platform Specific):** `memcpy`, `dup`, `dup2`, `dup3`, `read`, `write`, `mmap`, `munmap`, `res_9_init`, etc.

* **Relationship to Reverse Engineering:** This is a fundamental technique in reverse engineering. By intercepting these function calls, Frida can:
    * **Trace Execution:**  Log every call to `malloc` with its size, or every `printf` with its arguments. This provides a detailed trace of the target's actions.
    * **Modify Behavior:**  Change the return value of `malloc` to simulate memory allocation failures, or alter the string passed to `printf`.
    * **Data Inspection:** Examine the arguments passed to these functions. For instance, see what data is being printed, what memory is being allocated, or what files are being opened.

* **Example:**
    * **Scenario:** A target application calls `printf("User input: %s", user_provided_string);`.
    * **Frida's Hook:** Frida's shimmed `printf` is called instead of the system's `printf`.
    * **Reverse Engineering Use Case:** A reverse engineer could hook `printf` to:
        * Log every time this specific `printf` is called and the value of `user_provided_string`. This helps understand how user input is being processed.
        * Modify the `user_provided_string` before it's actually printed, potentially to bypass input validation or inject malicious data.

**2. Custom Memory Management:**

* **Core Functionality:** The shim uses `gum_malloc`, `gum_calloc`, `gum_realloc`, and `gum_free` from the Gum library (Frida's underlying engine).
* **Binary/Underlying Knowledge:** This demonstrates how Frida manages memory within the target process. It doesn't directly rely on the target's default heap allocator. This allows Frida to:
    * **Track Allocations:**  Gum can maintain metadata about each allocation, enabling Frida to know what memory is being used and potentially detect leaks or corruption.
    * **Isolate Frida's Operations:** By using its own heap, Frida reduces the chances of its memory operations interfering with the target's.

* **Example:**
    * **Scenario:** The target application allocates memory using `malloc`.
    * **Frida's Handling:** The call is intercepted by Frida's shim, and `gum_malloc` is called instead of the system's `malloc`.
    * **Reverse Engineering Use Case:** Frida can then use Gum's features to track this specific allocation, set breakpoints when it's accessed, or free it prematurely to observe the target's behavior.

**3. Exit Handler Management (`atexit`, `__cxa_atexit`):**

* **Core Functionality:** The code shims `__cxa_atexit` (used for C++ destructors) and potentially `atexit` (for C exit handlers) to ensure Frida's cleanup routines are executed before the target process completely terminates.
* **Binary/Kernel/Framework Knowledge:**
    * `atexit` and `__cxa_atexit` are mechanisms provided by the C and C++ runtime libraries to register functions that should be called when the program exits.
    * Frida needs to ensure its resources are released properly even when the target process exits normally.
* **Reasoning:**  Frida intercepts these calls to add its own cleanup functions. It maintains a list of exit handlers (`frida_atexit_entries`) and executes them in reverse order of registration during `frida_run_atexit_handlers`.
* **Assumption/Input-Output:** If the target calls `atexit(cleanup_function)`, Frida's shim will register `cleanup_function` to be called later. When the program exits, Frida will execute `cleanup_function`.

**4. Thread Safety (Spinlock):**

* **Core Functionality:** The `FRIDA_SHIM_LOCK()` and `FRIDA_SHIM_UNLOCK()` macros utilize a spinlock (`frida_shim_lock`).
* **Binary/Underlying Knowledge:**  Spinlocks are a low-level synchronization primitive used to protect shared resources from concurrent access by multiple threads.
* **Reasoning:**  In a multi-threaded target process, multiple threads might call the shimmed functions simultaneously. The spinlock ensures that Frida's internal data structures (like `frida_atexit_entries`) are accessed in a thread-safe manner, preventing race conditions and data corruption.

**5. Platform-Specific Implementations (`#ifdef`):**

* **Core Functionality:** The code uses preprocessor directives like `#ifdef HAVE_WINDOWS`, `#ifdef HAVE_DARWIN`, `#ifdef HAVE_LINUX` to provide different implementations for certain functions depending on the operating system.
* **Binary/Kernel/Framework Knowledge:** This demonstrates the need for platform-specific handling when dealing with low-level system interactions. System calls, memory management, and other OS-level functionalities can vary significantly between operating systems.
* **Examples:**
    * **Windows/ASAN:**  The code might have simplified implementations or no-ops for certain functions on Windows or when using ASAN (AddressSanitizer).
    * **macOS:**  The code includes assembly implementations for system calls like `read`, `write`, `mmap`, `munmap`. This suggests Frida might be directly invoking system calls on macOS for finer control or when standard library wrappers are insufficient. It also includes stubs for `res_*` functions, likely to avoid linking against the resolver library unless explicitly needed.
    * **Linux:** The code shims `dup`, `dup2`, and `dup3` which are related to file descriptor duplication. The `_frida_set_errno` function is likely a helper for setting the `errno` value after a system call failure.

**6. Constructor and Destructor Attributes (`__attribute__ ((constructor))`, `__attribute__ ((destructor)))`):**

* **Core Functionality:** These attributes ensure that `frida_init_memory` is called before `main` is executed, and `frida_deinit_memory` is called after `main` finishes (or when the shared library is unloaded).
* **Binary/Underlying Knowledge:** These are compiler-specific attributes that allow code to be executed during the loading and unloading of shared libraries. Frida uses this to initialize its internal heap and perform cleanup.

**7. Handling of `sprintf` and Related Functions:**

* **Core Functionality:** The shimmed versions of `sprintf`, `snprintf`, `vsnprintf`, etc., often call the corresponding Gum functions (`gum_vasprintf`, `gum_vsnprintf`). Note the use of `FRIDA_PRINTF_BUFFER_SIZE` as a potential buffer limit in some cases.
* **User/Programming Errors:**  A common mistake when using `sprintf` is buffer overflow – writing past the end of the allocated buffer. While the shim might use `gum_vsnprintf` internally for safety, incorrect usage in the target application can still lead to issues.
* **Example:**
    * **Target Code:** `char buffer[10]; sprintf(buffer, "Very long string: %s", long_user_input);`
    * **Frida's Role:** Frida's shimmed `sprintf` might prevent a crash within its own context by using `gum_vsnprintf`, but the target's buffer will still be overflowed, potentially leading to other problems.

**How User Operation Leads Here (Debugging Clue):**

1. **Frida Injection:** A user starts a Frida session and attaches to a target process.
2. **Payload Injection:** Frida injects a payload (which includes `frida-core`) into the target process.
3. **Library Loading:** The `libc-shim.so` (or equivalent DLL on Windows, or dylib on macOS) is loaded into the target process's address space.
4. **Symbol Interposition/Hooking:** The operating system's dynamic linker mechanism (e.g., `ld-linux.so`, `dyld`, `ld.so`) ensures that when the target process calls functions like `malloc` or `printf`, the calls are intercepted and redirected to the implementations provided in `libc-shim.c`. This happens due to symbol interposition, where the linker prioritizes symbols from libraries loaded earlier.
5. **Target Code Execution:** When the target process executes code that makes calls to standard C library functions, it will be executing the code within `libc-shim.c`.
6. **Debugging/Instrumentation:** Frida's JavaScript API can then be used to interact with these intercepted function calls, setting breakpoints, reading/writing arguments, and modifying behavior.

**In summary, `libc-shim.c` is a crucial component of Frida that enables dynamic instrumentation by intercepting standard C library functions. It leverages platform-specific knowledge, custom memory management, and thread safety mechanisms to provide a foundation for Frida's powerful reverse engineering and dynamic analysis capabilities.**

Prompt: 
```
这是目录为frida/subprojects/frida-core/lib/payload/libc-shim.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#define FRIDA_PRINTF_BUFFER_SIZE (512 * 1024)
#define _GNU_SOURCE

#include <errno.h>
#include <gum/gum.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef HAVE_XLOCALE_H
# include <xlocale.h>
#endif

#undef memcpy
#undef sprintf
#undef snprintf
#undef vsnprintf

#if defined (HAVE_WINDOWS) || defined (HAVE_ASAN)

void
frida_run_atexit_handlers (void)
{
}

# ifdef HAVE_ASAN

__attribute__ ((constructor)) static void
frida_init_memory (void)
{
  asm volatile ("");
}

#  ifndef HAVE_DARWIN
__attribute__ ((destructor)) static void
frida_deinit_memory (void)
{
  asm volatile ("");
}
#  endif

# endif

#else

#define FRIDA_SHIM_LOCK() gum_spinlock_acquire (&frida_shim_lock)
#define FRIDA_SHIM_UNLOCK() gum_spinlock_release (&frida_shim_lock)

typedef struct _FridaExitEntry FridaExitEntry;
typedef void (* FridaExitFunc) (gpointer user_data);

struct _FridaExitEntry
{
  FridaExitFunc func;
  gpointer user_data;
};

static gboolean frida_heap_initialized = FALSE;
static FridaExitEntry * frida_atexit_entries = NULL;
static guint frida_atexit_count = 0;

static GumSpinlock frida_shim_lock = GUM_SPINLOCK_INIT;

__attribute__ ((constructor)) static void
frida_init_memory (void)
{
  if (!frida_heap_initialized)
  {
    gum_internal_heap_ref ();
    frida_heap_initialized = TRUE;
  }
}

/*
 * Avoid destructors on i/macOS as modern toolchain versions now emit a
 * constructor per destructor, each calling __cxa_atexit().
 *
 * We want to make sure we release our heap as the very last thing we do,
 * so we shim __cxa_atexit() to make sure any destructors registered that
 * way will be run before we deallocate our internal heap.
 */

#ifndef HAVE_DARWIN

__attribute__ ((destructor)) static void
frida_deinit_memory (void)
{
  gum_internal_heap_unref ();
}

#endif

void
frida_run_atexit_handlers (void)
{
  gint i;

  for (i = (gint) frida_atexit_count - 1; i >= 0; i--)
  {
    const FridaExitEntry * entry = &frida_atexit_entries[i];

    entry->func (entry->user_data);
  }

  gum_free (frida_atexit_entries);
  frida_atexit_entries = 0;
  frida_atexit_count = 0;
}

G_GNUC_INTERNAL int
__cxa_atexit (void (* func) (void *), void * arg, void * dso_handle)
{
  FridaExitEntry * entry;

  frida_init_memory ();

  FRIDA_SHIM_LOCK ();
  frida_atexit_count++;
  frida_atexit_entries = gum_realloc (frida_atexit_entries, frida_atexit_count * sizeof (FridaExitEntry));
  entry = &frida_atexit_entries[frida_atexit_count - 1];
  FRIDA_SHIM_UNLOCK ();

  entry->func = func;
  entry->user_data = arg;

  return 0;
}

#ifdef HAVE_DARWIN

G_GNUC_INTERNAL int
atexit (void (* func) (void))
{
  __cxa_atexit ((FridaExitFunc) func, NULL, NULL);

  return 0;
}

#endif

G_GNUC_INTERNAL void *
malloc (size_t size)
{
  return gum_malloc (size);
}

G_GNUC_INTERNAL void *
calloc (size_t count, size_t size)
{
  return gum_calloc (count, size);
}

G_GNUC_INTERNAL void *
realloc (void * ptr, size_t size)
{
  return gum_realloc (ptr, size);
}

G_GNUC_INTERNAL void *
memalign (size_t alignment, size_t size)
{
  return gum_memalign (alignment, size);
}

G_GNUC_INTERNAL int
posix_memalign (void ** memptr, size_t alignment, size_t size)
{
  gpointer result;

  result = gum_memalign (alignment, size);
  if (result == NULL)
    return ENOMEM;

  *memptr = result;
  return 0;
}

G_GNUC_INTERNAL void
free (void * ptr)
{
  gum_free (ptr);
}

G_GNUC_INTERNAL size_t
malloc_size (const void * ptr)
{
  return gum_malloc_usable_size (ptr);
}

G_GNUC_INTERNAL size_t
malloc_usable_size (const void * ptr)
{
  return gum_malloc_usable_size (ptr);
}

G_GNUC_INTERNAL void *
memcpy (void * dst, const void * src, size_t n)
{
  return gum_memcpy (dst, src, n);
}

G_GNUC_INTERNAL char *
strdup (const char * s)
{
  return g_strdup (s);
}

G_GNUC_INTERNAL int
printf (const char * format, ...)
{
  int result;
  va_list args;
  gchar * message;

  va_start (args, format);
  result = gum_vasprintf (&message, format, args);
  va_end (args);

  fputs (message, stdout);

  g_free (message);

  return result;
}

G_GNUC_INTERNAL int
fprintf (FILE * stream, const char * format, ...)
{
  int result;
  va_list args;
  gchar * message;

  va_start (args, format);
  result = gum_vasprintf (&message, format, args);
  va_end (args);

  fputs (message, stream);

  g_free (message);

  return result;
}

G_GNUC_INTERNAL int
sprintf (char * string, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
snprintf (char * string, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
vprintf (const char * format, va_list args)
{
  int result;
  gchar * message;

  result = gum_vasprintf (&message, format, args);

  fputs (message, stdout);

  g_free (message);

  return result;
}

G_GNUC_INTERNAL int
vfprintf (FILE * stream, const char * format, va_list args)
{
  int result;
  gchar * message;

  result = gum_vasprintf (&message, format, args);

  fputs (message, stream);

  g_free (message);

  return result;
}

G_GNUC_INTERNAL int
vsnprintf (char * string, size_t size, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

G_GNUC_INTERNAL int
__sprintf_chk (char * string, int flag, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
__snprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
__vsnprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

#ifdef HAVE_XLOCALE_H

G_GNUC_INTERNAL int
sprintf_l (char * string, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
snprintf_l (char * string, size_t size, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
asprintf_l (char ** ret, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vasprintf (ret, format, args);
  va_end (args);

  return result;
}

#endif

#endif

#ifdef HAVE_DARWIN

/*
 * Get rid of the -lresolv dependency until we actually need it, i.e. if/when
 * we expose GLib's resolvers to JavaScript. This is however not needed for
 * our current Socket.connect() API, which is neat.
 */

#include <resolv.h>

G_GNUC_INTERNAL int
res_9_init (void)
{
  g_assert_not_reached ();
  return -1;
}

G_GNUC_INTERNAL int
res_9_ninit (res_9_state state)
{
  g_assert_not_reached ();
  return -1;
}

G_GNUC_INTERNAL void
res_9_ndestroy (res_9_state state)
{
  g_assert_not_reached ();
}

G_GNUC_INTERNAL int
res_9_nquery (res_9_state state, const char * dname, int klass, int type, u_char * answer, int anslen)
{
  g_assert_not_reached ();
  return -1;
}

G_GNUC_INTERNAL int
res_9_dn_expand (const u_char * msg, const u_char * eomorig, const u_char * comp_dn, char * exp_dn, int length)
{
  g_assert_not_reached ();
  return -1;
}

#endif

#ifdef HAVE_LINUX

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_dup3
# if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
#  define __NR_dup3 330
# elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
#  define __NR_dup3 292
# elif defined (HAVE_ARM)
#  define __NR_dup3 (__NR_SYSCALL_BASE + 358)
# elif defined (HAVE_MIPS)
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#   define __NR_dup3 4327
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#   define __NR_dup3 5286
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#   define __NR_dup3 6290
#  else
#   error Unexpected MIPS ABI
#  endif
# endif
#endif

int dup3 (int old_fd, int new_fd, int flags);

G_GNUC_INTERNAL int
dup (int old_fd)
{
  return syscall (__NR_dup, old_fd);
}

G_GNUC_INTERNAL int
dup2 (int old_fd, int new_fd)
{
  if (new_fd == old_fd)
  {
    if (fcntl (new_fd, F_GETFD) == -1)
      return -1;
    return new_fd;
  }

  return dup3 (old_fd, new_fd, 0);
}

G_GNUC_INTERNAL int
dup3 (int old_fd, int new_fd, int flags)
{
  return syscall (__NR_dup3, old_fd, new_fd, flags);
}

G_GNUC_INTERNAL long
_frida_set_errno (int n)
{
  errno = n;

  return -1;
}

#endif

#if defined (HAVE_DARWIN) && GLIB_SIZEOF_VOID_P == 8

# undef read
# undef write
# undef mmap
# undef munmap

ssize_t
read (int fildes, void * buf, size_t nbyte)
{
  ssize_t result;

# ifdef HAVE_I386
  register          gint rdi asm ("rdi") = fildes;
  register gconstpointer rsi asm ("rsi") = buf;
  register         gsize rdx asm ("rdx") = nbyte;
  register         guint eax asm ("eax") = 0x2000003;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x16, 0x3\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" ((gsize) fildes),
        "r" (buf),
        "r" (nbyte)
      : "x0", "x1", "x2", "x16"
  );
# endif

  return result;
}

ssize_t
write (int fildes, const void * buf, size_t nbyte)
{
  ssize_t result;

# ifdef HAVE_I386
  register          gint rdi asm ("rdi") = fildes;
  register gconstpointer rsi asm ("rsi") = buf;
  register         gsize rdx asm ("rdx") = nbyte;
  register         guint eax asm ("eax") = 0x2000004;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x16, 0x4\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" ((gsize) fildes),
        "r" (buf),
        "r" (nbyte)
      : "x0", "x1", "x2", "x16"
  );
# endif

  return result;
}

void *
mmap (void * addr, size_t len, int prot, int flags, int fd, off_t offset)
{
  void * result;

# ifdef HAVE_I386
  register      gpointer rdi asm ("rdi") = addr;
  register         gsize rsi asm ("rsi") = len;
  register         gsize rdx asm ("rdx") = (gsize) prot;
  register         gsize r10 asm ("r10") = (gsize) flags;
  register         gsize  r8 asm ( "r8") = (gsize) fd;
  register         gsize  r9 asm ( "r9") = offset;
  register         guint eax asm ("eax") = 0x20000c5;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (r10),
        "r" (r8),
        "r" (r9),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 4\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x3, [sp, #16 * 1]\n\t"
      "stp x4, x5, [sp, #16 * 2]\n\t"
      "str x16, [sp, #16 * 3]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x3, %4\n\t"
      "mov x4, %5\n\t"
      "mov x5, %6\n\t"
      "mov x16, 0xc5\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x3, [sp, #16 * 1]\n\t"
      "ldp x4, x5, [sp, #16 * 2]\n\t"
      "ldr x16, [sp, #16 * 3]\n\t"
      "add sp, sp, #16 * 4\n\t"
      : "=r" (result)
      : "r" (addr),
        "r" (len),
        "r" ((gsize) prot),
        "r" ((gsize) flags),
        "r" ((gsize) fd),
        "r" (offset)
      : "x0", "x1", "x2", "x3", "x4", "x5", "x16"
  );
# endif

  return result;
}

int
munmap (void * addr, size_t len)
{
  int result;

# ifdef HAVE_I386
  register      gpointer rdi asm ("rdi") = addr;
  register         gsize rsi asm ("rsi") = len;
  register         guint eax asm ("eax") = 0x2000049;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "str x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x16, 0x49\n\t"
      "svc 0x80\n\t"
      "mov %w0, w0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldr x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" (addr),
        "r" (len)
      : "x0", "x1", "x16"
  );
# endif

  return result;
}

#endif

"""

```