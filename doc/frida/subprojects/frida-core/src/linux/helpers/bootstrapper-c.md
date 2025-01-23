Response:
Let's break down the thought process for analyzing this C code and answering the request.

**1. Understanding the Goal:**

The core request is to understand the functionality of `bootstrapper.c` within the Frida context and relate it to reverse engineering, low-level details (kernel, framework, binary), logical reasoning, potential errors, and the user's path to this code.

**2. Initial Skim and Keyword Recognition:**

I'd first skim the code looking for familiar keywords and concepts related to dynamic instrumentation and reverse engineering:

* `#include`:  Indicates dependencies on other modules (elf-parser, inject-context) and standard libraries (stdio, unistd, etc.). The `#ifdef NOLIBC` block is interesting, suggesting a scenario without a full standard C library.
* `Frida...`:  Custom data structures and functions related to Frida's internal workings. These likely define the core logic.
* `bootstrap`:  The main function of this file, suggesting the initialization or setup of Frida within a target process.
* `dlopen`, `dlsym`, `dlclose`: Standard dynamic linking functions, crucial for instrumentation.
* `mmap`, `munmap`: Memory management functions, fundamental for code injection and memory manipulation.
* `/proc/self/auxv`, `/proc/self/maps`: Linux-specific files used to gather information about the current process. This is a strong indicator of interaction with the OS at a low level.
* `socketpair`:  Inter-process communication mechanism, suggesting communication between the injected Frida agent and the main Frida process.
* `prctl`: System call for process control, used here to modify dumpable status.
* `ElfW`, `Elf...`:  Data types and macros related to the ELF (Executable and Linkable Format) file format. Essential for parsing executable files.
* `AT_...`, `DT_...`, `PT_...`, `STT_...`:  ELF header tags and types.

**3. Deconstructing the `frida_bootstrap` Function:**

This is the entry point, so understanding its flow is crucial. I'd analyze its steps:

* **Allocation:**  Checks if `ctx->allocation_base` is set. If not, it allocates memory using `mmap`. This hints at Frida needing a dedicated memory region for its operations.
* **`frida_probe_process`:**  A critical function call. The name suggests it gathers information about the target process. The return value is checked for `FRIDA_BOOTSTRAP_AUXV_NOT_FOUND`, pointing to the use of `/proc/self/auxv`.
* **Setting `ctx` members:**  `rtld_flavor`, `rtld_base`, `r_brk` are populated based on the probe results. This shows Frida's awareness of the dynamic linker and its state.
* **Early Exit Conditions:** Checks for `process.interpreter` and `process.libc`. If both are null, it attempts to load libc and raises an error. This highlights the importance of libc for Frida's functionality.
* **`frida_resolve_libc_apis`:**  Another key function. It attempts to find the addresses of essential libc functions. Failure results in `FRIDA_BOOTSTRAP_LIBC_UNSUPPORTED`.
* **Socket Pair Creation:** If `ctx->enable_ctrlfds` is true, a `socketpair` is created. This establishes a communication channel.

**4. Analyzing Supporting Functions:**

I'd then examine the functions called by `frida_bootstrap` and other important ones:

* **`frida_probe_process`:**  Uses `/proc/self/auxv` to get ELF header information. It also checks `/proc/self/maps` to locate libc if the information isn't directly available. The manipulation of `PR_GET_DUMPABLE` and `PR_SET_DUMPABLE` is interesting – it likely tries to ensure it can access the necessary memory regions. The logic around `r_debug` and `r_brk` relates to understanding the dynamic linker's state.
* **`frida_resolve_libc_apis`:**  Iterates through ELF exports of libc to find function addresses. The handling of Android's linker is specific. The attempt to load `libpthread` if `pthread_create` and `pthread_detach` are missing shows flexibility and robustness.
* **`frida_collect_libc_symbol` and `frida_collect_android_linker_symbol`:**  Callbacks used by the ELF parsing functions to locate specific symbols.
* **`frida_try_load_libc_and_raise`:**  This function is fascinating. It constructs a minimal ELF header and attempts to execute the dynamic linker to load libc. This demonstrates a very low-level approach to bootstrapping when the target process is in a very early stage.
* **`frida_map_elf`:**  A custom ELF loader. It reads the ELF headers, maps memory, and loads segments. This is a core part of Frida's injection mechanism.
* **File Parsing Functions (`frida_parse_file`, `frida_parse_auxv_entry`, `frida_try_find_libc_from_maps_line`, etc.):** These functions handle the parsing of `/proc/self/auxv` and `/proc/self/maps` to extract necessary information.

**5. Connecting to Reverse Engineering Concepts:**

At this point, I would actively look for connections to reverse engineering techniques:

* **Code Injection:** The entire process aims to inject Frida's code into a target process. Functions like `frida_map_elf` and the memory manipulation are directly related.
* **Dynamic Analysis:** Frida is a *dynamic* instrumentation tool. This code enables that dynamic behavior by interacting with the running process.
* **Understanding Program Structure:** Parsing ELF headers is essential for understanding the layout of the executable and libraries in memory.
* **API Hooking:**  The `frida_resolve_libc_apis` function is the foundation for hooking libc functions.
* **Bypassing Protections:** The manipulation of `PR_SET_DUMPABLE` can be related to bypassing certain security measures.

**6. Identifying Low-Level Details:**

Focusing on interactions with the OS and hardware:

* **Kernel Interaction:**  Use of `/proc` filesystem, system calls (`prctl`, `socketpair` - even when `NOLIBC` is defined, suggesting custom syscall wrappers).
* **Memory Management:**  `mmap`, `munmap`, page size awareness.
* **ELF Format:**  Deep understanding and parsing of ELF headers and sections.
* **Dynamic Linking:**  Understanding the role of the dynamic linker (`rtld`), its flavors, and how it loads libraries.
* **Android specifics:**  Handling of the Android linker.

**7. Logical Reasoning (Hypothetical Inputs and Outputs):**

I would think about different scenarios:

* **Scenario 1: Successful Injection:**  Input: A target process. Output: `FRIDA_BOOTSTRAP_SUCCESS`, with `ctx` populated with relevant addresses and communication channels established.
* **Scenario 2: Early Injection:** Input: A process in its very initial stages. Output: Might trigger `frida_try_load_libc_and_raise`, attempting manual loading.
* **Scenario 3: Missing Libc Symbols:** Input: A process with a non-standard libc. Output: `FRIDA_BOOTSTRAP_LIBC_UNSUPPORTED`.

**8. User Errors:**

Consider common mistakes developers might make:

* **Incorrect Context Initialization:**  Forgetting to set `allocation_size` or `page_size`.
* **Assuming Libc Availability:** Trying to use Frida in environments without a standard libc (the `NOLIBC` case).
* **File Permission Issues:** Frida relies on reading `/proc/self/*`. Permissions could cause failures.

**9. Tracing the User's Path:**

Imagine the steps a user would take to reach this code:

1. **Install Frida:** The user installs the Frida client and server components.
2. **Target an Application:** The user identifies a running process or starts a new one they want to instrument.
3. **Attach with Frida:** The user uses the Frida client (Python, CLI) to attach to the target process.
4. **Frida Agent Injection:**  Frida's core logic involves injecting an agent (likely containing this `bootstrapper.c` code) into the target process.
5. **`frida_bootstrap` Execution:** Once injected, the `frida_bootstrap` function is the entry point for the agent's initialization.

By following this structured approach, I can systematically analyze the code, understand its purpose, and address all aspects of the request, providing a comprehensive explanation.
This C source file, `bootstrapper.c`, is a crucial component of the Frida dynamic instrumentation toolkit. Its primary function is to **bootstrap** or initialize the Frida agent within a target process on Linux (and potentially Android). Think of it as the initial foothold Frida establishes in the target process's memory space.

Here's a breakdown of its functionalities, relating them to reverse engineering and low-level concepts:

**1. Core Functionality: Initializing the Frida Agent**

* **Memory Allocation:** The `frida_bootstrap` function starts by allocating a chunk of memory within the target process using `mmap`. This memory will be used by the Frida agent for its own data structures and code.
    * **Reverse Engineering Relevance:**  Understanding memory layout is fundamental to reverse engineering. This step shows how Frida establishes its presence in the target's memory.
    * **Binary/Linux/Android Kernel/Framework:** `mmap` is a system call that directly interacts with the Linux (and Android, which is based on Linux) kernel's memory management subsystem. It allocates virtual memory for the process.

* **Process Probing (`frida_probe_process`):** This function gathers essential information about the target process. It reads data from:
    * `/proc/self/auxv`:  Provides auxiliary vector information, including the locations of program headers (PHDR), their size and count, and the base address of the interpreter (dynamic linker).
    * `/proc/self/maps`:  Lists the memory mappings of the process, including the base addresses and paths of loaded libraries like libc.
    * **Reverse Engineering Relevance:**  Analyzing `/proc/self/maps` is a common technique for reverse engineers to understand the memory layout of a process, identify loaded libraries, and find potential code injection points. The auxv information helps understand how the process was started.
    * **Binary/Linux/Android Kernel/Framework:**  `/proc` is a virtual filesystem provided by the Linux kernel, exposing process-specific information. Understanding program headers is crucial for understanding the ELF (Executable and Linkable Format) binary structure. The dynamic linker is a key component of the Linux userspace, responsible for loading shared libraries.

* **Detecting the Dynamic Linker Flavor (`frida_detect_rtld_flavor`, `frida_infer_rtld_flavor_from_filename`):** Frida needs to know which dynamic linker (like glibc's `ld-linux.so`, Android's `linker`, etc.) is being used to handle library loading. This influences how Frida interacts with the process.
    * **Reverse Engineering Relevance:** Different dynamic linkers have different internal structures and behaviors. Recognizing the linker flavor is important for advanced reverse engineering tasks, especially when dealing with hooking or understanding library loading mechanisms.
    * **Binary/Linux/Android Kernel/Framework:** This directly relates to the dynamic linking process in Linux and Android. The dynamic linker is responsible for resolving symbols and loading shared libraries at runtime.

* **Resolving Libc API Addresses (`frida_resolve_libc_apis`, `frida_collect_libc_symbol`, `frida_collect_android_linker_symbol`):**  Frida needs to call standard C library functions (libc) for various tasks. This step finds the in-memory addresses of essential functions like `mmap`, `munmap`, `dlopen`, `dlsym`, `socket`, etc. It does this by:
    * Enumerating the exported symbols of the libc library in memory.
    * Comparing symbol names with known libc function names.
    * **Reverse Engineering Relevance:**  Knowing the addresses of libc functions is fundamental for many reverse engineering tasks, including hooking these functions to intercept their behavior.
    * **Binary/Linux/Android Kernel/Framework:** Libc is a core system library providing essential functions for C programs on Linux and Android. Dynamic linking allows processes to share and use these functions.

* **Creating Control File Descriptors (`frida_bootstrap`):**  If enabled, Frida creates a pair of connected sockets (`socketpair`). These file descriptors are used for communication between the injected Frida agent and the main Frida process (running on the host machine).
    * **Reverse Engineering Relevance:**  Understanding inter-process communication (IPC) mechanisms is essential for reverse engineering complex applications. Frida uses sockets for its own internal communication.
    * **Binary/Linux/Android Kernel/Framework:** `socketpair` is a system call for creating a pair of connected sockets, enabling bidirectional communication within the system.

**2. Handling Early Process Stages**

* **Attempting to Load Libc (`frida_try_load_libc_and_raise`):**  If Frida is injected into a process very early in its startup, libc might not be loaded yet. This function attempts to manually load the dynamic linker (`ld.so`) and use it to load libc. This is a more complex and low-level approach.
    * **Reverse Engineering Relevance:**  This highlights Frida's ability to operate even in very early stages of a process's lifecycle, which can be crucial for debugging or analyzing startup routines.
    * **Binary/Linux/Android Kernel/Framework:** This involves a deep understanding of the dynamic linking process and the structure of ELF files. It directly interacts with the dynamic linker's functionality.

**3. Interacting with ELF Files**

* **ELF Parsing:** The code uses functions (likely defined in `elf-parser.h`) to parse ELF files (executables and shared libraries). This includes reading headers, program headers, dynamic sections, and symbol tables.
    * **Reverse Engineering Relevance:**  ELF analysis is a cornerstone of reverse engineering on Linux and Android. Understanding the structure of ELF files is essential for code analysis, identifying functions, and understanding program behavior.
    * **Binary/Linux/Android Kernel/Framework:**  ELF is the standard binary format on Linux and Android.

**4. Handling System Calls (with and without Libc)**

* **`#ifdef NOLIBC`:**  The code has conditional compilation blocks that define wrappers for certain system calls (`socketpair`, `prctl`) when a full standard C library is not available (`NOLIBC`). This might be relevant in very minimal environments.
    * **Reverse Engineering Relevance:** Understanding system calls is crucial for reverse engineering, as they represent the interface between user-space processes and the kernel.
    * **Binary/Linux/Android Kernel/Framework:** System calls are the fundamental way for user-space programs to request services from the operating system kernel.

**Examples and Use Cases:**

* **Reverse Engineering Example:** A reverse engineer wants to analyze how a particular function in a shared library is being called. They use Frida to attach to the process, and `bootstrapper.c` ensures Frida is initialized. Then, they might use Frida's scripting capabilities to hook functions resolved by `frida_resolve_libc_apis` (like `dlopen` or `dlsym`) to see when and how the target library is loaded.

* **Binary/Linux/Android Kernel/Framework Example:** When `frida_probe_process` reads `/proc/self/maps`, it's directly interacting with the Linux kernel's virtual filesystem interface for providing process information. The parsing of ELF headers relies on the defined structures of the ELF binary format.

**Logical Reasoning (Hypothetical Input and Output):**

**Assumption:** Frida is trying to inject into a running process where libc is already loaded.

**Input:** `FridaBootstrapContext *ctx` containing information like page size, allocation size, and a flag to enable control file descriptors.

**Process within `frida_bootstrap`:**

1. Memory is allocated (or reused if already allocated).
2. `frida_probe_process` reads `/proc/self/auxv` to get the base address of the dynamic linker and `/proc/self/maps` to find the base address of `libc.so`.
3. `frida_detect_rtld_flavor` determines the type of dynamic linker (e.g., glibc).
4. `frida_resolve_libc_apis` uses ELF parsing on the mapped `libc.so` to find the addresses of functions like `mmap`, `dlopen`, etc.
5. If `ctx->enable_ctrlfds` is true, a socket pair is created.

**Output:** `FRIDA_BOOTSTRAP_SUCCESS`. The `ctx` structure will be updated with:
* `ctx->allocation_base`: The address of the allocated memory.
* `ctx->rtld_flavor`: The detected dynamic linker flavor.
* `ctx->rtld_base`: The base address of the dynamic linker.
* `ctx->r_brk`:  A breakpoint address used by the dynamic linker.
* `ctx->ctrlfds`:  File descriptors for the created socket pair (if enabled).
* `ctx->libc`:  A pointer to the `FridaLibcApi` structure containing the resolved libc function addresses.

**User or Programming Common Usage Errors:**

* **Incorrect `FridaBootstrapContext` initialization:** For example, providing an incorrect `allocation_size` that is too small. This could lead to `FRIDA_BOOTSTRAP_ALLOCATION_ERROR`.
* **Trying to use Frida in environments without a standard libc:** If the target process is running in a very minimal environment without libc, `frida_resolve_libc_apis` will likely fail, leading to `FRIDA_BOOTSTRAP_LIBC_UNSUPPORTED`.
* **File permission issues:** If the Frida process doesn't have permissions to read `/proc/self/auxv` or `/proc/self/maps`, `frida_probe_process` will fail, potentially leading to `FRIDA_BOOTSTRAP_AUXV_NOT_FOUND`.

**How User Operation Reaches Here (Debugging Clues):**

1. **User starts a Frida script or uses the Frida CLI tools to attach to a target process.**  For example, using `frida -p <pid>`.
2. **The Frida client (on the host machine) communicates with the Frida server (also on the host or a remote device).**
3. **The Frida server determines the target process and initiates the injection process.**
4. **A Frida agent (which contains the compiled `bootstrapper.c` code) is loaded into the target process's memory space.** This might involve techniques like `ptrace` or other process injection methods.
5. **The entry point of the injected agent is executed, which is the `frida_bootstrap` function.**

Therefore, if you are debugging a Frida issue and want to understand how you reached `bootstrapper.c`, you should look at the steps involved in attaching Frida to the target process and how the agent is being injected. Errors during injection or initialization might manifest within this code. Examining the contents of the `FridaBootstrapContext` at the start of `frida_bootstrap` can provide valuable clues about the environment in which Frida is being initialized.

### 提示词
```
这是目录为frida/subprojects/frida-core/src/linux/helpers/bootstrapper.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "elf-parser.h"
#include "inject-context.h"

#include <alloca.h>
#include <stdalign.h>

#ifdef NOLIBC
# define AF_UNIX 1
# define SOCK_STREAM 1
# define PR_GET_DUMPABLE 3
# define PR_SET_DUMPABLE 4
# define RTLD_LAZY 1
#else
# include <errno.h>
# include <fcntl.h>
# include <signal.h>
# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <sys/prctl.h>
#endif
#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif
#define FRIDA_GLIBC_RTLD_DLOPEN 0x80000000U

#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define FRIDA_STRINGIFY(identifier) _FRIDA_STRINGIFY (identifier)
#define _FRIDA_STRINGIFY(identifier) #identifier

#ifndef DF_1_PIE
# define DF_1_PIE 0x08000000
#endif

#ifndef AT_RANDOM
# define AT_RANDOM 25
#endif

#ifndef AT_EXECFN
# define AT_EXECFN  31
#endif

typedef struct _FridaCollectLibcApiContext FridaCollectLibcApiContext;
typedef struct _FridaProcessLayout FridaProcessLayout;
typedef struct _FridaRDebug FridaRDebug;
typedef int FridaRState;
typedef struct _FridaLinkMap FridaLinkMap;
typedef struct _FridaOpenFileForMappedRangeContext FridaOpenFileForMappedRangeContext;
typedef struct _FridaDetectRtldFlavorContext FridaDetectRtldFlavorContext;
typedef struct _FridaEntrypointParameters FridaEntrypointParameters;
typedef ssize_t (* FridaParseFunc) (void * data, size_t size, void * user_data);

struct _FridaCollectLibcApiContext
{
  int total_missing;
  FridaRtldFlavor rtld_flavor;
  FridaLibcApi * api;
};

struct _FridaProcessLayout
{
  ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_size;
  ElfW(Half) phdr_count;
  ElfW(Ehdr) * interpreter;
  FridaRtldFlavor rtld_flavor;
  FridaRDebug * r_debug;
  void * r_brk;
  void * libc;
};

struct _FridaRDebug
{
  int r_version;
  FridaLinkMap * r_map;
  ElfW(Addr) r_brk;
  FridaRState r_state;
  ElfW(Addr) r_ldbase;
};

enum _FridaRState
{
  RT_CONSISTENT,
  RT_ADD,
  RT_DELETE
};

struct _FridaLinkMap
{
  ElfW(Addr) l_addr;
  char * l_name;
  ElfW(Dyn) * l_ld;
  FridaLinkMap * l_next;
  FridaLinkMap * l_prev;
};

struct _FridaOpenFileForMappedRangeContext
{
  void * base;
  int fd;
};

struct _FridaDetectRtldFlavorContext
{
  ElfW(Ehdr) * interpreter;
  FridaRtldFlavor flavor;
};

struct _FridaEntrypointParameters
{
  intptr_t argc;
  char * argv[2];
  char * envp[1];
  ElfW(auxv_t) auxv[9];
};

static bool frida_resolve_libc_apis (const FridaProcessLayout * layout, FridaLibcApi * libc);
static bool frida_collect_libc_symbol (const FridaElfExportDetails * details, void * user_data);
static bool frida_collect_android_linker_symbol (const FridaElfExportDetails * details, void * user_data);

static bool frida_probe_process (size_t page_size, FridaProcessLayout * layout);
static void frida_enumerate_module_symbols_on_disk (void * loaded_base, FridaFoundElfSymbolFunc func, void * user_data);
static int frida_open_file_for_mapped_range_with_base (void * base);
static ssize_t frida_open_file_for_matching_maps_line (void * data, size_t size, void * user_data);
static FridaRtldFlavor frida_detect_rtld_flavor (ElfW(Ehdr) * interpreter);
static FridaRtldFlavor frida_infer_rtld_flavor_from_filename (const char * name);
static ssize_t frida_try_infer_rtld_flavor_from_maps_line (void * data, size_t size, void * user_data);
static bool frida_path_is_libc (const char * path, FridaRtldFlavor rtld_flavor);
static ssize_t frida_parse_auxv_entry (void * data, size_t size, void * user_data);
static bool frida_collect_interpreter_symbol (const FridaElfExportDetails * details, void * user_data);
static ssize_t frida_try_find_libc_from_maps_line (void * data, size_t size, void * user_data);
static void frida_try_load_libc_and_raise (FridaBootstrapContext * ctx);
static int frida_libc_main (int argc, char * argv[]);
static void * frida_map_elf (FridaBootstrapContext * ctx, const char * path, void ** entrypoint);

static void frida_parse_file (const char * path, FridaParseFunc parse, void * user_data);
static size_t frida_parse_size (const char * str);
static bool frida_str_has_prefix (const char * str, const char * prefix);
static bool frida_str_has_suffix (const char * str, const char * suffix);

static int frida_socketpair (int domain, int type, int protocol, int sv[2]);
static int frida_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
FridaBootstrapStatus
frida_bootstrap (FridaBootstrapContext * ctx)
{
  FridaLibcApi * libc = ctx->libc;
  FridaProcessLayout process;

  if (ctx->allocation_base == NULL)
  {
    ctx->allocation_base = mmap (NULL, ctx->allocation_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (ctx->allocation_base == MAP_FAILED)
        ? FRIDA_BOOTSTRAP_ALLOCATION_ERROR
        : FRIDA_BOOTSTRAP_ALLOCATION_SUCCESS;
  }

  if (!frida_probe_process (ctx->page_size, &process))
    return FRIDA_BOOTSTRAP_AUXV_NOT_FOUND;

  ctx->rtld_flavor = process.rtld_flavor;
  ctx->rtld_base = process.interpreter;
  ctx->r_brk = process.r_brk;

  if (process.interpreter != NULL && process.libc == NULL)
    return FRIDA_BOOTSTRAP_TOO_EARLY;

  if (process.interpreter == NULL && process.libc == NULL)
  {
    frida_try_load_libc_and_raise (ctx);
    return FRIDA_BOOTSTRAP_LIBC_LOAD_ERROR;
  }

  if (!frida_resolve_libc_apis (&process, libc))
    return FRIDA_BOOTSTRAP_LIBC_UNSUPPORTED;

  ctx->ctrlfds[0] = -1;
  ctx->ctrlfds[1] = -1;
  if (ctx->enable_ctrlfds)
    frida_socketpair (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctx->ctrlfds);

  return FRIDA_BOOTSTRAP_SUCCESS;
}

static bool
frida_resolve_libc_apis (const FridaProcessLayout * layout, FridaLibcApi * libc)
{
  FridaCollectLibcApiContext ctx;

  memset (libc, 0, sizeof (FridaLibcApi));
  libc->dlopen_flags = RTLD_LAZY;

  ctx.total_missing = 17;
  if (layout->rtld_flavor == FRIDA_RTLD_ANDROID)
    ctx.total_missing -= 4;
  ctx.rtld_flavor = layout->rtld_flavor;
  ctx.api = libc;
  frida_elf_enumerate_exports (layout->libc, frida_collect_libc_symbol, &ctx);

  if (ctx.total_missing > 0 &&
      (libc->dlopen_flags & FRIDA_GLIBC_RTLD_DLOPEN) != 0 &&
      libc->dlerror == NULL)
  {
    ctx.total_missing--;
  }

  if (ctx.total_missing == 2 &&
      libc->pthread_create == NULL &&
      libc->pthread_detach == NULL)
  {
    const void * pretend_caller_addr = libc->close;
    void * libpthread = libc->dlopen ("libpthread.so.0", libc->dlopen_flags, pretend_caller_addr);
    if (libpthread != NULL)
    {
      libc->pthread_create = libc->dlsym (libpthread, "pthread_create", pretend_caller_addr);
      if (libc->pthread_create != NULL)
        ctx.total_missing--;
      libc->pthread_detach = libc->dlsym (libpthread, "pthread_detach", pretend_caller_addr);
      if (libc->pthread_detach != NULL)
        ctx.total_missing--;
    }
  }

  if (ctx.total_missing != 0)
    return false;

  if (layout->rtld_flavor == FRIDA_RTLD_ANDROID)
  {
    bool found_all_or_none;

    ctx.total_missing = 4;
    frida_elf_enumerate_exports (layout->interpreter, frida_collect_android_linker_symbol, &ctx);

    if (ctx.total_missing == 4)
      frida_enumerate_module_symbols_on_disk (layout->interpreter, frida_collect_android_linker_symbol, &ctx);

    found_all_or_none = ctx.total_missing == 0 || ctx.total_missing == 4;
    if (!found_all_or_none)
      return false;
  }

  return true;
}

static bool
frida_collect_libc_symbol (const FridaElfExportDetails * details, void * user_data)
{
  FridaCollectLibcApiContext * ctx = user_data;
  FridaLibcApi * api = ctx->api;

  if (details->type != STT_FUNC)
    return true;

#define FRIDA_TRY_COLLECT(e) \
    FRIDA_TRY_COLLECT_NAMED (e, FRIDA_STRINGIFY (e))
#define FRIDA_TRY_COLLECT_NAMED(e, n) \
    if (api->e == NULL && strcmp (details->name, n) == 0) \
    { \
      api->e = details->address; \
      ctx->total_missing--; \
      goto beach; \
    }

  FRIDA_TRY_COLLECT (printf)
  FRIDA_TRY_COLLECT (sprintf)

  FRIDA_TRY_COLLECT (mmap)
  FRIDA_TRY_COLLECT (munmap)
  FRIDA_TRY_COLLECT (socket)
  FRIDA_TRY_COLLECT (socketpair)
  FRIDA_TRY_COLLECT (connect)
  FRIDA_TRY_COLLECT (recvmsg)
  FRIDA_TRY_COLLECT (send)
  FRIDA_TRY_COLLECT (fcntl)
  FRIDA_TRY_COLLECT (close)

  FRIDA_TRY_COLLECT (pthread_create)
  FRIDA_TRY_COLLECT (pthread_detach)

  if (ctx->rtld_flavor != FRIDA_RTLD_ANDROID)
  {
    FRIDA_TRY_COLLECT (dlopen)
    if (api->dlopen == NULL && strcmp (details->name, "__libc_dlopen_mode") == 0)
    {
      api->dlopen = details->address;
      api->dlopen_flags |= FRIDA_GLIBC_RTLD_DLOPEN;
      ctx->total_missing--;
      goto beach;
    }

    FRIDA_TRY_COLLECT (dlclose)
    FRIDA_TRY_COLLECT_NAMED (dlclose, "__libc_dlclose")

    FRIDA_TRY_COLLECT (dlsym)
    FRIDA_TRY_COLLECT_NAMED (dlsym, "__libc_dlsym")

    FRIDA_TRY_COLLECT (dlerror)
  }

#undef FRIDA_TRY_COLLECT

beach:
  return ctx->total_missing > 0;
}

static bool
frida_collect_android_linker_symbol (const FridaElfExportDetails * details, void * user_data)
{
  FridaCollectLibcApiContext * ctx = user_data;
  FridaLibcApi * api = ctx->api;

  if (details->type != STT_FUNC)
    return true;

#define FRIDA_TRY_COLLECT(e, n) \
    if (api->e == NULL && strcmp (details->name, n) == 0) \
    { \
      api->e = details->address; \
      ctx->total_missing--; \
      goto beach; \
    }

  FRIDA_TRY_COLLECT (dlopen, "__loader_dlopen");
  FRIDA_TRY_COLLECT (dlclose, "__loader_dlclose");
  FRIDA_TRY_COLLECT (dlsym, "__loader_dlsym");
  FRIDA_TRY_COLLECT (dlerror, "__loader_dlerror");

  FRIDA_TRY_COLLECT (dlopen, "__dl__Z8__dlopenPKciPKv");
  FRIDA_TRY_COLLECT (dlclose, "__dl__Z9__dlclosePv");
  FRIDA_TRY_COLLECT (dlsym, "__dl__Z7__dlsymPvPKcPKv");
  FRIDA_TRY_COLLECT (dlerror, "__dl__Z9__dlerrorv");

#undef FRIDA_TRY_COLLECT

beach:
  return ctx->total_missing > 0;
}

static bool
frida_probe_process (size_t page_size, FridaProcessLayout * layout)
{
  int previous_dumpable;
  bool use_proc_fallback;

  layout->phdrs = NULL;
  layout->phdr_size = 0;
  layout->phdr_count = 0;
  layout->interpreter = NULL;
  layout->rtld_flavor = FRIDA_RTLD_UNKNOWN;
  layout->r_debug = NULL;
  layout->r_brk = NULL;
  layout->libc = NULL;

  previous_dumpable = frida_prctl (PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (previous_dumpable != -1 && previous_dumpable != 1)
    frida_prctl (PR_SET_DUMPABLE, 1, 0, 0, 0);

  frida_parse_file ("/proc/self/auxv", frida_parse_auxv_entry, layout);

  if (previous_dumpable != -1 && previous_dumpable != 1)
    frida_prctl (PR_SET_DUMPABLE, previous_dumpable, 0, 0, 0);

  if (layout->phdrs == NULL)
    return false;

  layout->rtld_flavor = frida_detect_rtld_flavor (layout->interpreter);

  if (layout->interpreter != NULL)
  {
    frida_elf_enumerate_exports (layout->interpreter, frida_collect_interpreter_symbol, layout);

    if (layout->r_debug == NULL || layout->r_brk == NULL)
      frida_enumerate_module_symbols_on_disk (layout->interpreter, frida_collect_interpreter_symbol, layout);

    if (layout->r_debug != NULL)
    {
      FridaRDebug * r = layout->r_debug;
      FridaLinkMap * map, * program;

      for (map = r->r_map; map != NULL; map = map->l_next)
      {
        if (frida_path_is_libc (map->l_name, layout->rtld_flavor))
        {
          layout->libc = (void *) map->l_addr;
          break;
        }
      }

      /*
       * Injecting right after libc has been loaded is risky, e.g. it may not yet be fully linked.
       * So instead of waiting for r_brk to be executed again, we use the program's earliest initializer / entrypoint.
       *
       * This still leaves the issue where we might be attaching to a process in the brief moment right after libc has become
       * visible, but before it's been fully linked in. So we definitely want to move to a better strategy.
       */
      program = r->r_map;
      if (layout->libc == NULL && program != NULL)
      {
        const ElfW(Ehdr) * program_elf;
        ElfW(Addr) addr_delta;
        const ElfW(Dyn) * entries, * entry;

        program_elf = (const ElfW(Ehdr) *)
            frida_elf_compute_base_from_phdrs (layout->phdrs, layout->phdr_size, layout->phdr_count, page_size);

        addr_delta = (program_elf->e_type == ET_EXEC)
            ? 0
            : (ElfW(Addr)) program_elf;

        entries = (program->l_ld != NULL)
            ? program->l_ld
            : frida_elf_find_dynamic_section (program_elf);

        layout->r_brk = NULL;

        for (entry = entries; entry->d_tag != DT_NULL; entry++)
        {
          switch (entry->d_tag)
          {
            case DT_INIT:
              layout->r_brk = (void *) (entry->d_un.d_ptr + addr_delta);
              break;
            case DT_PREINIT_ARRAY:
            case DT_INIT_ARRAY:
              if (layout->r_brk == NULL)
              {
                void * val = *((void **) (entry->d_un.d_ptr + addr_delta));
                if (val != NULL && val != (void *) -1)
                  layout->r_brk = val;
              }
              break;
          }
        }

        if (layout->r_brk == NULL)
          layout->r_brk = (void *) (program_elf->e_entry + addr_delta);
      }

      use_proc_fallback = false;
    }
    else
    {
      use_proc_fallback = true;
    }
  }
  else
  {
    use_proc_fallback = true;
  }

  if (use_proc_fallback)
    frida_parse_file ("/proc/self/maps", frida_try_find_libc_from_maps_line, layout);

  return true;
}

static void
frida_enumerate_module_symbols_on_disk (void * loaded_base, FridaFoundElfSymbolFunc func, void * user_data)
{
  int fd;
  off_t size;
  void * elf;

  fd = frida_open_file_for_mapped_range_with_base (loaded_base);
  if (fd == -1)
    return;
  size = lseek (fd, 0, SEEK_END);
  elf = mmap (NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);

  frida_elf_enumerate_symbols (elf, loaded_base, func, user_data);

  munmap (elf, size);
  close (fd);
}

static int
frida_open_file_for_mapped_range_with_base (void * base)
{
  FridaOpenFileForMappedRangeContext ctx;

  ctx.base = base;
  ctx.fd = -1;
  frida_parse_file ("/proc/self/maps", frida_open_file_for_matching_maps_line, &ctx);

  return ctx.fd;
}

static ssize_t
frida_open_file_for_matching_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  FridaOpenFileForMappedRangeContext * ctx = user_data;
  char * next_newline;
  void * base;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  base = (void *) frida_parse_size (line);
  if (base == ctx->base)
  {
    const char * path = strchr (line, '/');
    if (path != NULL)
    {
      ctx->fd = open (path, O_RDONLY);
      return -1;
    }
  }

  return (next_newline + 1) - (char *) data;
}

static FridaRtldFlavor
frida_detect_rtld_flavor (ElfW(Ehdr) * interpreter)
{
  const char * soname;
  FridaDetectRtldFlavorContext ctx;

  if (interpreter == NULL)
    return FRIDA_RTLD_NONE;

  soname = frida_elf_query_soname (interpreter);
  if (soname != NULL)
    return frida_infer_rtld_flavor_from_filename (soname);

  ctx.interpreter = interpreter;
  ctx.flavor = FRIDA_RTLD_UNKNOWN;
  frida_parse_file ("/proc/self/maps", frida_try_infer_rtld_flavor_from_maps_line, &ctx);

  return ctx.flavor;
}

static FridaRtldFlavor
frida_infer_rtld_flavor_from_filename (const char * name)
{
  if (frida_str_has_prefix (name, "ld-linux-"))
    return FRIDA_RTLD_GLIBC;

  if (frida_str_has_prefix (name, "ld-uClibc"))
    return FRIDA_RTLD_UCLIBC;

  if (strcmp (name, "libc.so") == 0 ||
      frida_str_has_prefix (name, "libc.musl") ||
      frida_str_has_prefix (name, "ld-musl"))
    return FRIDA_RTLD_MUSL;

  if (strcmp (name, "ld-android.so") == 0)
    return FRIDA_RTLD_ANDROID;
  if (strcmp (name, "linker") == 0)
    return FRIDA_RTLD_ANDROID;
  if (strcmp (name, "linker64") == 0)
    return FRIDA_RTLD_ANDROID;

  return FRIDA_RTLD_UNKNOWN;
}

static ssize_t
frida_try_infer_rtld_flavor_from_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  FridaDetectRtldFlavorContext * ctx = user_data;
  char * next_newline;
  void * base;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  base = (void *) frida_parse_size (line);

  if (base == ctx->interpreter)
  {
    const char * filename = strrchr (line, '/') + 1;
    ctx->flavor = frida_infer_rtld_flavor_from_filename (filename);
    return -1;
  }

  return (next_newline + 1) - (char *) data;
}

static bool
frida_path_is_libc (const char * path, FridaRtldFlavor rtld_flavor)
{
  const char * last_slash, * name;

  if (rtld_flavor == FRIDA_RTLD_ANDROID)
  {
    return frida_str_has_suffix (path, "/lib/libc.so") ||
        frida_str_has_suffix (path, "/lib64/libc.so") ||
        frida_str_has_suffix (path, "/bionic/libc.so");
  }

  last_slash = strrchr (path, '/');
  if (last_slash != NULL)
    name = last_slash + 1;
  else
    name = path;

  return frida_str_has_prefix (name, "libc.so") ||
      frida_str_has_prefix (name, "libc.musl") ||
      frida_str_has_prefix (name, "ld-musl");
}

static ssize_t
frida_parse_auxv_entry (void * data, size_t size, void * user_data)
{
  ElfW(auxv_t) * entry = data;
  FridaProcessLayout * layout = user_data;

  if (size < sizeof (ElfW(auxv_t)))
    return 0;

  switch (entry->a_type)
  {
    case AT_PHDR:
      layout->phdrs = (ElfW(Phdr) *) entry->a_un.a_val;
      break;
    case AT_PHENT:
      layout->phdr_size = entry->a_un.a_val;
      break;
    case AT_PHNUM:
      layout->phdr_count = entry->a_un.a_val;
      break;
    case AT_BASE:
      layout->interpreter = (ElfW(Ehdr) *) entry->a_un.a_val;
      break;
  }

  return sizeof (ElfW(auxv_t));
}

static bool
frida_collect_interpreter_symbol (const FridaElfExportDetails * details, void * user_data)
{
  FridaProcessLayout * layout = user_data;
  bool found_both;

  if (layout->r_debug == NULL &&
        details->type == STT_OBJECT && (
        strcmp (details->name, "_r_debug") == 0 ||
        strcmp (details->name, "__dl__r_debug") == 0))
    layout->r_debug = details->address;

  if (layout->r_brk == NULL &&
        details->type == STT_FUNC && (
        strcmp (details->name, "_dl_debug_state") == 0 ||
        strcmp (details->name, "__dl_rtld_db_dlactivity") == 0 ||
        strcmp (details->name, "rtld_db_dlactivity") == 0))
    layout->r_brk = details->address;

  found_both = layout->r_debug != NULL && layout->r_brk != NULL;
  return !found_both;
}

static ssize_t
frida_try_find_libc_from_maps_line (void * data, size_t size, void * user_data)
{
  char * line = data;
  FridaProcessLayout * layout = user_data;
  char * next_newline, * path;

  next_newline = strchr (line, '\n');
  if (next_newline == NULL)
    return 0;

  *next_newline = '\0';

  path = strchr (line, '/');
  if (path != NULL && frida_path_is_libc (path, layout->rtld_flavor))
  {
    layout->libc = (void *) frida_parse_size (line);
    return -1;
  }

  return (next_newline + 1) - (char *) data;
}

static void
frida_try_load_libc_and_raise (FridaBootstrapContext * ctx)
{
  void * ld, * entrypoint, * program;
  uint8_t dummy_random[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
  const char * ld_name = ctx->fallback_ld;
  const char * libc_name = ctx->fallback_libc;
  size_t phdr_offset = 64;
  size_t ld_name_offset = 256;
  size_t ld_name_size = strlen (ld_name) + 1;
  const char * strtab_data = libc_name;
  size_t strtab_offset = 384;
  size_t strtab_size = strlen (libc_name) + 1;
  size_t symtab_offset = 448;
  ElfW(Dyn) dyn[] = {
    {
      .d_tag = DT_NEEDED,
      .d_un.d_val = 0,
    },
    {
      .d_tag = DT_STRTAB,
      .d_un.d_ptr = strtab_offset,
    },
    {
      .d_tag = DT_STRSZ,
      .d_un.d_val = strtab_size,
    },
    {
      .d_tag = DT_SYMTAB,
      .d_un.d_ptr = symtab_offset,
    },
    {
      .d_tag = DT_SYMENT,
      .d_un.d_val = sizeof (ElfW(Sym)),
    },
    {
      .d_tag = DT_FLAGS_1,
      .d_un.d_val = DF_1_PIE,
    },
    {
      .d_tag = DT_NULL,
      .d_un.d_val = 0,
    },
  };
  size_t dyn_offset = 512;
  size_t dyn_size = sizeof (dyn);
  size_t entrypoint_offset = 1024;
  ElfW(Phdr) phdr[] = {
    {
      .p_type = PT_PHDR,
      .p_flags = PF_R,
      .p_offset = phdr_offset,
      .p_vaddr = phdr_offset,
      .p_paddr = phdr_offset,
      .p_align = 8,
    },
    {
      .p_type = PT_INTERP,
      .p_flags = PF_R,
      .p_offset = ld_name_offset,
      .p_vaddr = ld_name_offset,
      .p_paddr = ld_name_offset,
      .p_filesz = ld_name_size,
      .p_memsz = ld_name_size,
      .p_align = 1,
    },
    {
      .p_type = PT_DYNAMIC,
      .p_flags = PF_R | PF_W,
      .p_offset = dyn_offset,
      .p_vaddr = dyn_offset,
      .p_paddr = dyn_offset,
      .p_filesz = dyn_size,
      .p_memsz = dyn_size,
      .p_align = 8,
    },
  };
  ElfW(Ehdr) ehdr = {
    .e_ident = ELFMAG "\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    .e_type = ET_DYN,
    .e_machine = EM_X86_64,
    .e_version = EV_CURRENT,
    .e_entry = entrypoint_offset,
    .e_phoff = phdr_offset,
    .e_shoff = -1,
    .e_flags = 0,
    .e_ehsize = sizeof (ElfW(Ehdr)),
    .e_phentsize = sizeof (ElfW(Phdr)),
    .e_phnum = sizeof (phdr) / sizeof (phdr[0]),
    .e_shentsize = 0,
    .e_shnum = 0,
    .e_shstrndx = 0,
  };

  phdr[0].p_filesz = sizeof (phdr);
  phdr[0].p_memsz = sizeof (phdr);

  entrypoint = NULL;
  ld = frida_map_elf (ctx, ld_name, &entrypoint);
  if (ld == NULL)
    return;

  program = mmap (NULL, ctx->page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memmove (program, &ehdr, sizeof (ehdr));
  memmove (program + phdr_offset, phdr, sizeof (phdr));
  memmove (program + ld_name_offset, ld_name, ld_name_size);
  memmove (program + strtab_offset, strtab_data, strtab_size);
  memmove (program + dyn_offset, dyn, dyn_size);

  {
    alignas (16) FridaEntrypointParameters params = {
      .argc = 1,
      .argv = {
        "/bin/program",
        NULL,
      },
      .envp = {
        NULL,
      },
      .auxv = {
        { .a_type = AT_PAGESZ, .a_un.a_val = ctx->page_size },
        { .a_type = AT_PHDR, .a_un.a_val = (size_t) (program + phdr_offset) },
        { .a_type = AT_PHENT, .a_un.a_val = sizeof (ElfW(Phdr)) },
        { .a_type = AT_PHNUM, .a_un.a_val = sizeof (phdr) / sizeof (phdr[0]) },
        { .a_type = AT_BASE, .a_un.a_val = (size_t) ld },
        { .a_type = AT_ENTRY, .a_un.a_val = (size_t) frida_libc_main },
        { .a_type = AT_RANDOM, .a_un.a_val = (ElfW(Addr)) dummy_random },
        { .a_type = AT_EXECFN, .a_un.a_val = (ElfW(Addr)) "/bin/program" },
        { .a_type = AT_NULL, .a_un.a_val = 0 },
      },
    };

#if defined (__i386__) || defined (__i486__) || defined (__i586__) || defined (__i686__)
    asm volatile (
        "mov %0, %%esp\n\t"
        "jmp *%1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__x86_64__)
    asm volatile (
        "mov %0, %%rsp\n\t"
        "jmp *%1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__ARM_EABI__)
    asm volatile (
        "mov sp, %0\n\t"
        "bx %1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__aarch64__)
    asm volatile (
        "mov sp, %0\n\t"
        "br %1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#elif defined (__mips__)
    asm volatile (
        "move $sp, %0\n\t"
        "jr %1\n\t"
        :
        : "r" (&params),
          "r" (entrypoint)
        : "memory"
    );
#endif
  }
}

static int
frida_libc_main (int argc, char * argv[])
{
  raise (SIGSTOP);
  return 0;
}

static void *
frida_map_elf (FridaBootstrapContext * ctx, const char * path, void ** entrypoint)
{
  bool success = false;
  int fd = -1;
  ElfW(Ehdr) ehdr;
  size_t phdrs_size;
  ElfW(Phdr) * phdrs;
  const ElfW(Addr) page_size = ctx->page_size;
  ElfW(Half) i;
  ElfW(Addr) lowest, highest;
  size_t footprint_size = 0;
  void * base = MAP_FAILED;
  void * previous_end;
  ElfW(Addr) bss_start, bss_end;
  size_t n;

  fd = open (path, O_RDONLY);
  if (fd == -1)
    goto beach;

  if (read (fd, &ehdr, sizeof (ehdr)) != sizeof (ehdr))
    goto beach;

  if (lseek (fd, ehdr.e_phoff, SEEK_SET) == -1)
    goto beach;
  phdrs_size = ehdr.e_phnum * ehdr.e_phentsize;
  phdrs = alloca (phdrs_size);
  if (read (fd, phdrs, phdrs_size) != phdrs_size)
    goto beach;

  lowest = ~0;
  highest = 0;
  for (i = 0; i != ehdr.e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_LOAD)
    {
      lowest = MIN (FRIDA_ELF_PAGE_START (phdr->p_vaddr, page_size), lowest);
      highest = MAX (phdr->p_vaddr + phdr->p_memsz, highest);
    }
  }

  footprint_size = highest - lowest;

  base = mmap (NULL, footprint_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED)
    goto beach;

  previous_end = NULL;

  bss_start = 0;
  bss_end = 0;

  for (i = 0; i != ehdr.e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_LOAD)
    {
      ElfW(Addr) relative_vaddr;
      ElfW(Addr) map_address;
      size_t gap_size, page_offset, map_offset, map_size;
      void * segment_base;
      ElfW(Word) flags = phdr->p_flags;
      int prot;

      relative_vaddr = phdr->p_vaddr - lowest;

      map_address = FRIDA_ELF_PAGE_START (base + relative_vaddr, page_size);

      gap_size = (previous_end != NULL)
          ? (void *) map_address - previous_end
          : 0;
      if (gap_size != 0)
        munmap (previous_end, gap_size);

      page_offset = FRIDA_ELF_PAGE_OFFSET (relative_vaddr, page_size);
      map_offset = phdr->p_offset - page_offset;
      map_size = FRIDA_ELF_PAGE_ALIGN (phdr->p_filesz + page_offset, page_size);

      prot = 0;
      if ((flags & PF_R) != 0)
        prot |= PROT_READ;
      if ((flags & PF_W) != 0)
        prot |= PROT_WRITE;
      if ((flags & PF_X) != 0)
        prot |= PROT_EXEC;

      segment_base = mmap ((void *) map_address, map_size, prot, MAP_PRIVATE | MAP_FIXED, fd, map_offset);
      if (segment_base == MAP_FAILED)
        goto beach;

      previous_end = segment_base + map_size;

      bss_start = MAX ((ElfW(Addr)) base + relative_vaddr + phdr->p_filesz, bss_start);
      bss_end = MAX ((ElfW(Addr)) base + relative_vaddr + phdr->p_memsz, bss_end);
    }
  }

  n = FRIDA_ELF_PAGE_OFFSET (bss_start, page_size);
  if (n != 0)
  {
    n = page_size - n;
    memset ((void *) bss_start, 0, n);
  }

  if (entrypoint != NULL)
    *entrypoint = base + ehdr.e_entry;

  success = true;

beach:
  if (!success && base != MAP_FAILED)
    munmap (base, footprint_size);

  if (fd != -1)
    close (fd);

  return success ? base : NULL;
}

static void
frida_parse_file (const char * path, FridaParseFunc parse, void * user_data)
{
  int fd;
  char * cursor;
  size_t fill_amount;
  char buffer[2048];

  fd = open (path, O_RDONLY);
  if (fd == -1)
    goto beach;

  fill_amount = 0;
  while (true)
  {
    ssize_t n;

    n = read (fd, buffer + fill_amount, sizeof (buffer) - fill_amount - 1);
    if (n > 0)
    {
      fill_amount += n;
      buffer[fill_amount] = '\0';
    }
    if (fill_amount == 0)
      break;

    cursor = buffer;
    while (true)
    {
      ssize_t n = parse (cursor, buffer + fill_amount - cursor, user_data);
      if (n == -1)
        goto beach;
      if (n == 0)
      {
        size_t consumed = cursor - buffer;
        if (consumed != 0)
        {
          memmove (buffer, buffer + consumed, fill_amount - consumed + 1);
          fill_amount -= consumed;
        }
        else
        {
          fill_amount = 0;
        }
        break;
      }

      cursor += n;
    }
  }

beach:
  if (fd != -1)
    close (fd);
}

static size_t
frida_parse_size (const char * str)
{
  size_t result = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    char ch = *cursor;

    if (ch >= '0' && ch <= '9')
      result = (result * 16) + (ch - '0');
    else if (ch >= 'a' && ch <= 'f')
      result = (result * 16) + (10 + (ch - 'a'));
    else
      break;
  }

  return result;
}

static bool
frida_str_has_prefix (const char * str, const char * prefix)
{
  return strncmp (str, prefix, strlen (prefix)) == 0;
}

static bool
frida_str_has_suffix (const char * str, const char * suffix)
{
  size_t str_length, suffix_length;

  str_length = strlen (str);
  suffix_length = strlen (suffix);
  if (str_length < suffix_length)
    return false;

  return strcmp (str + str_length - suffix_length, suffix) == 0;
}

static int
frida_socketpair (int domain, int type, int protocol, int sv[2])
{
#ifdef NOLIBC
  return my_syscall4 (__NR_socketpair, domain, type, protocol, sv);
#else
  return socketpair (domain, type, protocol, sv);
#endif
}

static int
frida_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
#ifdef NOLIBC
  return my_syscall5 (__NR_prctl, option, arg2, arg3, arg4, arg5);
#else
  return prctl (option, arg2, arg3, arg4, arg5);
#endif
}

#ifdef BUILDING_TEST_PROGRAM

#include <assert.h>
#include <stdio.h>
#include <strings.h>

int
main (void)
{
  FridaBootstrapContext ctx;
  FridaBootstrapStatus status;
  FridaLibcApi libc;

  bzero (&ctx, sizeof (ctx));
  ctx.allocation_size = 4096;
  status = frida_bootstrap (&ctx);
  assert (status == FRIDA_BOOTSTRAP_ALLOCATION_SUCCESS);
  printf ("allocation_base: %p\n", ctx.allocation_base);
  assert (ctx.allocation_base != NULL);

  bzero (&libc, sizeof (libc));
  ctx.page_size = getpagesize ();
  ctx.enable_ctrlfds = true;
  ctx.libc = &libc;

  status = frida_bootstrap (&ctx);
  printf ("status: %zu\n", status);

  return 0;
}

#endif
```