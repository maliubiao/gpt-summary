Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the request.

**1. Initial Understanding of the Context:**

The request clearly states this is part of Frida, a dynamic instrumentation toolkit, specifically within the `gumstalker-x86.c` file. This immediately tells us the core function: **code tracing and modification on x86 architectures**. The "stalker" part strongly implies the code is responsible for following the execution flow of a program.

**2. High-Level Function Identification (Scanning for Key Structures and Functions):**

I'd start by scanning the code for prominent data structures and function names. Keywords like `GumStalker`, `GumCpuContext`, `GumExecCtx`, `gum_stalker_find_exec_ctx_by_thread_id`, `gum_stalker_get_exec_ctx`, `gum_exec_ctx_switch_block`, and the presence of architecture-specific registers (`EIP`, `RIP`, `RAX`, etc.) are strong indicators of the code's purpose. The conditional compilation using `#ifdef HAVE_WINDOWS`, `#ifdef HAVE_DARWIN`, etc., points to platform-specific handling.

**3. Deeper Dive into Key Functions:**

* **`gum_x86_register_from_capstone`:**  This function is straightforward. It maps Capstone register IDs to Gum's internal register IDs. This immediately links the code to a specific disassembly library (Capstone) and highlights the interaction with instruction analysis.

* **`gum_stalker_on_exception`:** This is a crucial function. The name "on_exception" suggests it handles exceptions during code execution. The `GUM_EXCEPTION_SINGLE_STEP` check and the manipulation of debug registers (`Dr0`, `Dr7`) strongly indicate the use of hardware breakpoints for single-stepping and potentially more advanced tracing techniques. The conditional logic based on `GLIB_SIZEOF_VOID_P` (32-bit vs. 64-bit) shows different strategies for handling calls. The Windows-specific code further emphasizes the platform-dependent nature.

* **`gum_enable_hardware_breakpoint`:** This is a utility function directly related to the previous one. It shows how hardware breakpoints are configured by manipulating the DR7 register.

* **Platform-Specific Sections (`#ifdef HAVE_WINDOWS`, `#ifdef HAVE_DARWIN`, etc.):**  These sections reveal OS-specific code for tasks like finding system call boundaries (`gum_find_system_call_above_us` on Windows) and locating thread exit functions (`gum_find_thread_exit_implementation`). This highlights the need for platform awareness in a dynamic instrumentation tool.

* **Helper Functions (`gum_collect_export`, `gum_collect_export_by_handle`, `gum_module_find_base_address`, `gum_module_find_symbol_by_name`, etc.):** These functions point towards the ability to interact with loaded modules, find exported functions, and retrieve memory addresses – core functionalities for instrumentation.

**4. Connecting to Reverse Engineering Concepts:**

At this stage, I'd explicitly link the observed functionality to common reverse engineering techniques:

* **Dynamic Analysis:** The core purpose of the code is to monitor and intercept execution, which falls directly under dynamic analysis.
* **Tracing:** The "stalker" concept and the use of breakpoints are fundamental to tracing program execution.
* **Hooking/Instrumentation:** The ability to intercept and potentially modify code flow (implied by the manipulation of `EIP`/`RIP`) is the essence of hooking and instrumentation.
* **Understanding Calling Conventions:**  The Windows-specific code dealing with stack frames and identifying system calls (`gum_find_system_call_above_us`) demonstrates an understanding of calling conventions.

**5. Identifying Low-Level and OS Interactions:**

This is where knowledge of operating systems and architecture comes into play:

* **x86/x64 Architecture:**  The direct manipulation of CPU registers is a clear indicator of low-level interaction.
* **Hardware Breakpoints:** Understanding how debug registers work is crucial for interpreting the `gum_stalker_on_exception` function.
* **System Calls:** The Windows-specific code for finding system calls shows interaction with the operating system kernel.
* **Dynamic Linking and Loading:** Functions like `GetModuleHandle`, `GetProcAddress`, `gum_module_find_export_by_name` relate to how programs load and link libraries.
* **Thread Management:** The handling of thread IDs and finding thread exit functions demonstrates interaction with the OS's thread management mechanisms.

**6. Reasoning and Examples:**

For logical reasoning and examples, I'd consider:

* **Input to `gum_x86_register_from_capstone`:**  Assume a Capstone ID for `X86_REG_EAX`. The output would be the corresponding `GUM_X86_EAX` enum value.
* **Scenarios for `gum_stalker_on_exception`:** Consider a function call. The code uses single-stepping to intercept the return from the call. I'd explain the sequence of events and how the debug registers are used.

**7. Identifying Potential User Errors:**

Think about how a user might misuse Frida or this specific component:

* **Incorrect breakpoint setup:**  Setting breakpoints on invalid addresses or using incorrect conditions.
* **Conflicting instrumentation:** Multiple Frida scripts trying to modify the same code region.
* **Performance overhead:** Excessive tracing can significantly slow down the target process.

**8. Tracing User Actions:**

Consider the typical Frida workflow:

1. User writes a Frida script (JavaScript).
2. The script uses Frida's API to attach to a process.
3. The script uses the `Stalker` API to enable tracing.
4. The `Stalker` in the target process (where this C code runs) starts intercepting instructions.
5. An exception (like a single-step) triggers the `gum_stalker_on_exception` function.

**9. Summarizing the Functionality:**

Finally, synthesize the identified features into a concise summary that captures the essence of `gumstalker-x86.c`. Focus on the core responsibilities: tracing, interception, handling exceptions, and platform-specific adjustments.

**Self-Correction/Refinement During the Process:**

* **Initial focus might be too narrow:**  I might initially focus only on the register mapping. Realizing the "stalker" name is significant would broaden the scope.
* **Overlooking platform differences:**  The `#ifdef` blocks are crucial and shouldn't be ignored. They indicate a significant design aspect.
* **Not connecting to RE concepts explicitly:**  It's important to explicitly link the code's functions to established reverse engineering methodologies.

By following this structured approach, combining code analysis with domain knowledge, and iterating through different aspects, it's possible to generate a comprehensive and accurate answer to the request.
This C source file, `gumstalker-x86.c`, is a crucial component of Frida's dynamic instrumentation engine specifically designed for **x86 and x64 architectures**. It implements the "stalker" functionality, which is responsible for **selectively tracing and intercepting the execution of code** within a target process.

Here's a breakdown of its functionalities, relating them to reverse engineering, low-level details, logical reasoning, potential user errors, and how a user might reach this code:

**1. Core Functionality: Code Tracing and Interception (The "Stalker")**

* **Purpose:** The primary goal of the stalker is to monitor the execution flow of a program, allowing Frida to inject custom logic at specific points or whenever certain conditions are met. This is achieved without modifying the target process's binary on disk.
* **Mechanism:** The stalker uses a combination of techniques to achieve this:
    * **Code Patching/Rewriting:**  It might rewrite parts of the target process's code in memory to redirect execution to Frida's own code.
    * **Hardware Breakpoints:**  On Windows (as seen in the `gum_stalker_on_exception` function), it leverages hardware breakpoints (DR0-DR3, DR7 registers) to intercept execution at specific addresses.
    * **Single-Stepping:** The code handles `GUM_EXCEPTION_SINGLE_STEP` exceptions, indicating the ability to step through code instruction by instruction.
    * **Context Switching:** It manages execution contexts (`GumExecCtx`) to keep track of the original program's state and switch between the target process's code and Frida's injected code.

**2. Relationship to Reverse Engineering Methods:**

* **Dynamic Analysis:** This file is a cornerstone of dynamic analysis. Instead of static analysis (examining the binary without running it), the stalker allows reverse engineers to observe the program's behavior in real-time.
* **Tracing Execution Flow:**  The stalker's core function directly addresses the need to understand how a program executes, which function calls which, and the order of operations.
* **Hooking:** By intercepting function calls or specific instructions, the stalker enables hooking – the ability to insert custom code before or after the execution of target code. This is fundamental for modifying program behavior or gathering information.
* **Identifying Function Boundaries and Arguments:** While not directly implemented in the provided snippet, the stalker provides the foundation for analyzing function calls, inspecting arguments, and return values. The Windows-specific code attempts to identify calls and their return addresses on the stack.
* **Understanding Control Flow:** By observing jumps, calls, and returns, the stalker helps in reconstructing the program's control flow graph.

**Example:**

Imagine you want to understand how a specific function in a game calculates a player's score. Using Frida and the stalker, you could:

1. **Identify the target function's address.**
2. **Use Frida's API to tell the stalker to intercept execution at the beginning of this function.**
3. **When the stalker intercepts execution, your Frida script can:**
    * **Read the function's arguments from registers or the stack.**
    * **Step through the function's instructions to see how the calculation is performed.**
    * **Modify the arguments or even the return value to influence the outcome.**

**3. Binary Underpinnings, Linux, Android Kernel & Framework Knowledge:**

* **x86/x64 Architecture:** The code directly interacts with x86/x64 registers (e.g., EIP, RIP, RAX, RSP, DR0-DR7). It understands the distinction between 32-bit and 64-bit modes (`GLIB_SIZEOF_VOID_P`).
* **Memory Management:** The stalker operates within the target process's memory space. It needs to understand memory layout and how code and data are organized. Functions like `gum_module_find_base_address` indicate awareness of how modules are loaded into memory.
* **Exception Handling:** The `gum_stalker_on_exception` function demonstrates a deep understanding of how the operating system's exception handling mechanism works, specifically for single-step exceptions and hardware breakpoints.
* **Calling Conventions:** The Windows-specific code that tries to find the return address after a call (`gum_find_system_call_above_us`) relies on knowledge of the x86 calling convention (how arguments are passed on the stack, where the return address is stored).
* **System Calls:** The Windows code also attempts to identify system call boundaries, indicating an understanding of how user-space programs interact with the kernel. The mention of `ki_user_callback_dispatcher_impl` hints at internal kernel mechanisms.
* **Thread Management:** The code manages execution contexts per thread (`gum_stalker_find_exec_ctx_by_thread_id`), reflecting the need to handle multi-threaded applications. The `gum_find_thread_exit_implementation` function shows awareness of thread lifecycle management.
* **Platform-Specific APIs:** The use of `#ifdef HAVE_WINDOWS`, `#ifdef HAVE_DARWIN`, etc., highlights the need for platform-specific implementations. Functions like `GetModuleHandle`, `GetProcAddress` (Windows), and the pattern matching for `pthread_exit` (macOS) are examples.

**4. Logical Reasoning and Assumptions (Hypothetical Input & Output):**

* **Input to `gum_x86_register_from_capstone`:**
    * **Assumption:**  `capstone_reg` is a valid register ID from the Capstone disassembly library (e.g., `X86_REG_EAX`).
    * **Output:** The corresponding `GumX86Register` enum value (e.g., `GUM_X86_EAX`).
* **Input to `gum_stalker_on_exception` (Windows scenario):**
    * **Assumption:** A single-step exception (`details->type == GUM_EXCEPTION_SINGLE_STEP`) has occurred in the target process.
    * **Assumption:** The stalker is actively tracing the thread that triggered the exception.
    * **Possible Output:**
        * If the exception occurs at a previously set breakpoint for single-stepping through a call, the code will manipulate the debug registers to step over the call or intercept the return.
        * If the exception occurs at an "infect point" (where Frida injected code), the execution will be redirected to Frida's code.
* **Input to `gum_enable_hardware_breakpoint`:**
    * **Assumption:** `dr7_reg` is a pointer to the DR7 register value, and `index` is a valid hardware breakpoint index (0-3).
    * **Output:** The DR7 register value will be modified to enable the hardware breakpoint at the specified index.

**5. User or Programming Errors:**

* **Incorrect Register Mapping:** If the `gum_x86_register_from_capstone` function had incorrect mappings, Frida would misinterpret the registers used in instructions, leading to incorrect analysis or instrumentation.
* **Race Conditions:** In multi-threaded scenarios, improper management of `GumExecCtx` or shared resources could lead to race conditions, causing unpredictable behavior or crashes.
* **Incorrect Breakpoint Handling:** Errors in the logic within `gum_stalker_on_exception`, such as not correctly restoring debug registers or miscalculating jump addresses, could lead to program crashes or incorrect execution flow.
* **Platform-Specific Issues:** Code that works correctly on one platform might fail on another due to differences in system call conventions, memory layout, or exception handling mechanisms. For example, the Windows-specific code for finding system calls wouldn't work on Linux or macOS.
* **Memory Corruption:** If the stalker incorrectly rewrites code or manipulates memory, it could lead to memory corruption and crashes in the target process.
* **Overhead and Performance:**  Aggressively tracing too many instructions or setting too many breakpoints can introduce significant performance overhead, making the target application sluggish or unresponsive.

**6. User Actions Leading to This Code:**

A user interacting with Frida would indirectly trigger the execution of this code through a series of steps:

1. **User Installs Frida:** The user installs the Frida client and server components on their system and the target device (if it's a mobile device or embedded system).
2. **User Writes a Frida Script:** The user writes a JavaScript script that leverages Frida's API. This script might use the `Stalker` API to enable code tracing. For example:

   ```javascript
   Stalker.follow({
     events: {
       exec: true // Trace every instruction
       // or
       // call: true, // Trace function calls
       // ret: true  // Trace function returns
     }
   });
   ```

3. **User Attaches Frida to a Process:** The user uses the Frida client to attach to a running process or spawn a new process with Frida instrumentation. This establishes a connection between the Frida client and the Frida server running within the target process.
4. **Frida Server Initializes Gum:** The Frida server in the target process initializes the Gum library, which includes the stalker component.
5. **Stalker is Activated:** When the user's script calls `Stalker.follow()`, the Gum stalker is activated. This involves setting up the necessary hooks and mechanisms to intercept execution.
6. **Target Process Executes Code:** As the target process executes instructions, the stalker (implemented in `gumstalker-x86.c`) intercepts the execution based on the specified events (e.g., every instruction, function calls).
7. **`gum_stalker_on_exception` is Invoked (Potentially):**  If hardware breakpoints are used (especially on Windows for single-stepping), the `gum_stalker_on_exception` function will be called by the operating system when a breakpoint is hit.
8. **Instruction Processing and Redirection:** The stalker's logic within this file determines what to do with the intercepted execution – whether to simply record the instruction, redirect execution to a Frida-provided callback, or modify the program's state.

**7. Summary of Functionality:**

In essence, `gumstalker-x86.c` provides the core **real-time code tracing and interception capabilities for x86/x64 architectures within the Frida dynamic instrumentation framework.** It uses a combination of code rewriting, hardware breakpoints, and exception handling to monitor and potentially modify the execution flow of a target process, enabling powerful dynamic analysis and reverse engineering scenarios. It is highly platform-dependent, with specific code paths for Windows and other operating systems, reflecting the underlying differences in their kernel and system-level mechanisms.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
EBP;
    case X86_REG_ESI: return GUM_X86_ESI;
    case X86_REG_EDI: return GUM_X86_EDI;
    case X86_REG_R8D: return GUM_X86_R8D;
    case X86_REG_R9D: return GUM_X86_R9D;
    case X86_REG_R10D: return GUM_X86_R10D;
    case X86_REG_R11D: return GUM_X86_R11D;
    case X86_REG_R12D: return GUM_X86_R12D;
    case X86_REG_R13D: return GUM_X86_R13D;
    case X86_REG_R14D: return GUM_X86_R14D;
    case X86_REG_R15D: return GUM_X86_R15D;
    case X86_REG_EIP: return GUM_X86_EIP;

    case X86_REG_RAX: return GUM_X86_RAX;
    case X86_REG_RCX: return GUM_X86_RCX;
    case X86_REG_RDX: return GUM_X86_RDX;
    case X86_REG_RBX: return GUM_X86_RBX;
    case X86_REG_RSP: return GUM_X86_RSP;
    case X86_REG_RBP: return GUM_X86_RBP;
    case X86_REG_RSI: return GUM_X86_RSI;
    case X86_REG_RDI: return GUM_X86_RDI;
    case X86_REG_R8: return GUM_X86_R8;
    case X86_REG_R9: return GUM_X86_R9;
    case X86_REG_R10: return GUM_X86_R10;
    case X86_REG_R11: return GUM_X86_R11;
    case X86_REG_R12: return GUM_X86_R12;
    case X86_REG_R13: return GUM_X86_R13;
    case X86_REG_R14: return GUM_X86_R14;
    case X86_REG_R15: return GUM_X86_R15;
    case X86_REG_RIP: return GUM_X86_RIP;

    default:
      return GUM_X86_NONE;
  }
}

#ifdef HAVE_WINDOWS

static gboolean
gum_stalker_on_exception (GumExceptionDetails * details,
                          gpointer user_data)
{
  GumStalker * self = GUM_STALKER (user_data);
  GumCpuContext * cpu_context = &details->context;
  CONTEXT * tc = details->native_context;
  GumExecCtx * candidate_ctx;

  if (details->type != GUM_EXCEPTION_SINGLE_STEP)
    return FALSE;

  candidate_ctx =
      gum_stalker_find_exec_ctx_by_thread_id (self, details->thread_id);
  if (candidate_ctx != NULL &&
      GUM_CPU_CONTEXT_XIP (cpu_context) == candidate_ctx->previous_pc)
  {
    GumExecCtx * pending_ctx = candidate_ctx;

    tc->Dr0 = pending_ctx->previous_dr0;
    tc->Dr7 = pending_ctx->previous_dr7;

    pending_ctx->previous_pc = 0;

    GUM_CPU_CONTEXT_XIP (cpu_context) = pending_ctx->infect_body;

    return TRUE;
  }

# if GLIB_SIZEOF_VOID_P == 8
  return FALSE;
# else
  {
    GumExecCtx * ctx;

    ctx = gum_stalker_get_exec_ctx ();
    if (ctx == NULL)
      return FALSE;

    switch (ctx->mode)
    {
      case GUM_EXEC_CTX_NORMAL:
      case GUM_EXEC_CTX_SINGLE_STEPPING_ON_CALL:
      {
        DWORD instruction_after_call_here;
        DWORD instruction_after_call_above_us;

        ctx->previous_dr0 = tc->Dr0;
        ctx->previous_dr1 = tc->Dr1;
        ctx->previous_dr2 = tc->Dr2;
        ctx->previous_dr7 = tc->Dr7;

        tc->Dr7 = 0x00000700;

        instruction_after_call_here = cpu_context->eip +
            gum_x86_reader_insn_length ((guint8 *) cpu_context->eip);
        tc->Dr0 = instruction_after_call_here;
        gum_enable_hardware_breakpoint (&tc->Dr7, 0);

        tc->Dr1 = (DWORD) self->ki_user_callback_dispatcher_impl;
        gum_enable_hardware_breakpoint (&tc->Dr7, 1);

        instruction_after_call_above_us =
            (DWORD) gum_find_system_call_above_us (self,
                (gpointer *) cpu_context->esp);
        if (instruction_after_call_above_us != 0)
        {
          tc->Dr2 = instruction_after_call_above_us;
          gum_enable_hardware_breakpoint (&tc->Dr7, 2);
        }

        ctx->mode = GUM_EXEC_CTX_SINGLE_STEPPING_THROUGH_CALL;

        break;
      }
      case GUM_EXEC_CTX_SINGLE_STEPPING_THROUGH_CALL:
      {
        tc->Dr0 = ctx->previous_dr0;
        tc->Dr1 = ctx->previous_dr1;
        tc->Dr2 = ctx->previous_dr2;
        tc->Dr7 = ctx->previous_dr7;

        gum_exec_ctx_switch_block (ctx, NULL,
            GSIZE_TO_POINTER (cpu_context->eip),
            GSIZE_TO_POINTER (cpu_context->eip));
        cpu_context->eip = (DWORD) ctx->resume_at;

        ctx->mode = GUM_EXEC_CTX_NORMAL;

        break;
      }
      default:
        g_assert_not_reached ();
    }

    return TRUE;
  }
#endif
}

static void
gum_enable_hardware_breakpoint (GumNativeRegisterValue * dr7_reg,
                                guint index)
{
  /* Set both RWn and LENn to 00. */
  *dr7_reg &= ~((GumNativeRegisterValue) 0xf << (16 + (2 * index)));

  /* Set LE bit. */
  *dr7_reg |= (GumNativeRegisterValue) (1 << (2 * index));
}

# if GLIB_SIZEOF_VOID_P == 4

static void
gum_collect_export (GArray * impls,
                    const TCHAR * module_name,
                    const gchar * export_name)
{
  HMODULE module_handle;

  module_handle = GetModuleHandle (module_name);
  if (module_handle == NULL)
    return;

  gum_collect_export_by_handle (impls, module_handle, export_name);
}

static void
gum_collect_export_by_handle (GArray * impls,
                              HMODULE module_handle,
                              const gchar * export_name)
{
  gsize impl;

  impl = GPOINTER_TO_SIZE (GetProcAddress (module_handle, export_name));
  if (impl == 0)
    return;

  g_array_append_val (impls, impl);
}

static gpointer
gum_find_system_call_above_us (GumStalker * stalker,
                               gpointer * start_esp)
{
  gpointer * top_esp, * cur_esp;
  guint8 call_fs_c0_code[] = { 0x64, 0xff, 0x15, 0xc0, 0x00, 0x00, 0x00 };
  guint8 call_ebp_8_code[] = { 0xff, 0x55, 0x08 };
  guint8 * minimum_address, * maximum_address;

#ifdef _MSC_VER
  __asm
  {
    mov eax, fs:[4];
    mov [top_esp], eax;
  }
#else
  asm volatile (
      "movl %%fs:4, %k0"
      : "=q" (top_esp)
  );
#endif

  if ((guint) ABS (top_esp - start_esp) > stalker->page_size)
  {
    top_esp = (gpointer *) ((GPOINTER_TO_SIZE (start_esp) +
        (stalker->page_size - 1)) & ~(stalker->page_size - 1));
  }

  /* These boundaries are quite artificial... */
  minimum_address = (guint8 *) stalker->user32_start + sizeof (call_fs_c0_code);
  maximum_address = (guint8 *) stalker->user32_end - 1;

  for (cur_esp = start_esp + 1; cur_esp < top_esp; cur_esp++)
  {
    guint8 * address = (guint8 *) *cur_esp;

    if (address >= minimum_address && address <= maximum_address)
    {
      if (memcmp (address - sizeof (call_fs_c0_code), call_fs_c0_code,
          sizeof (call_fs_c0_code)) == 0
          || memcmp (address - sizeof (call_ebp_8_code), call_ebp_8_code,
          sizeof (call_ebp_8_code)) == 0)
      {
        return address;
      }
    }
  }

  return NULL;
}

# endif

#endif

static gpointer
gum_find_thread_exit_implementation (void)
{
#if defined (HAVE_DARWIN)
  GumAddress result = 0;
  const gchar * pthread_path = "/usr/lib/system/libsystem_pthread.dylib";
  GumMemoryRange range;
  GumMatchPattern * pattern;

  range.base_address = gum_module_find_base_address (pthread_path);
  range.size = 128 * 1024;

  pattern = gum_match_pattern_new_from_string (
#if GLIB_SIZEOF_VOID_P == 8
      /*
       * Verified on macOS:
       * - 10.14.6
       * - 10.15.6
       * - 11.0 Beta 3
       */
      "55 "            /* push rbp                       */
      "48 89 e5 "      /* mov rbp, rsp                   */
      "41 57 "         /* push r15                       */
      "41 56 "         /* push r14                       */
      "53 "            /* push rbx                       */
      "50 "            /* push rax                       */
      "49 89 f6 "      /* mov r14, rsi                   */
      "49 89 ff"       /* mov r15, rdi                   */
      "bf 01 00 00 00" /* mov edi, 0x1                   */
#else
      /*
       * Verified on macOS:
       * - 10.14.6
       */
      "55 "            /* push ebp                       */
      "89 e5 "         /* mov ebp, esp                   */
      "53 "            /* push ebx                       */
      "57 "            /* push edi                       */
      "56 "            /* push esi                       */
      "83 ec 0c "      /* sub esp, 0xc                   */
      "89 d6 "         /* mov esi, edx                   */
      "89 cf"          /* mov edi, ecx                   */
#endif
  );

  gum_memory_scan (&range, pattern, gum_store_thread_exit_match, &result);

  gum_match_pattern_unref (pattern);

  /* Non-public symbols are all <redacted> on iOS. */
#ifndef HAVE_IOS
  if (result == 0)
    result = gum_module_find_symbol_by_name (pthread_path, "_pthread_exit");
#endif

  return GSIZE_TO_POINTER (result);
#elif defined (HAVE_GLIBC)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_query_libc_name (),
        "__call_tls_dtors"));
#elif defined (HAVE_ANDROID)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_query_libc_name (),
        "pthread_exit"));
#elif defined (HAVE_FREEBSD)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        "/lib/libthr.so.3",
        "_pthread_exit"));
#else
  return NULL;
#endif
}

#ifdef HAVE_DARWIN

static gboolean
gum_store_thread_exit_match (GumAddress address,
                             gsize size,
                             gpointer user_data)
{
  GumAddress * result = user_data;

  *result = address;

  return FALSE;
}

#endif

#endif
```