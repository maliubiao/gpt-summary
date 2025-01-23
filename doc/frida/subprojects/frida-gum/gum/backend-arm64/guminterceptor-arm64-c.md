Response:
Let's break down the thought process for analyzing this C code and fulfilling the request.

1. **Understanding the Goal:** The primary goal is to analyze the provided C code (`guminterceptor-arm64.c`) and explain its functionality, especially in relation to reverse engineering, low-level details, and potential user errors. The request also asks for specific examples and a debugging scenario.

2. **Initial Code Scan and Keyword Recognition:**  My first step is to quickly scan the code, looking for key terms and structures. I see:
    * `#include`:  This tells me about dependencies and the types of functionalities involved (memory, architecture-specific details like `gumarm64reader.h`, OS-specific things like `gumdarwin.h`).
    * `GumInterceptorBackend`, `GumFunctionContext`: These are clearly central data structures, suggesting this code implements part of Frida's interception mechanism.
    * `gum_interceptor_backend_*`:  This naming convention indicates functions related to managing the interceptor backend.
    * `gum_arm64_*`:  Signals architecture-specific logic for ARM64.
    * `trampoline`, `thunk`: These terms are common in dynamic instrumentation, indicating code injection and redirection.
    * `#ifdef HAVE_DARWIN`: Highlights platform-specific code, in this case for macOS/iOS.
    * `dlfcn.h`, `mach-o/`: Further confirms the macOS-specific sections deal with dynamic linking and executable formats.
    * `_gum_interceptor_begin_invocation`, `_gum_interceptor_end_invocation`: Likely hooks called before and after intercepted function execution.
    * `gum_code_allocator_*`: Indicates management of dynamically generated code.
    * Function calls like `gum_memcpy`, `gum_memory_allocate`: Show interaction with memory.
    * Register names like `ARM64_REG_X0`, `ARM64_REG_LR`: Reinforce the ARM64 context.

3. **High-Level Functionality Deduction:** Based on the keywords, I can infer the core purpose: This code implements the ARM64-specific backend for Frida's interception mechanism. It's responsible for:
    * Allocating and managing code for interceptors (trampolines).
    * Redirecting execution flow from the original function to Frida's handlers.
    * Handling function entry and exit.
    * Potentially dealing with platform-specific intricacies (like grafted segments on macOS).

4. **Detailed Analysis - Breaking Down by Sections:** Now I start a more systematic analysis, mentally dividing the code into functional blocks:

    * **Structure Definitions:**  I analyze `GumInterceptorBackend` and `GumArm64FunctionContextData` to understand the data they hold. This gives clues about the state managed by the interceptor.
    * **Backend Creation/Destruction:** The `_gum_interceptor_backend_create` and `_gum_interceptor_backend_destroy` functions are fundamental for managing the backend's lifecycle. The conditional initialization based on code signing policy is a key detail.
    * **macOS Specific Code (`#ifdef HAVE_DARWIN`):** This section is significant. I see it deals with `GumGraftedImport`, `GumGraftedHook`, interacting with the dynamic linker (`_dyld_register_func_for_add_image`), and potentially manipulating code in shared libraries. The concepts of "grafted segments" and "import tables" are central here.
    * **Trampoline Management:** The `gum_interceptor_backend_prepare_trampoline`, `_gum_interceptor_backend_create_trampoline`, `_gum_interceptor_backend_destroy_trampoline`, and `_gum_interceptor_backend_activate_trampoline` functions are the heart of the interception process. I pay attention to how they allocate memory, generate code, and modify the target function's prologue. The handling of "deflectors" is also important.
    * **Thunk Creation:**  The `gum_interceptor_backend_create_thunks` and related functions generate small pieces of code (`enter_thunk`, `leave_thunk`) that are used to call Frida's internal functions when an intercepted function is entered or exited. The `gum_emit_prolog` and `gum_emit_epilog` functions show how the CPU state is saved and restored.
    * **Helper Functions:** Functions like `_gum_interceptor_backend_get_function_address` and `_gum_interceptor_backend_resolve_redirect` provide supporting functionality.

5. **Relating to Reverse Engineering:**  As I analyze, I actively think about how each part relates to reverse engineering:
    * **Code Modification:** The core idea of intercepting involves modifying the target process's code. The trampoline creation and activation are direct examples.
    * **Dynamic Analysis:** Frida is a *dynamic* instrumentation tool. This code is responsible for the runtime aspects of interception.
    * **Understanding Function Behavior:** By intercepting function calls, reverse engineers can observe arguments, return values, and side effects.
    * **Circumventing Security Measures:** The code signing check in the constructor is relevant to bypassing certain security restrictions. The macOS-specific grafted segment handling hints at more advanced techniques to hook system libraries.

6. **Identifying Low-Level Details:** I focus on:
    * **ARM64 Instructions:**  The `gumarm64writer_*` functions show direct manipulation of ARM64 assembly instructions.
    * **Memory Management:**  `GumCodeAllocator`, `gum_memory_allocate`, `gum_memcpy` are clearly low-level memory operations.
    * **Stack Frame Manipulation:** The `gum_emit_prolog` and `gum_emit_epilog` functions demonstrate how the stack is modified to save and restore registers.
    * **Pointers and Addresses:** The code heavily uses pointers and manipulates memory addresses.

7. **Considering User Errors and Debugging:** I think about common mistakes users might make and how this code is involved in the debugging process:
    * **Incorrect Interceptor Logic:** If a user's JavaScript code for the interceptor is faulty, it could lead to crashes within the `_gum_function_context_begin_invocation` or `_gum_function_context_end_invocation` calls.
    * **Conflicting Hooks:**  Multiple Frida scripts trying to hook the same function could lead to unexpected behavior. The locking mechanism (`GRecMutex`) is relevant here.
    * **Memory Corruption:**  While less likely due to user error directly interacting with *this* C code, understanding the memory manipulation is crucial for debugging if memory corruption occurs in the intercepted function or Frida's own internals.

8. **Constructing Examples and the Debugging Scenario:**  Based on my understanding, I create concrete examples to illustrate the functionality. The debugging scenario is designed to show how a user's action (setting up an interceptor) leads to the execution of this specific C code.

9. **Review and Refinement:** Finally, I review my analysis to ensure accuracy, clarity, and completeness. I make sure the examples are relevant and the debugging scenario is plausible. I also double-check that I've addressed all aspects of the original request.
This C source code file, `guminterceptor-arm64.c`, is a crucial part of the Frida dynamic instrumentation toolkit. It implements the **interceptor** functionality specifically for the **ARM64 architecture**. Let's break down its functions:

**Core Functionality:**

1. **Code Injection and Redirection (Trampolines):**  The primary function of this code is to create and manage **trampolines**. A trampoline is a small piece of dynamically generated code that is placed at the beginning of an intercepted function. This trampoline redirects the execution flow to Frida's own handlers, allowing it to execute custom code before and after the original function.

2. **Function Hooking:**  This file provides the low-level mechanisms for hooking functions. When you use Frida to intercept a function, this code is responsible for modifying the target function's prologue (the initial instructions) to jump to the trampoline.

3. **Context Management:** It manages the context of the intercepted function, saving and restoring registers and other relevant information so that the original function can resume execution correctly after Frida's handlers have run. This involves structures like `GumCpuContext`.

4. **Architecture-Specific Implementation:**  Being in the `backend-arm64` directory, the code uses ARM64-specific instructions and concepts. This includes:
    * **Register manipulation:**  Saving and restoring registers like `X0`, `LR`, `FP`, and vector registers.
    * **Instruction writing:** Using `GumArm64Writer` to generate ARM64 assembly code for the trampolines.
    * **Instruction relocation:** Using `GumArm64Relocator` to analyze and potentially rewrite instructions in the target function's prologue to ensure the trampoline works correctly.

5. **Thunk Generation:**  It creates "thunks" (`enter_thunk`, `leave_thunk`). These are small, reusable pieces of code that handle the entry and exit points of an intercepted function. They are responsible for calling Frida's internal functions (`_gum_function_context_begin_invocation`, `_gum_function_context_end_invocation`).

6. **Grafted Hooks (macOS/iOS):**  The `#ifdef HAVE_DARWIN` section deals with a more advanced hooking mechanism called "grafted hooks" specific to macOS and iOS. This likely involves leveraging existing code injection points within the system to minimize code modification and potential detection. It interacts with Mach-O binary format and the dynamic linker (`dyld`).

7. **Code Allocation:** It interacts with a `GumCodeAllocator` to allocate memory for the dynamically generated trampolines and thunks.

**Relationship to Reverse Engineering:**

This file is *directly* related to reverse engineering. Frida is a powerful tool used extensively in reverse engineering for:

* **Dynamic Analysis:** Frida allows reverse engineers to observe the runtime behavior of applications by intercepting function calls, inspecting arguments and return values, and modifying program execution. `guminterceptor-arm64.c` is the core engine for this dynamic analysis on ARM64.

* **Hooking and Instrumentation:** The ability to hook functions is fundamental to reverse engineering. It allows researchers to understand how specific functionalities are implemented, track data flow, and identify vulnerabilities.

* **Bypassing Security Measures:** By intercepting security-related functions (e.g., authentication checks, anti-tampering mechanisms), reverse engineers can often bypass or analyze these protections.

**Examples in Reverse Engineering:**

* **Tracing API Calls:** A reverse engineer could use Frida to hook functions in a specific library or framework to trace the sequence of API calls made by an application. This file is responsible for setting up the redirection that triggers the tracing logic.
    * **Example:** Hooking `open()` on Linux/Android or `open()`/`_NSFileManager` methods on macOS/iOS to track file access.
* **Modifying Function Arguments or Return Values:**  This code sets up the infrastructure that allows a reverse engineer to intercept a function, examine its arguments, potentially modify them before the original function executes, and then examine or change the return value.
    * **Example:** Hooking a licensing function and forcing it to return a "success" code, even if the actual license check fails.
* **Analyzing Malware Behavior:** Security researchers use Frida to intercept system calls and API calls made by malware to understand its actions and communication patterns.
    * **Example:** Hooking `connect()` or `send()` to observe network connections and data being sent by malicious software.

**Binary Underlying, Linux/Android Kernel, and Framework Knowledge:**

* **Binary Underlying (ARM64 Assembly):** This code directly deals with the ARM64 instruction set. Functions like `gum_arm64_writer_put_...` generate specific ARM64 assembly instructions (e.g., `ldr`, `str`, `b`, `bl`). Understanding ARM64 assembly is crucial for comprehending how this code works.
* **Linux/Android Kernel (Indirect):** While this code doesn't directly interact with the kernel in most scenarios, the act of injecting code and modifying process memory is a low-level operation that relies on the operating system's memory management and process control mechanisms. On Android, understanding the Android Runtime (ART) and its execution model is relevant.
* **macOS/iOS Kernel and Frameworks (Direct - Grafted Hooks):** The `#ifdef HAVE_DARWIN` section shows direct interaction with macOS/iOS kernel concepts like Mach-O load commands (`LC_SEGMENT_64`) and the dynamic linker (`dyld`). "Grafted hooks" are a more sophisticated technique that likely leverages specific features of the Darwin kernel and framework loading process.
* **Memory Management:** Concepts like page sizes (`GUM_ARM64_LOGICAL_PAGE_SIZE`), memory protection (e.g., using `gum_try_mprotect` on macOS), and code signing policies are important aspects.

**Examples of Binary/Kernel/Framework Involvement:**

* **Trampoline Placement:**  The code needs to find a suitable location in memory to place the trampoline. This involves understanding memory regions and permissions within the target process.
* **Instruction Relocation:** When modifying the original function's prologue, the `GumArm64Relocator` analyzes the existing instructions. If a jump instruction has a relative offset, and the trampoline is placed far away, the relocator might need to rewrite the instruction to ensure the jump still works correctly.
* **Grafted Hook Details (macOS/iOS):** The code iterates through load commands in the Mach-O header to find specific segments (`__FRIDA_DATA`). This segment likely contains pre-placed "hooks" where Frida can redirect execution. This requires in-depth knowledge of the Mach-O binary format and how the dynamic linker resolves symbols and loads libraries.

**Logical Inference (Hypothetical Input and Output):**

Let's imagine we want to hook a simple function `int add(int a, int b)` at address `0x12345678`.

**Hypothetical Input:**

* `function_address`: `0x12345678`
* `replacement_function` (for a fast interceptor): Address of Frida's handler function.
* `GumInterceptorBackend` structure initialized.
* `GumCodeAllocator` providing memory for the trampoline.

**Logical Steps (Simplified):**

1. **`gum_interceptor_backend_prepare_trampoline`:**  Determines the necessary size for the trampoline and allocates a `GumCodeSlice`. It might also identify a "scratch register" to use for temporary storage.
2. **`_gum_interceptor_backend_create_trampoline`:**
   * Writes ARM64 instructions into the allocated `GumCodeSlice` to create the trampoline. This trampoline will typically:
     * Save relevant registers.
     * Load the address of the Frida handler.
     * Jump to the Frida handler.
     * Have another section to handle returning from the handler to the original function.
   * Analyzes the first few instructions at `0x12345678` using `GumArm64Relocator`.
   * Copies these overwritten instructions into `ctx->overwritten_prologue`.
3. **`_gum_interceptor_backend_activate_trampoline`:**
   * Writes instructions at the beginning of the original function (`0x12345678`). These instructions will jump to the newly created trampoline. The specific instructions depend on the size of the overwritten prologue. It might use a `b` (branch) instruction for short jumps or `ldr` and `br` for longer jumps.

**Hypothetical Output:**

* A `GumCodeSlice` containing the ARM64 trampoline code.
* The first few bytes at `0x12345678` are overwritten with instructions that jump to the trampoline's address.
* When `add(1, 2)` is called, execution will flow: `0x12345678` (now trampoline jump) -> `trampoline code` -> Frida handler -> (after handler returns) -> `original instructions from overwritten prologue` -> rest of the `add` function.

**User or Programming Common Usage Errors:**

While the user doesn't directly interact with this C code, their actions in the Frida scripting environment can lead to issues that manifest here:

1. **Hooking the Same Function Multiple Times:**  If a user tries to hook the same function multiple times without proper management, it could lead to conflicts in trampoline creation and activation. Frida tries to prevent this, but incorrect usage could still cause problems.

2. **Incorrect Frida Script Logic:** If the user's JavaScript code that defines the `onEnter` or `onLeave` handlers has errors, those errors will be triggered when the execution jumps to Frida's handlers via the trampolines created by this C code. This could lead to crashes or unexpected behavior within Frida's internal functions called from the thunks.

3. **Hooking Functions with Very Short Prologues:** If the function being hooked has a very short prologue (e.g., only one or two instructions), the relocation logic might become complex or even impossible to handle reliably. This could lead to errors during trampoline creation.

4. **Memory Protection Issues:** If the user attempts to hook a function in a memory region that doesn't allow code modification, the `_gum_interceptor_backend_activate_trampoline` function might fail when trying to overwrite the prologue.

**Example of a User Operation Leading Here (Debugging Scenario):**

1. **User writes a Frida script (JavaScript):**
   ```javascript
   Interceptor.attach(Module.findExportByName(null, "my_vulnerable_function"), {
     onEnter: function(args) {
       console.log("Entering my_vulnerable_function with arguments:", args);
     },
     onLeave: function(retval) {
       console.log("Leaving my_vulnerable_function with return value:", retval);
     }
   });
   ```

2. **User runs the Frida script against a target process.**

3. **Frida's core logic (in a higher-level language like JavaScript or Python) identifies the target function `my_vulnerable_function` and needs to set up the interception.**

4. **Frida determines the architecture of the target process (ARM64 in this case).**

5. **Frida calls into the ARM64-specific interceptor backend (`guminterceptor-arm64.c`).**

6. **`_gum_interceptor_backend_create` is called to initialize the backend.**

7. **`gum_interceptor_backend_prepare_trampoline` is called to prepare memory for the trampoline at the address of `my_vulnerable_function`.**

8. **`_gum_interceptor_backend_create_trampoline` is called to generate the ARM64 assembly code for the trampoline that will jump to Frida's internal `onEnter` handler.**

9. **`_gum_interceptor_backend_activate_trampoline` is called to overwrite the beginning of `my_vulnerable_function` with a jump to the newly created trampoline.**

10. **Now, when `my_vulnerable_function` is called by the target process, execution will be redirected through the trampoline created by this C code, triggering the user's `onEnter` and `onLeave` handlers.**

**As a debugging线索 (debugging clue):**

If you are debugging a Frida script and encounter issues (e.g., crashes, unexpected behavior) when hooking a function on ARM64, understanding this C code can provide valuable insights:

* **Check Trampoline Address:**  You might use Frida's debugging features to inspect the memory at the address of the hooked function. You should see the jump instruction that leads to the trampoline.
* **Examine Trampoline Code:** If you suspect issues with the trampoline itself, you might try to disassemble the code in the allocated `GumCodeSlice` to see the generated ARM64 instructions.
* **Investigate Relocation Errors:** If the target function's prologue is complex, errors might occur during relocation. Understanding how `GumArm64Relocator` works can help diagnose these issues.
* **macOS/iOS Grafted Hooks:** If you are on macOS/iOS and hooking system libraries, understanding the grafted hook mechanism can be crucial for debugging issues related to those hooks.

In summary, `guminterceptor-arm64.c` is a fundamental piece of Frida's ARM64 instrumentation engine, responsible for the low-level details of code injection, redirection, and context management that enable Frida's powerful dynamic analysis capabilities. Understanding its functionality is essential for advanced Frida users and developers working on ARM64 platforms.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm64/guminterceptor-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2014-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2022 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumarm64reader.h"
#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gumcloak.h"
#include "gumlibc.h"
#include "gummemory.h"
#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
# include "gumdarwingrafter-priv.h"
#endif

#ifdef HAVE_DARWIN
# include <dlfcn.h>
# include <mach-o/dyld.h>
# include <mach-o/loader.h>
# include <stdlib.h>
#endif

#define GUM_ARM64_LOGICAL_PAGE_SIZE 4096

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))

#define GUM_FCDATA(context) \
    ((GumArm64FunctionContextData *) (context)->backend_data.storage)

typedef struct _GumArm64FunctionContextData GumArm64FunctionContextData;

struct _GumInterceptorBackend
{
  GRecMutex * mutex;
  GumCodeAllocator * allocator;

  GumArm64Writer writer;
  GumArm64Relocator relocator;

  gpointer thunks;
  gpointer enter_thunk;
  gpointer leave_thunk;
};

struct _GumArm64FunctionContextData
{
  guint redirect_code_size;
  arm64_reg scratch_reg;
};

G_STATIC_ASSERT (sizeof (GumArm64FunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_thunks (gpointer mem, GumInterceptorBackend * self);
static void gum_emit_enter_thunk (GumArm64Writer * aw);
static void gum_emit_leave_thunk (GumArm64Writer * aw);

static void gum_emit_prolog (GumArm64Writer * aw);
static void gum_emit_epilog (GumArm64Writer * aw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new0 (GumInterceptorBackend);
  backend->mutex = mutex;
  backend->allocator = allocator;

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_OPTIONAL)
  {
    gum_arm64_writer_init (&backend->writer, NULL);
    gum_arm64_relocator_init (&backend->relocator, NULL, &backend->writer);

    gum_interceptor_backend_create_thunks (backend);
  }

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  if (backend->thunks != NULL)
  {
    gum_interceptor_backend_destroy_thunks (backend);

    gum_arm64_relocator_clear (&backend->relocator);
    gum_arm64_writer_clear (&backend->writer);
  }

  g_slice_free (GumInterceptorBackend, backend);
}

#ifdef HAVE_DARWIN

typedef struct _GumImportTarget GumImportTarget;
typedef struct _GumImportEntry GumImportEntry;
typedef struct _GumClaimHookOperation GumClaimHookOperation;
typedef struct _GumGraftedSegmentPairDetails GumGraftedSegmentPairDetails;

typedef gboolean (* GumFoundGraftedSegmentPairFunc) (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);

struct _GumImportTarget
{
  gpointer implementation;
  GumFunctionContext * ctx;
  GArray * entries;
};

struct _GumImportEntry
{
  const struct mach_header_64 * mach_header;
  GumGraftedImport * import;
};

struct _GumClaimHookOperation
{
  GumFunctionContext * ctx;
  guint32 code_offset;

  gboolean success;
};

struct _GumGraftedSegmentPairDetails
{
  const struct mach_header_64 * mach_header;

  GumGraftedHeader * header;

  GumGraftedHook * hooks;
  guint32 num_hooks;

  GumGraftedImport * imports;
  guint32 num_imports;
};

extern void _gum_interceptor_begin_invocation (void);
extern void _gum_interceptor_end_invocation (void);

static void gum_on_module_added (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static void gum_on_module_removed (const struct mach_header * mh,
    intptr_t vmaddr_slide);
static gboolean gum_attach_segment_pair (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);
static gboolean gum_detach_segment_pair (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);
static gboolean gum_claim_hook_if_found_in_pair (
    const GumGraftedSegmentPairDetails * details, gpointer user_data);

static GumImportTarget * gum_import_target_register (gpointer implementation);
static void gum_import_target_link (GumImportTarget * self,
    GumFunctionContext * ctx);
static void gum_import_target_free (GumImportTarget * target);
static void gum_import_target_maybe_activate (GumImportTarget * self,
    const GumImportEntry * entry);
static void gum_import_target_activate (GumImportTarget * self,
    const GumImportEntry * entry);
static void gum_import_target_deactivate (GumImportTarget * self,
    const GumImportEntry * entry);

static void gum_enumerate_grafted_segment_pairs (gconstpointer mach_header,
    GumFoundGraftedSegmentPairFunc func, gpointer user_data);

static int gum_compare_grafted_hook (const void * element_a,
    const void * element_b);

static gboolean gum_is_system_module (const gchar * path);

static GumInterceptorBackend * gum_interceptor_backend = NULL;
static GHashTable * gum_import_targets = NULL;

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  GumImportTarget * target;
  Dl_info info;
  GumClaimHookOperation op;

  if (gum_interceptor_backend == NULL)
  {
    gum_interceptor_backend = self;
    gum_import_targets = g_hash_table_new_full (NULL, NULL, NULL,
        (GDestroyNotify) gum_import_target_free);

    _dyld_register_func_for_add_image (gum_on_module_added);
    _dyld_register_func_for_remove_image (gum_on_module_removed);
  }

  target = g_hash_table_lookup (gum_import_targets, ctx->function_address);
  if (target != NULL)
  {
    gum_import_target_link (target, ctx);
    return TRUE;
  }

  if (dladdr (ctx->function_address, &info) == 0)
    return FALSE;

  op.ctx = ctx;
  op.code_offset = (guint8 *) ctx->function_address - (guint8 *) info.dli_fbase;

  op.success = FALSE;

  gum_enumerate_grafted_segment_pairs (info.dli_fbase,
      gum_claim_hook_if_found_in_pair, &op);

  if (!op.success && gum_is_system_module (info.dli_fname))
  {
    target = gum_import_target_register (ctx->function_address);
    gum_import_target_link (target, ctx);
    return TRUE;
  }

  return op.success;
}

static void
gum_on_module_added (const struct mach_header * mh,
                     intptr_t vmaddr_slide)
{
  g_rec_mutex_lock (gum_interceptor_backend->mutex);
  gum_enumerate_grafted_segment_pairs (mh, gum_attach_segment_pair, NULL);
  g_rec_mutex_unlock (gum_interceptor_backend->mutex);
}

static void
gum_on_module_removed (const struct mach_header * mh,
                       intptr_t vmaddr_slide)
{
  g_rec_mutex_lock (gum_interceptor_backend->mutex);
  gum_enumerate_grafted_segment_pairs (mh, gum_detach_segment_pair, NULL);
  g_rec_mutex_unlock (gum_interceptor_backend->mutex);
}

static gboolean
gum_attach_segment_pair (const GumGraftedSegmentPairDetails * details,
                         gpointer user_data)
{
  const struct mach_header_64 * mach_header = details->mach_header;
  GumGraftedHeader * header = details->header;
  GumGraftedImport * imports = details->imports;
  guint32 i;

  header->begin_invocation =
      GPOINTER_TO_SIZE (_gum_interceptor_begin_invocation);
  header->end_invocation =
      GPOINTER_TO_SIZE (_gum_interceptor_end_invocation);

  for (i = 0; i != header->num_imports; i++)
  {
    GumGraftedImport * import = &imports[i];
    gpointer * slot, implementation;
    GumImportTarget * target;
    GumImportEntry entry;

    slot = (gpointer *) ((const guint8 *) mach_header + import->slot_offset);
    implementation = *slot;

    target = g_hash_table_lookup (gum_import_targets, implementation);
    if (target == NULL)
      target = gum_import_target_register (implementation);

    entry.mach_header = mach_header;
    entry.import = import;
    g_array_append_val (target->entries, entry);

    gum_import_target_maybe_activate (target, &entry);
  }

  return TRUE;
}

static gboolean
gum_detach_segment_pair (const GumGraftedSegmentPairDetails * details,
                         gpointer user_data)
{
  const struct mach_header_64 * mach_header = details->mach_header;
  GHashTableIter iter;
  gpointer implementation;
  GumImportTarget * target;
  GQueue empty_targets = G_QUEUE_INIT;
  GList * cur;

  g_hash_table_iter_init (&iter, gum_import_targets);
  while (g_hash_table_iter_next (&iter, &implementation, (gpointer *) &target))
  {
    GArray * entries = target->entries;
    gint i;

    for (i = 0; i < entries->len; i++)
    {
      GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
      if (entry->mach_header == mach_header)
      {
        g_array_remove_index_fast (entries, i);
        i--;
      }
    }

    if (target->ctx == NULL && entries->len == 0)
    {
      g_queue_push_tail (&empty_targets, implementation);
    }
    else if (entries->len != 0)
    {
      gum_import_target_maybe_activate (target,
          &g_array_index (entries, GumImportEntry, 0));
    }
  }

  for (cur = empty_targets.head; cur != NULL; cur = cur->next)
  {
    g_hash_table_remove (gum_import_targets, cur->data);
  }

  g_queue_clear (&empty_targets);

  return TRUE;
}

static gboolean
gum_claim_hook_if_found_in_pair (const GumGraftedSegmentPairDetails * details,
                                 gpointer user_data)
{
  GumClaimHookOperation * op = user_data;
  GumFunctionContext * ctx = op->ctx;
  GumGraftedHook key = { 0, };
  GumGraftedHook * hook;
  guint8 * trampoline;

  key.code_offset = op->code_offset;
  hook = bsearch (&key, details->hooks, details->header->num_hooks,
      sizeof (GumGraftedHook), gum_compare_grafted_hook);
  if (hook == NULL)
    return TRUE;

  hook->user_data = GPOINTER_TO_SIZE (ctx);

  ctx->grafted_hook = hook;

  trampoline = (guint8 *) details->mach_header + hook->trampoline_offset;
  ctx->on_enter_trampoline =
      trampoline + GUM_GRAFTED_HOOK_ON_ENTER_OFFSET (hook);
  ctx->on_leave_trampoline =
      trampoline + GUM_GRAFTED_HOOK_ON_LEAVE_OFFSET (hook);
  ctx->on_invoke_trampoline =
      trampoline + GUM_GRAFTED_HOOK_ON_INVOKE_OFFSET (hook);

  op->success = TRUE;

  return FALSE;
}

static GumImportTarget *
gum_import_target_register (gpointer implementation)
{
  GumImportTarget * target;

  target = g_slice_new (GumImportTarget);
  target->implementation = implementation;
  target->ctx = NULL;
  target->entries = g_array_new (FALSE, FALSE, sizeof (GumImportEntry));

  g_hash_table_insert (gum_import_targets, implementation, target);

  return target;
}

static void
gum_import_target_link (GumImportTarget * self,
                        GumFunctionContext * ctx)
{
  self->ctx = ctx;
  ctx->import_target = self;
}

static void
gum_import_target_free (GumImportTarget * target)
{
  g_array_free (target->entries, TRUE);

  g_slice_free (GumImportTarget, target);
}

static void
gum_import_target_activate_all (GumImportTarget * self)
{
  GArray * entries = self->entries;
  guint i;

  for (i = 0; i != entries->len; i++)
  {
    const GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
    gum_import_target_activate (self, entry);
  }
}

static void
gum_import_target_deactivate_all (GumImportTarget * self)
{
  GArray * entries = self->entries;
  guint i;

  for (i = 0; i != entries->len; i++)
  {
    const GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
    gum_import_target_deactivate (self, entry);
  }
}

static void
gum_import_target_maybe_activate (GumImportTarget * self,
                                  const GumImportEntry * entry)
{
  GumFunctionContext * ctx = self->ctx;

  if (ctx == NULL || !ctx->activated)
    return;

  gum_import_target_activate (self, entry);
}

static void
gum_import_target_activate (GumImportTarget * self,
                            const GumImportEntry * entry)
{
  GumFunctionContext * ctx = self->ctx;
  GumGraftedImport * import = entry->import;
  gpointer * slot;
  guint8 * trampoline;
  mach_port_t self_task;
  GumPageProtection prot;
  gboolean flip_needed;

  import->user_data = GPOINTER_TO_SIZE (ctx);

  slot = (gpointer *) ((guint8 *) entry->mach_header + import->slot_offset);

  trampoline = (guint8 *) entry->mach_header + import->trampoline_offset;
  ctx->on_enter_trampoline =
      trampoline + GUM_GRAFTED_IMPORT_ON_ENTER_OFFSET (import);
  ctx->on_leave_trampoline =
      trampoline + GUM_GRAFTED_IMPORT_ON_LEAVE_OFFSET (import);
  ctx->on_invoke_trampoline = self->implementation;

  self_task = mach_task_self ();

  if (!gum_darwin_query_protection (self_task, GUM_ADDRESS (slot), &prot))
    return;

  flip_needed = (prot & GUM_PAGE_WRITE) == 0;
  if (flip_needed)
  {
    if (!gum_try_mprotect (slot, 4, prot | GUM_PAGE_WRITE))
      return;
  }

  *slot = ctx->on_enter_trampoline;

  if (flip_needed)
    gum_try_mprotect (slot, 4, prot);
}

static void
gum_import_target_deactivate (GumImportTarget * self,
                              const GumImportEntry * entry)
{
  mach_port_t self_task;
  GumPageProtection prot;
  gboolean flip_needed;
  gpointer * slot =
      (gpointer *) ((guint8 *) entry->mach_header + entry->import->slot_offset);

  self_task = mach_task_self ();

  if (!gum_darwin_query_protection (self_task, GUM_ADDRESS (slot), &prot))
    return;

  flip_needed = (prot & GUM_PAGE_WRITE) == 0;
  if (flip_needed)
  {
    if (!gum_try_mprotect (slot, 4, prot | GUM_PAGE_WRITE))
      return;
  }

  *slot = self->implementation;

  if (flip_needed)
    gum_try_mprotect (slot, 4, prot);
}

static void
gum_import_target_clear_user_data (GumImportTarget * self)
{
  GArray * entries = self->entries;
  guint i;

  for (i = 0; i != entries->len; i++)
  {
    const GumImportEntry * entry = &g_array_index (entries, GumImportEntry, i);
    entry->import->user_data = 0;
  }
}

static void
gum_enumerate_grafted_segment_pairs (gconstpointer mach_header,
                                     GumFoundGraftedSegmentPairFunc func,
                                     gpointer user_data)
{
  const struct mach_header_64 * mh;
  gconstpointer command;
  intptr_t slide;
  guint i;

  mh = mach_header;
  command = mh + 1;
  slide = 0;
  for (i = 0; i != mh->ncmds; i++)
  {
    const struct load_command * lc = command;

    if (lc->cmd == LC_SEGMENT_64)
    {
      const struct segment_command_64 * sc = command;

      if (strcmp (sc->segname, "__TEXT") == 0)
      {
        slide = (guint8 *) mach_header - (guint8 *) sc->vmaddr;
      }
      else if (g_str_has_prefix (sc->segname, "__FRIDA_DATA"))
      {
        GumGraftedHeader * header = GSIZE_TO_POINTER (sc->vmaddr + slide);

        if (header->abi_version == GUM_DARWIN_GRAFTER_ABI_VERSION)
        {
          GumGraftedSegmentPairDetails d;

          d.mach_header = mh;

          d.header = header;

          d.hooks = (GumGraftedHook *) (header + 1);
          d.num_hooks = header->num_hooks;

          d.imports = (GumGraftedImport *) (d.hooks + header->num_hooks);
          d.num_imports = header->num_imports;

          if (!func (&d, user_data))
            return;
        }
      }
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

static int
gum_compare_grafted_hook (const void * element_a,
                          const void * element_b)
{
  const GumGraftedHook * a = element_a;
  const GumGraftedHook * b = element_b;

  return (gssize) a->code_offset - (gssize) b->code_offset;
}

static gboolean
gum_is_system_module (const gchar * path)
{
  gboolean has_system_prefix;
  static gboolean api_initialized = FALSE;
  static bool (* dsc_contains_path) (const char * path) = NULL;

  has_system_prefix = g_str_has_prefix (path, "/System/") ||
      g_str_has_prefix (path, "/usr/lib/") ||
      g_str_has_prefix (path, "/Developer/") ||
      g_str_has_prefix (path, "/private/preboot/");
  if (has_system_prefix)
    return TRUE;

  if (!api_initialized)
  {
    dsc_contains_path =
        dlsym (RTLD_DEFAULT, "_dyld_shared_cache_contains_path");
    api_initialized = TRUE;
  }

  if (dsc_contains_path != NULL)
    return dsc_contains_path (path);

  return FALSE;
}

#else

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
}

#endif

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx,
                                            gboolean * need_deflector)
{
  GumArm64FunctionContextData * data = GUM_FCDATA (ctx);
  gpointer function_address = ctx->function_address;
  guint redirect_limit;

  *need_deflector = FALSE;

  if (gum_arm64_relocator_can_relocate (function_address, 16,
      GUM_SCENARIO_ONLINE, &redirect_limit, &data->scratch_reg))
  {
    data->redirect_code_size = 16;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  }
  else
  {
    GumAddressSpec spec;
    gsize alignment;

    if (redirect_limit >= 8)
    {
      data->redirect_code_size = 8;

      spec.near_address = GSIZE_TO_POINTER (
          GPOINTER_TO_SIZE (function_address) &
          ~((gsize) (GUM_ARM64_LOGICAL_PAGE_SIZE - 1)));
      spec.max_distance = GUM_ARM64_ADRP_MAX_DISTANCE;
      alignment = GUM_ARM64_LOGICAL_PAGE_SIZE;
    }
    else if (redirect_limit >= 4)
    {
      data->redirect_code_size = 4;

      spec.near_address = function_address;
      spec.max_distance = GUM_ARM64_B_MAX_DISTANCE;
      alignment = 0;
    }
    else
    {
      return FALSE;
    }

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, alignment);
    if (ctx->trampoline_slice == NULL)
    {
      ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
      *need_deflector = TRUE;
    }
  }

  if (data->scratch_reg == ARM64_REG_INVALID)
    goto no_scratch_reg;

  return TRUE;

no_scratch_reg:
  {
    gum_code_slice_unref (ctx->trampoline_slice);
    ctx->trampoline_slice = NULL;
    return FALSE;
  }
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64Relocator * ar = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumArm64FunctionContextData * data = GUM_FCDATA (ctx);
  gboolean need_deflector;
  gpointer deflector_target;
  GString * signature;
  gboolean is_eligible_for_lr_rewriting;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx, &need_deflector))
    return FALSE;

  gum_arm64_writer_reset (aw, ctx->trampoline_slice->data);

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
  {
    deflector_target = ctx->replacement_function;
  }
  else
  {
    ctx->on_enter_trampoline =
        gum_sign_code_pointer (gum_arm64_writer_cur (aw));
    deflector_target = ctx->on_enter_trampoline;
  }

  if (need_deflector)
  {
    GumAddressSpec caller;
    gpointer return_address;
    gboolean dedicated;

    caller.near_address =
        (guint8 *) function_address + data->redirect_code_size - 4;
    caller.max_distance = GUM_ARM64_B_MAX_DISTANCE;

    return_address = (guint8 *) function_address + data->redirect_code_size;

    dedicated = data->redirect_code_size == 4;

    ctx->trampoline_deflector = gum_code_allocator_alloc_deflector (
        self->allocator, &caller, return_address, deflector_target, dedicated);
    if (ctx->trampoline_deflector == NULL)
    {
      gum_code_slice_unref (ctx->trampoline_slice);
      ctx->trampoline_slice = NULL;
      return FALSE;
    }

    gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X0, ARM64_REG_LR);
  }

  if (ctx->type != GUM_INTERCEPTOR_TYPE_FAST)
  {
    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
        GUM_ADDRESS (gum_sign_code_pointer (self->enter_thunk)));
    gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

    ctx->on_leave_trampoline = gum_arm64_writer_cur (aw);

    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
    gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
        GUM_ADDRESS (gum_sign_code_pointer (self->leave_thunk)));
    gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);

    gum_arm64_writer_flush (aw);
    g_assert (gum_arm64_writer_offset (aw) <= ctx->trampoline_slice->size);
  }

  ctx->on_invoke_trampoline = gum_sign_code_pointer (gum_arm64_writer_cur (aw));

  gum_arm64_relocator_reset (ar, function_address, aw);

  signature = g_string_sized_new (16);

  do
  {
    const cs_insn * insn;

    reloc_bytes = gum_arm64_relocator_read_one (ar, &insn);
    g_assert (reloc_bytes != 0);

    if (signature->len != 0)
      g_string_append_c (signature, ';');
    g_string_append (signature, insn->mnemonic);
  }
  while (reloc_bytes < data->redirect_code_size);

  /*
   * Try to deal with minimal thunks that determine their caller and pass
   * it along to some inner function. This is important to support hooking
   * dlopen() on Android, where the dynamic linker uses the caller address
   * to decide on namespace and whether to allow the particular library to
   * be used by a particular caller.
   *
   * Because we potentially replace LR in order to trap the return, we end
   * up breaking dlopen() in such cases. We work around this by detecting
   * LR being read, and replace that instruction with a load of the actual
   * caller.
   *
   * This is however a bit risky done blindly, so we try to limit the
   * scope to the bare minimum. A potentially better longer term solution
   * is to analyze the function and patch each point of return, so we don't
   * have to replace LR on entry. That is however a bit complex, so we
   * opt for this simpler solution for now.
   */
  is_eligible_for_lr_rewriting = strcmp (signature->str, "mov;b") == 0 ||
      g_str_has_prefix (signature->str, "stp;mov;mov;bl");

  g_string_free (signature, TRUE);

  if (is_eligible_for_lr_rewriting)
  {
    const cs_insn * insn;

    while ((insn = gum_arm64_relocator_peek_next_write_insn (ar)) != NULL)
    {
      if (insn->id == ARM64_INS_MOV &&
          insn->detail->arm64.operands[1].reg == ARM64_REG_LR)
      {
        arm64_reg dst_reg = insn->detail->arm64.operands[0].reg;
        const guint reg_size = sizeof (gpointer);
        const guint reg_pair_size = 2 * reg_size;
        guint dst_reg_index, dst_reg_slot_index, dst_reg_offset_in_frame;

        gum_arm64_writer_put_push_all_x_registers (aw);

        gum_arm64_writer_put_call_address_with_arguments (aw,
            GUM_ADDRESS (_gum_interceptor_translate_top_return_address), 1,
            GUM_ARG_REGISTER, ARM64_REG_LR);

        if (dst_reg >= ARM64_REG_X0 && dst_reg <= ARM64_REG_X28)
        {
          dst_reg_index = dst_reg - ARM64_REG_X0;
        }
        else
        {
          g_assert (dst_reg >= ARM64_REG_X29 && dst_reg <= ARM64_REG_X30);

          dst_reg_index = dst_reg - ARM64_REG_X29;
        }

        dst_reg_slot_index = (dst_reg_index * reg_size) / reg_pair_size;

        dst_reg_offset_in_frame = (15 - dst_reg_slot_index) * reg_pair_size;
        if (dst_reg_index % 2 != 0)
          dst_reg_offset_in_frame += reg_size;

        gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_X0, ARM64_REG_SP,
            dst_reg_offset_in_frame);

        gum_arm64_writer_put_pop_all_x_registers (aw);

        gum_arm64_relocator_skip_one (ar);
      }
      else
      {
        gum_arm64_relocator_write_one (ar);
      }
    }
  }
  else
  {
    gum_arm64_relocator_write_all (ar);
  }

  if (!ar->eoi)
  {
    GumAddress resume_at;

    resume_at = gum_sign_code_address (
        GUM_ADDRESS (function_address) + reloc_bytes);
    gum_arm64_writer_put_ldr_reg_address (aw, data->scratch_reg, resume_at);
    gum_arm64_writer_put_br_reg (aw, data->scratch_reg);
  }

  gum_arm64_writer_flush (aw);
  g_assert (gum_arm64_writer_offset (aw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
#ifdef HAVE_DARWIN
  if (ctx->grafted_hook != NULL)
  {
    GumGraftedHook * func = ctx->grafted_hook;
    func->user_data = 0;
    return;
  }

  if (ctx->import_target != NULL)
  {
    gum_import_target_clear_user_data (ctx->import_target);
    return;
  }
#endif

  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumArm64Writer * aw = &self->writer;
  GumArm64FunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress on_enter;

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
    on_enter = GUM_ADDRESS (ctx->replacement_function);
  else
    on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

#ifdef HAVE_DARWIN
  if (ctx->grafted_hook != NULL)
  {
    _gum_grafted_hook_activate (ctx->grafted_hook);
    return;
  }

  if (ctx->import_target != NULL)
  {
    gum_import_target_activate_all (ctx->import_target);
    return;
  }
#endif

  gum_arm64_writer_reset (aw, prologue);
  aw->pc = GUM_ADDRESS (ctx->function_address);

  if (ctx->trampoline_deflector != NULL)
  {
    if (data->redirect_code_size == 8)
    {
      gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X0, ARM64_REG_LR);
      gum_arm64_writer_put_bl_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
    else
    {
      g_assert (data->redirect_code_size == 4);
      gum_arm64_writer_put_b_imm (aw,
          GUM_ADDRESS (ctx->trampoline_deflector->trampoline));
    }
  }
  else
  {
    switch (data->redirect_code_size)
    {
      case 4:
        gum_arm64_writer_put_b_imm (aw, on_enter);
        break;
      case 8:
        gum_arm64_writer_put_adrp_reg_address (aw, data->scratch_reg, on_enter);
        gum_arm64_writer_put_br_reg_no_auth (aw, data->scratch_reg);
        break;
      case 16:
        gum_arm64_writer_put_ldr_reg_address (aw, data->scratch_reg, on_enter);
        gum_arm64_writer_put_br_reg (aw, data->scratch_reg);
        break;
      default:
        g_assert_not_reached ();
    }
  }

  gum_arm64_writer_flush (aw);
  g_assert (gum_arm64_writer_offset (aw) <= data->redirect_code_size);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
#ifdef HAVE_DARWIN
  if (ctx->grafted_hook != NULL)
  {
    _gum_grafted_hook_deactivate (ctx->grafted_hook);
    return;
  }

  if (ctx->import_target != NULL)
  {
    gum_import_target_deactivate_all (ctx->import_target);
    return;
  }
#endif

  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return ctx->function_address;
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  return gum_arm64_reader_try_get_relative_jump_target (address);
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  gsize page_size, code_size;
  GumMemoryRange range;

  page_size = gum_query_page_size ();
  code_size = page_size;

  self->thunks = gum_memory_allocate (NULL, code_size, page_size, GUM_PAGE_RW);

  range.base_address = GUM_ADDRESS (self->thunks);
  range.size = code_size;
  gum_cloak_add_range (&range);

  gum_memory_patch_code (self->thunks, 1024,
      (GumMemoryPatchApplyFunc) gum_emit_thunks, self);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_memory_free (self->thunks, gum_query_page_size ());
}

static void
gum_emit_thunks (gpointer mem,
                 GumInterceptorBackend * self)
{
  GumArm64Writer * aw = &self->writer;

  self->enter_thunk = self->thunks;
  gum_arm64_writer_reset (aw, mem);
  aw->pc = GUM_ADDRESS (self->enter_thunk);
  gum_emit_enter_thunk (aw);
  gum_arm64_writer_flush (aw);

  self->leave_thunk =
      (guint8 *) self->enter_thunk + gum_arm64_writer_offset (aw);
  gum_emit_leave_thunk (aw);
  gum_arm64_writer_flush (aw);
}

static void
gum_emit_enter_thunk (GumArm64Writer * aw)
{
  gum_emit_prolog (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, lr));
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X3, ARM64_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2,
      GUM_ARG_REGISTER, ARM64_REG_X3);

  gum_emit_epilog (aw);
}

static void
gum_emit_leave_thunk (GumArm64Writer * aw)
{
  gum_emit_prolog (aw);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X1, ARM64_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X2, ARM64_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

  gum_arm64_writer_put_call_address_with_arguments (aw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, ARM64_REG_X17,
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_REGISTER, ARM64_REG_X2);

  gum_emit_epilog (aw);
}

static void
gum_emit_prolog (GumArm64Writer * aw)
{
  gint i;

  /*
   * Set up our stack frame:
   *
   * [in: frame pointer chain entry, out: next_hop]
   * [in/out: cpu_context]
   */

  /* Reserve space for next_hop */
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_SP, ARM64_REG_SP, 16);

  /* Store vector registers */
  for (i = 30; i != -2; i -= 2)
    gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_Q0 + i, ARM64_REG_Q1 + i);

  /* Store X1-X28, FP, and LR */
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_FP, ARM64_REG_LR);
  for (i = 27; i != -1; i -= 2)
    gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X0 + i, ARM64_REG_X1 + i);

  /* Store NZCV and X0 */
  gum_arm64_writer_put_mov_reg_nzcv (aw, ARM64_REG_X1);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X0);

  /* PC placeholder and SP */
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X0,
      ARM64_REG_SP, sizeof (GumCpuContext) -
      G_STRUCT_OFFSET (GumCpuContext, nzcv) + 16);
  gum_arm64_writer_put_push_reg_reg (aw, ARM64_REG_XZR, ARM64_REG_X0);

  /* Frame pointer chain entry */
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_LR, ARM64_REG_SP,
      sizeof (GumCpuContext) + 8);
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_FP, ARM64_REG_SP,
      sizeof (GumCpuContext) + 0);
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_FP, ARM64_REG_SP,
      sizeof (GumCpuContext));
}

static void
gum_emit_epilog (GumArm64Writer * aw)
{
  guint i;

  /* Skip PC and SP */
  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_SP, ARM64_REG_SP, 16);

  /* Restore NZCV and X0 */
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X0);
  gum_arm64_writer_put_mov_nzcv_reg (aw, ARM64_REG_X1);

  /* Restore X1-X28, FP, and LR */
  for (i = 1; i != 29; i += 2)
    gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X0 + i, ARM64_REG_X1 + i);
  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_FP, ARM64_REG_LR);

  /* Restore vector registers */
  for (i = 0; i != 32; i += 2)
    gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_Q0 + i, ARM64_REG_Q1 + i);

  gum_arm64_writer_put_pop_reg_reg (aw, ARM64_REG_X16, ARM64_REG_X17);
#ifndef HAVE_PTRAUTH
  gum_arm64_writer_put_ret_reg (aw, ARM64_REG_X16);
#else
  gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
#endif
}
```