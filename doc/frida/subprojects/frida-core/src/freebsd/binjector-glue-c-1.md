Response:
The user wants to understand the functionality of the provided C code snippet, which is part of Frida, a dynamic instrumentation toolkit.

Here's a breakdown of the thought process to analyze the code and answer the user's request:

1. **Identify the Core Functionality:** The code heavily uses preprocessor directives (`#if defined`, `#elif defined`) to handle different architectures (x86 and ARM64). This suggests that the core functionality is architecture-dependent. The presence of `gum_x86_writer_*` and `gum_arm64_writer_*` functions further confirms this and points towards runtime code generation or manipulation.

2. **Analyze Architecture-Specific Blocks:**
   - **x86:** Look for common x86 assembly instructions (PUSH, MOV, SUB, CALL, RET). Note the use of `EMIT_*` macros, which likely encapsulate these instructions. The code sequence seems to be setting up a stack frame, calling functions like `open`, `write`, `dlopen`, `dlsym`, `dlclose`, and `pthread_detach`, and then cleaning up. The use of `FRIDA_REMOTE_DATA_FIELD` suggests interaction with data in the target process.
   - **ARM64:** Similar to x86, identify ARM64 assembly instructions (MOV, ADD, PUSH, POP, LDR, STR, BLR, RET). Again, `EMIT_*` macros are used. The overall flow seems comparable to the x86 version, performing similar actions like opening a file, writing data, loading libraries, resolving symbols, and detaching threads.

3. **Identify Common Functionality:** Despite the architecture-specific sections, some code blocks appear to be shared or have similar purposes.
   - `frida_inject_instance_commit_*_code`: This function likely finalizes the generated code and makes it ready for execution.
   - `frida_inject_instance_emit_payload_code`: This seems to be the main function responsible for generating the payload code.
   - The use of `api->..._impl` suggests a level of abstraction for interacting with system calls or library functions in the target process. The `FridaRemoteApi` structure likely holds pointers to these functions.

4. **Connect to Reverse Engineering:** The code's ability to inject code into a running process and call functions within it is a key technique in dynamic analysis and reverse engineering. It allows researchers to observe and modify the behavior of an application at runtime.

5. **Identify Low-Level/Kernel/Framework Interactions:** The code interacts with:
   - **Binary Level:** It directly manipulates assembly instructions.
   - **Operating System (Linux/FreeBSD):** It uses system calls like `open`, `write`, `close`, `dlopen`, `dlsym`, `dlclose`, `pthread_create`, `pthread_detach`, and `waitpid`. The use of `ptrace` is a strong indicator of low-level process manipulation, a kernel feature.
   - **Dynamic Linking (ld):** Functions like `dlopen`, `dlsym`, and `dlclose` directly interact with the dynamic linker.
   - **Threading (pthread):** The code manipulates threads using functions like `pthread_create` and `pthread_detach`.

6. **Analyze Logical Reasoning:** The code has conditional logic (e.g., `EMIT_CMP`, `EMIT_JNE`, `EMIT_JE`, `EMIT_CBNZ`, `EMIT_B_COND`) that controls the execution flow based on the return values of function calls or the state of variables. For example, it checks if a module is already loaded before attempting to load it again.

7. **Consider User/Programming Errors:**  Incorrect usage of the Frida API, such as providing wrong paths to libraries or incorrect entry point names, could lead to failures within this code. Memory allocation failures in the target process or permission issues are also potential error scenarios.

8. **Trace User Operations:**  To reach this code, a user would typically:
   - Use the Frida client API (e.g., Python bindings).
   - Target a specific process (by PID or name).
   - Request code injection, potentially specifying a library to load and a function to call.
   - Frida would then prepare the necessary data structures and generate the payload code represented in this file.

9. **Summarize Functionality (Part 2):** Based on the analysis, the code primarily focuses on constructing and injecting a payload into a target process. This payload performs actions like opening a communication channel (FIFO), loading a shared library, resolving a function within that library, calling the function, and potentially detaching a thread or unloading the library based on a policy. It also handles architecture differences.

By following these steps, we can systematically dissect the code and generate a comprehensive answer to the user's request.
This is the second part of the `frida/subprojects/frida-core/src/freebsd/binjector-glue.c` file, focusing on the code injection payload construction for different architectures (x86 and ARM64).

Let's break down its functionality:

**Core Functionality: Constructing and Injecting Payload Code**

This code snippet is responsible for dynamically generating the assembly instructions that will be injected into the target process. This injected code acts as a bridge, facilitating communication and interaction between Frida and the target application. It's architecture-specific, with separate code generation logic for x86 and ARM64.

**Specific Actions Performed by the Injected Payload:**

1. **Establish Communication:**
   - Opens a FIFO (First-In, First-Out) named pipe for communication with the Frida agent.
   - Writes a "hello byte" to the FIFO, signaling successful initial injection.

2. **Dynamic Library Loading and Function Invocation:**
   - **Conditional Library Loading:** Checks if a module (shared library) handle is already present. If not, it attempts to load the specified shared library (`so_path`) using `dlopen`.
   - **Symbol Resolution:** Uses `dlsym` to find the address of a specific entry point function (`entrypoint_name`) within the loaded library.
   - **Function Call:**  Calls the resolved entry point function, passing arguments. The arguments include:
     - `entrypoint_data`:  Likely data passed from Frida to the injected function.
     - `unload_policy`:  Determines how the injected library should be handled after the function call.
     - `fd`: The file descriptor of the FIFO.

3. **Library Unloading and Thread Management (Conditional):**
   - **Unload Policy:** Implements different policies for unloading the injected library:
     - `FRIDA_UNLOAD_POLICY_IMMEDIATE`: Unloads the library immediately after the entry point function returns using `dlclose`.
     - `FRIDA_UNLOAD_POLICY_DEFERRED`:  Detaches the worker thread (created during the initial injection) using `pthread_detach`.
   - **Thread ID Retrieval:** Retrieves the thread ID of the current thread using `pthread_getthreadid_np`.

4. **Communication of Results:**
   - Writes the chosen `unload_policy` back to the FIFO.
   - Writes the thread ID to the FIFO.

5. **Cleanup:**
   - Closes the FIFO.
   - Restores the stack and returns control to the caller in the target process.

**Relationship to Reverse Engineering:**

This code is *fundamental* to Frida's reverse engineering capabilities. Here's how:

* **Dynamic Instrumentation:** It enables the core principle of dynamic instrumentation – injecting custom code into a running process without modifying its executable file on disk.
* **Function Hooking/Interception:** By injecting code and calling functions within the target process, Frida can intercept function calls, examine arguments, modify return values, and execute custom logic before or after the original function. The `entrypoint_name` is the target function to be "hooked" or interacted with.
* **Code Execution in Target Context:** The injected code runs within the address space of the target process, having access to its memory and resources. This allows for powerful introspection and manipulation.
* **Example:** Imagine you want to understand how a specific function in a closed-source application validates user input. Using Frida, you could:
    1. Use the Frida client to target the application's process.
    2. Inject code using mechanisms that eventually lead to this `binjector-glue.c` code being executed.
    3. The injected payload would load a custom library containing your "hook" function (the `entrypoint_name`).
    4. Your hook function would be called whenever the original validation function is executed, allowing you to inspect the input, the application's internal state, and even modify the validation process.

**Binary Level, Linux/Android Kernel & Framework Knowledge:**

* **Binary Level:**
    - The code directly manipulates assembly instructions using the `gum` library (part of the V8 JavaScript engine, used by Frida for code generation).
    - It understands CPU registers (e.g., `XBP`, `XSP`, `EAX`, `X0`, `FP`, `LR`) and their roles in function calls and stack management.
    - It deals with concepts like stack alignment and instruction encoding.
* **Linux/FreeBSD Kernel:**
    - **`ptrace`:** While not directly in this code snippet, the broader context of `binjector-glue.c` and Frida involves heavy use of the `ptrace` system call. `ptrace` allows one process to control another, enabling actions like reading/writing memory, setting breakpoints, and injecting code. The code comments reference `PT_CONTINUE`, `PT_GETREGS`, `PT_SETREGS`, and `PT_IO`, which are `ptrace` operations.
    - **Process Memory Management:** The code interacts with memory management concepts through functions like `dlopen` (loads shared libraries into the process's address space) and the need to allocate executable memory for the injected code (likely handled elsewhere in Frida).
    - **System Calls:**  The code indirectly uses system calls like `open`, `write`, `close` through the resolved function pointers in the `api` structure.
    - **Signals:** The surrounding code (not shown here) uses signals (like `SIGTRAP`, `SIGSTOP`) in conjunction with `ptrace` for process control and synchronization.
* **Dynamic Linking (ld):**
    - The code directly calls functions provided by the dynamic linker (`dlopen`, `dlsym`, `dlclose`). Understanding how dynamic linking works is crucial for successful code injection and function hooking.
    - Concepts like `RTLD_LAZY` and `RTLD_GLOBAL` (flags for `dlopen`) are used.
* **Threading (pthread):**
    - The code uses `pthread_create` (in the initial injection setup, not shown here) and `pthread_detach` and `pthread_getthreadid_np`. Understanding how threads work and how to interact with them is important for managing the injected payload's execution.
* **Android Framework (Indirectly):** While this specific file is for FreeBSD, the concepts are similar on Android. On Android, `linker` (the Android dynamic linker) and `libcutils` provide similar functionality to the standard Linux/FreeBSD libraries. Frida on Android would use analogous approaches for code injection and function hooking.

**Logical Reasoning (Hypothetical Input and Output):**

Let's assume the following input to the Frida injection process:

* **Target Process:** A process with PID `1234`.
* **`fifo_path`:** `/tmp/frida_pipe_1234`.
* **`so_path`:** `/data/local/tmp/my_agent.so`.
* **`entrypoint_name`:** `my_hook_function`.
* **`entrypoint_data`:** A pointer to some data structure in the target process.
* **`unload_policy`:** `FRIDA_UNLOAD_POLICY_IMMEDIATE`.

**Hypothetical Output (Simplified):**

1. **Target Process:**
   - A file descriptor for `/tmp/frida_pipe_1234` would be opened.
   - The byte representing the "hello byte" would be written to the pipe.
   - The shared library `/data/local/tmp/my_agent.so` would be loaded into the process's memory (if not already loaded).
   - The address of the function `my_hook_function` within `my_agent.so` would be resolved.
   - The `my_hook_function` would be called with the `entrypoint_data`, and the address of a variable representing `FRIDA_UNLOAD_POLICY_IMMEDIATE`, and the file descriptor.
   - After `my_hook_function` returns, `dlclose` would be called to unload `/data/local/tmp/my_agent.so`.
   - The value corresponding to `FRIDA_UNLOAD_POLICY_IMMEDIATE` would be written back to the pipe.
   - The thread ID of the currently executing thread would be written to the pipe.
   - The file descriptor for the pipe would be closed.

2. **Frida Agent:** Would receive the "hello byte", the `unload_policy` value, and the thread ID through the FIFO.

**User or Programming Common Usage Errors:**

* **Incorrect Paths:** Providing an incorrect `so_path` (library path) or `entrypoint_name` will cause `dlopen` or `dlsym` to fail, leading to the injection failing.
* **Missing Permissions:** If the Frida agent doesn't have the necessary permissions to access the target process's memory or create/open the FIFO, the injection will fail.
* **Library Dependencies:** If `my_agent.so` has dependencies that are not available in the target process's environment, `dlopen` will fail.
* **ABI Mismatch:** If the injected library (`my_agent.so`) is compiled for a different architecture than the target process, the injection will likely crash or behave unpredictably.
* **Incorrect Argument Types/Sizes:** If the `entrypoint_data` pointer or the types of the arguments passed to the injected function don't match what the function expects, it can lead to crashes or unexpected behavior.
* **Race Conditions:**  While this specific code tries to synchronize, in more complex scenarios, race conditions can occur if multiple injection attempts or interactions with the target process happen concurrently.

**User Operation Steps to Reach Here (Debugging Clues):**

1. **User Initiates Injection:** The user interacts with the Frida client (e.g., using Python bindings) to attach to a process and inject code. This might involve calling functions like `frida.attach()` and then using methods to load scripts or libraries.
2. **Frida Core Processing:** The Frida client communicates with the Frida server running on the target device. The server receives the injection request.
3. **`binjector-glue.c` Invocation:** The Frida server, specifically the `frida-core` component, will determine the target architecture and use the appropriate code injection mechanism. For FreeBSD, and depending on the injection strategy, the code in `binjector-glue.c` (or similar files for other platforms) will be involved in constructing the payload.
4. **Memory Allocation:** Frida will allocate memory in the target process to store the generated payload code and any necessary data.
5. **Payload Generation:** The functions in `binjector-glue.c`, like `frida_inject_instance_emit_payload_code`, will be called to generate the architecture-specific assembly instructions.
6. **Payload Writing:**  Frida will use `ptrace` (or similar mechanisms) to write the generated code into the allocated memory in the target process.
7. **Execution Transfer:** Frida will manipulate the target process's execution flow (registers, instruction pointer) to start executing the injected payload code.

**In Summary (Function of Part 2):**

This part of `frida/subprojects/frida-core/src/freebsd/binjector-glue.c` is responsible for the **dynamic generation of architecture-specific assembly code that forms the initial payload injected into a target process.** This payload handles setting up communication, loading libraries, calling user-specified functions within those libraries, and managing the lifecycle of the injected code. It is a crucial component enabling Frida's dynamic instrumentation capabilities for reverse engineering and security analysis.

### 提示词
```
这是目录为frida/subprojects/frida-core/src/freebsd/binjector-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
ter_flush (&cw);
  g_assert (gum_x86_writer_offset (&cw) <= worker_offset);
  while (gum_x86_writer_offset (&cw) != worker_offset - code->size)
    gum_x86_writer_put_nop (&cw);
  frida_inject_instance_commit_x86_code (&cw, code);
  gum_x86_writer_clear (&cw);

  gum_x86_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  EMIT_PUSH (XBP);
  EMIT_MOVE (XBP, XSP);
  EMIT_SUB (XSP, 32 + ((cw.target_cpu == GUM_CPU_IA32) ? 4 : 8));
  EMIT_PUSH (XBX);

  fd_offset = -4;
  unload_policy_offset = -8;
  tid_offset = -12;

  EMIT_CALL_IMM (api->open_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY | O_CLOEXEC));
  EMIT_STORE_REG (XBP, fd_offset, EAX);

  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (EAX),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_LOAD_FIELD (XAX, module_handle);
  EMIT_CMP (XAX, 0);
  EMIT_JNE (skip_dlopen);
  {
    EMIT_CALL_IMM (api->dlopen_impl,
        2,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY));
    EMIT_STORE_FIELD (module_handle, XAX);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));

  EMIT_STORE_IMM (XBP, unload_policy_offset, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_LEA (XCX, XBP, unload_policy_offset);
  EMIT_LEA (XDX, XBP, fd_offset);
  EMIT_CALL_REG (XAX,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (XCX),
      ARG_REG (XDX));

  EMIT_LOAD_REG (EAX, XBP, unload_policy_offset);
  EMIT_CMP (EAX, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_JNE (skip_dlclose);
  {
    EMIT_LOAD_FIELD (XAX, module_handle);
    EMIT_CALL_IMM (api->dlclose_impl,
        1,
        ARG_REG (XAX));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LOAD_REG (EAX, XBP, unload_policy_offset);
  EMIT_CMP (EAX, FRIDA_UNLOAD_POLICY_DEFERRED);
  EMIT_JE (skip_detach);
  {
    EMIT_LOAD_FIELD (XAX, pthread_so);
    EMIT_CALL_IMM (api->dlsym_impl,
        2,
        ARG_REG (XAX),
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_detach_string)));
    EMIT_LOAD_FIELD (XCX, worker_thread);
    EMIT_CALL_REG (XAX,
        1,
        ARG_REG (XCX));
  }
  EMIT_LABEL (skip_detach);

  EMIT_LOAD_FIELD (XAX, pthread_so);
  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_getthreadid_np_string)));
  gum_x86_writer_put_call_reg (&cw, GUM_X86_XAX);
  EMIT_STORE_REG (XBP, tid_offset, EAX);

  EMIT_LOAD_FIELD (XAX, pthread_so);
  EMIT_CALL_IMM (api->dlclose_impl,
      1,
      ARG_REG (XAX));

  fd_reg = (cw.target_cpu == GUM_CPU_IA32) ? GUM_X86_EDX : GUM_X86_EDI;

  EMIT_LOAD_REGV (fd_reg, XBP, fd_offset);
  EMIT_LEA (XCX, XBP, unload_policy_offset);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REGV (fd_reg),
      ARG_REG (XCX),
      ARG_IMM (1));

  EMIT_LOAD_REGV (fd_reg, XBP, fd_offset);
  EMIT_LEA (XCX, XBP, tid_offset);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REGV (fd_reg),
      ARG_REG (XCX),
      ARG_IMM (4));

  EMIT_LOAD_REG (ECX, XBP, fd_offset);
  EMIT_CALL_IMM (api->close_impl,
      1,
      ARG_REG (ECX));

  EMIT_POP (XBX);
  EMIT_MOVE (XSP, XBP);
  EMIT_POP (XBP);
  EMIT_RET ();

  frida_inject_instance_commit_x86_code (&cw, code);
  gum_x86_writer_clear (&cw);
}

#elif defined (HAVE_ARM64)

#define EMIT_MOVE(dst, src) \
    gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_##dst, ARM64_REG_##src)
#define EMIT_ADD(dst, src, offset) \
    gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_##dst, ARM64_REG_##src, offset)
#define EMIT_PUSH(a, b) \
    gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_POP(a, b) \
    gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaTrampolineData, field))
#define EMIT_STORE_FIELD(field, reg) \
    gum_arm64_writer_put_str_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaTrampolineData, field))
#define EMIT_LDR(dst, src, offset) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##dst, ARM64_REG_##src, offset)
#define EMIT_LDR_ADDRESS(reg, value) \
    gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_##reg, value)
#define EMIT_LDR_U64(reg, value) \
    gum_arm64_writer_put_ldr_reg_u64 (&cw, ARM64_REG_##reg, value)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_arm64_writer_put_call_address_with_arguments (&cw, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_arm64_writer_put_call_reg_with_arguments (&cw, ARM64_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_RET() \
    gum_arm64_writer_put_ret (&cw)
#define EMIT_LABEL(name) \
    gum_arm64_writer_put_label (&cw, name)
#define EMIT_CBNZ(reg, label) \
    gum_arm64_writer_put_cbnz_reg_label (&cw, ARM64_REG_##reg, label)
#define EMIT_CMP(a, b) \
    gum_arm64_writer_put_cmp_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_B_COND(cond, label) \
    gum_arm64_writer_put_b_cond_label (&cw, ARM64_CC_##cond, label)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, ARM64_REG_##reg

static void
frida_inject_instance_commit_arm64_code (GumArm64Writer * cw, FridaCodeChunk * code)
{
  gum_arm64_writer_flush (cw);
  code->cur = gum_arm64_writer_cur (cw);
  code->size += gum_arm64_writer_offset (cw);
}

static void
frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  const FridaRemoteApi * api = &params->api;
  GumArm64Writer cw;
  const guint worker_offset = 128;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";

  gum_arm64_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

  EMIT_LDR_ADDRESS (X20, remote_address + params->data.offset);

  EMIT_CALL_IMM (api->dlopen_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (RTLD_GLOBAL | RTLD_LAZY));
  EMIT_STORE_FIELD (pthread_so, X0);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (X0),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_create_string)));
  EMIT_MOVE (X5, X0);

  EMIT_CALL_REG (X5,
      4,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (worker_thread)),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset),
      ARG_IMM (remote_address + params->data.offset));

  gum_arm64_writer_put_brk_imm (&cw, 0);
  gum_arm64_writer_flush (&cw);
  g_assert (gum_arm64_writer_offset (&cw) <= worker_offset);
  while (gum_arm64_writer_offset (&cw) != worker_offset - code->size)
    gum_arm64_writer_put_nop (&cw);
  frida_inject_instance_commit_arm64_code (&cw, code);
  gum_arm64_writer_clear (&cw);

  gum_arm64_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  EMIT_PUSH (FP, LR);
  EMIT_MOVE (FP, SP);
  EMIT_PUSH (X23, X24);
  EMIT_PUSH (X21, X22);
  EMIT_PUSH (X19, X20);

  EMIT_MOVE (X20, X0);

  EMIT_CALL_IMM (api->open_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY | O_CLOEXEC));
  EMIT_MOVE (W21, W0);

  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (W21),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_LOAD_FIELD (X19, module_handle);
  EMIT_CBNZ (X19, skip_dlopen);
  {
    EMIT_CALL_IMM (api->dlopen_impl,
        2,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY));
    EMIT_MOVE (X19, X0);
    EMIT_STORE_FIELD (module_handle, X19);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (X19),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));
  EMIT_MOVE (X5, X0);

  EMIT_LDR_U64 (X0, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_PUSH (X0, X21);
  EMIT_MOVE (X1, SP);
  EMIT_ADD (X2, SP, 8);
  EMIT_CALL_REG (X5,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (X1),
      ARG_REG (X2));

  EMIT_LDR (W21, SP, 8);
  EMIT_LDR (W22, SP, 0);

  EMIT_LDR_U64 (X1, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_CMP (W22, W1);
  EMIT_B_COND (NE, skip_dlclose);
  {
    EMIT_CALL_IMM (api->dlclose_impl,
        1,
        ARG_REG (X19));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LDR_U64 (X1, FRIDA_UNLOAD_POLICY_DEFERRED);
  EMIT_CMP (W22, W1);
  EMIT_B_COND (EQ, skip_detach);
  {
    EMIT_LOAD_FIELD (X0, pthread_so);
    EMIT_CALL_IMM (api->dlsym_impl,
        2,
        ARG_REG (X0),
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_detach_string)));
    EMIT_MOVE (X5, X0);
    EMIT_LOAD_FIELD (X0, worker_thread);
    EMIT_CALL_REG (X5,
        1,
        ARG_REG (X0));
  }
  EMIT_LABEL (skip_detach);

  EMIT_LOAD_FIELD (X0, pthread_so);
  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (X0),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_getthreadid_np_string)));
  gum_arm64_writer_put_blr_reg (&cw, ARM64_REG_X0);
  EMIT_MOVE (W23, W0);

  EMIT_LOAD_FIELD (X0, pthread_so);
  EMIT_CALL_IMM (api->dlclose_impl,
      1,
      ARG_REG (X0));

  EMIT_MOVE (X1, SP);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (W21),
      ARG_REG (X1),
      ARG_IMM (1));

  EMIT_POP (X0, X1);

  EMIT_PUSH (X23, X24);
  EMIT_MOVE (X1, SP);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (W21),
      ARG_REG (X1),
      ARG_IMM (4));
  EMIT_POP (X23, X24);

  EMIT_CALL_IMM (api->close_impl,
      1,
      ARG_REG (W21));

  EMIT_POP (X19, X20);
  EMIT_POP (X21, X22);
  EMIT_POP (X23, X24);
  EMIT_POP (FP, LR);
  EMIT_RET ();

  frida_inject_instance_commit_arm64_code (&cw, code);
  gum_arm64_writer_clear (&cw);
}

#endif

static gboolean
frida_wait_for_attach_signal (pid_t pid)
{
  int status = 0;
  pid_t res;
  int stop_signal;

  res = waitpid (pid, &status, 0);
  if (res != pid || !WIFSTOPPED (status))
    return FALSE;
  stop_signal = WSTOPSIG (status);

  switch (stop_signal)
  {
    case SIGTRAP:
      if (ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0) != 0)
        return FALSE;
      if (!frida_wait_for_child_signal (pid, SIGSTOP, NULL))
        return FALSE;
      /* fall through */
    case SIGSTOP:
      return TRUE;
    default:
      break;
  }

  return FALSE;
}

static gboolean
frida_wait_for_child_signal (pid_t pid, int signal, gboolean * exited)
{
  gboolean success = FALSE;
  gboolean child_did_exit = TRUE;
  int status = 0;
  pid_t res;

  res = waitpid (pid, &status, 0);
  if (res != pid || WIFEXITED (status))
    goto beach;

  child_did_exit = FALSE;

  if (!WIFSTOPPED (status))
    goto beach;

  if (signal == SIGTRAP)
  {
    switch (WSTOPSIG (status))
    {
      case SIGTRAP:
      case SIGTTIN:
      case SIGTTOU:
        success = TRUE;
        break;
      default:
        success = FALSE;
        break;
    }
  }
  else
  {
    success = WSTOPSIG (status) == signal;
  }

beach:
  if (exited != NULL)
    *exited = child_did_exit;

  return success;
}

static gint
frida_get_regs (pid_t pid, FridaRegs * regs)
{
  return ptrace (PT_GETREGS, pid, (caddr_t) regs, 0);
}

static gint
frida_set_regs (pid_t pid, const FridaRegs * regs)
{
  return ptrace (PT_SETREGS, pid, (caddr_t) regs, 0);
}

static gboolean
frida_run_to_entrypoint (pid_t pid, GError ** error)
{
  GumAddress entrypoint;
#if defined (HAVE_I386)
  guint8 original_entry_insn;
  const guint8 patched_entry_insn = 0xcc;
#elif defined (HAVE_ARM64)
  guint32 original_entry_insn;
  const guint32 patched_entry_insn = 0xd4200000;
#else
# error Unsupported architecture
#endif
  int ret;
  const gchar * failed_operation;
  gboolean success;
  FridaRegs regs;

  entrypoint = _frida_find_entrypoint (pid, error);
  if (entrypoint == 0)
    goto propagate_error;

  if (!frida_remote_read (pid, entrypoint, &original_entry_insn, sizeof (original_entry_insn), error))
    goto propagate_error;

  if (!frida_remote_write (pid, entrypoint, &patched_entry_insn, sizeof (patched_entry_insn), error))
    goto propagate_error;

  ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");

  success = frida_wait_for_child_signal (pid, SIGTRAP, NULL);
  CHECK_OS_RESULT (success, !=, FALSE, "WAIT(SIGTRAP)");

  if (!frida_remote_write (pid, entrypoint, &original_entry_insn, sizeof (original_entry_insn), error))
    goto propagate_error;

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.r_rip = entrypoint;
#elif defined (HAVE_ARM64)
  regs.elr = entrypoint;
#else
# error Unsupported architecture
#endif

  ret = frida_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
os_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "%s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
}

static gboolean
frida_remote_api_try_init (FridaRemoteApi * api, pid_t pid)
{
  gboolean success = FALSE;
  FridaSymbolResolver * resolver;

  resolver = frida_symbol_resolver_new (pid);

#define FRIDA_TRY_RESOLVE(kind, name) \
    api->name##_impl = frida_symbol_resolver_find_##kind##_function (resolver, G_STRINGIFY (name)); \
    if (api->name##_impl == 0) \
      goto beach

  FRIDA_TRY_RESOLVE (ld, dlopen);
  FRIDA_TRY_RESOLVE (ld, dlclose);
  FRIDA_TRY_RESOLVE (ld, dlsym);

  FRIDA_TRY_RESOLVE (libc, mmap);
  FRIDA_TRY_RESOLVE (libc, munmap);
  FRIDA_TRY_RESOLVE (libc, mprotect);

  FRIDA_TRY_RESOLVE (libc, open);
  FRIDA_TRY_RESOLVE (libc, close);
  FRIDA_TRY_RESOLVE (libc, write);

#undef FRIDA_TRY_RESOLVE

  success = TRUE;
  goto beach;

beach:
  {
    g_object_unref (resolver);

    return success;
  }
}

static GumAddress
frida_remote_alloc (pid_t pid, size_t size, int prot, const FridaRemoteApi * api, GError ** error)
{
  GumAddress args[] = {
    0,
    size,
    prot,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
  };
  GumAddress retval;

  if (!frida_remote_call (pid, api->mmap_impl, args, G_N_ELEMENTS (args), &retval, NULL, error))
    return 0;

  if (retval == FRIDA_MAP_FAILED)
    goto mmap_failed;

  return retval;

mmap_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to allocate memory in the specified process");
    goto failure;
  }
failure:
  {
    return 0;
  }
}

static gboolean
frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, const FridaRemoteApi * api, GError ** error)
{
  GumAddress args[] = {
    address,
    size
  };
  GumAddress retval;

  if (!frida_remote_call (pid, api->munmap_impl, args, G_N_ELEMENTS (args), &retval, NULL, error))
    return FALSE;

  return retval == 0;
}

static gboolean
frida_remote_mprotect (pid_t pid, GumAddress address, size_t size, int prot, const FridaRemoteApi * api, GError ** error)
{
  GumAddress args[] = {
    address,
    size,
    prot
  };
  GumAddress retval;

  if (!frida_remote_call (pid, api->mprotect_impl, args, G_N_ELEMENTS (args), &retval, NULL, error))
    return FALSE;

  return retval == 0;
}

static gboolean
frida_remote_read (pid_t pid, GumAddress remote_address, gpointer data, gsize size, GError ** error)
{
  struct ptrace_io_desc d;

  d.piod_op = PIOD_READ_D;
  d.piod_offs = GSIZE_TO_POINTER (remote_address);
  d.piod_addr = data;
  d.piod_len = size;

  if (ptrace (PT_IO, pid, (caddr_t) &d, 0) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "remote_read failed: %s",
        strerror (errno));
    return FALSE;
  }
}

static gboolean
frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  struct ptrace_io_desc d;

  d.piod_op = PIOD_WRITE_D;
  d.piod_offs = GSIZE_TO_POINTER (remote_address);
  d.piod_addr = (void *) data;
  d.piod_len = size;

  if (ptrace (PT_IO, pid, (caddr_t) &d, 0) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "remote_write failed: %s",
        strerror (errno));
    return FALSE;
  }
}

static gboolean
frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, gboolean * exited,
    GError ** error)
{
  int ret;
  const gchar * failed_operation;
  FridaRegs regs;
  gint i;
  gboolean success;

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.r_rsp -= FRIDA_RED_ZONE_SIZE;
  regs.r_rsp -= (regs.r_rsp - (MAX (args_length - 6, 0) * 8)) % FRIDA_STACK_ALIGNMENT;

  regs.r_rip = func;

  for (i = 0; i != args_length && i < 6; i++)
  {
    switch (i)
    {
      case 0:
        regs.r_rdi = args[i];
        break;
      case 1:
        regs.r_rsi = args[i];
        break;
      case 2:
        regs.r_rdx = args[i];
        break;
      case 3:
        regs.r_rcx = args[i];
        break;
      case 4:
        regs.r_r8 = args[i];
        break;
      case 5:
        regs.r_r9 = args[i];
        break;
      default:
        g_assert_not_reached ();
    }
  }

  {
    gint num_stack_args = args_length - 6;
    if (num_stack_args > 0)
    {
      guintptr * stack_args;

      stack_args = g_newa (guintptr, num_stack_args);
      for (i = 0; i != num_stack_args; i++)
        stack_args[i] = args[6 + i];

      regs.r_rsp -= num_stack_args * sizeof (guintptr);
      if (!frida_remote_write (pid, regs.r_rsp, stack_args, num_stack_args * sizeof (guintptr), error))
        goto propagate_error;
    }
  }

  {
    guintptr dummy_return_address = FRIDA_DUMMY_RETURN_ADDRESS;

    regs.r_rsp -= 8;
    if (!frida_remote_write (pid, regs.r_rsp, &dummy_return_address, sizeof (dummy_return_address), error))
      goto propagate_error;
  }
#elif defined (HAVE_ARM64)
  regs.sp -= regs.sp % FRIDA_STACK_ALIGNMENT;

  regs.elr = func;

  g_assert (args_length <= 8);
  for (i = 0; i != args_length; i++)
    regs.x[i] = args[i];

  regs.lr = FRIDA_DUMMY_RETURN_ADDRESS;
#else
# error Unsupported architecture
#endif

  ret = frida_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");

  success = frida_wait_for_child_signal (pid, SIGSEGV, exited);
  CHECK_OS_RESULT (success, !=, FALSE, "PT_CONTINUE wait");

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  *retval = regs.r_rax;
#elif defined (HAVE_ARM64)
  *retval = regs.x[0];
#else
# error Unsupported architecture
#endif

  return TRUE;

os_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "remote_call %s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
propagate_error:
  {
    return FALSE;
  }
#endif
}

static gboolean
frida_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, gboolean * exited, GError ** error)
{
  int ret;
  const gchar * failed_operation;
  FridaRegs regs;
  gboolean success;

  ret = frida_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.r_rip = remote_address;
  regs.r_rsp = remote_stack;
#elif defined (HAVE_ARM64)
  regs.elr = remote_address;
  regs.sp = remote_stack;
#else
# error Unsupported architecture
#endif

  ret = frida_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");

  success = frida_wait_for_child_signal (pid, SIGTRAP, exited);
  CHECK_OS_RESULT (success, !=, FALSE, "PT_CONTINUE wait");

  if (result != NULL)
  {
    ret = frida_get_regs (pid, &regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    *result = regs.r_rax;
#elif defined (HAVE_ARM64)
    *result = regs.x[0];
#else
# error Unsupported architecture
#endif
  }

  return TRUE;

os_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "remote_exec %s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
}
```