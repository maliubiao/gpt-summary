Response:
Let's break down the thought process for analyzing this `loader.c` file.

**1. Understanding the Goal:** The request asks for a functional breakdown of the code, its relation to reverse engineering, low-level concepts, logical reasoning, potential errors, and the user path to this code. Essentially, it's a comprehensive analysis of a specific component within Frida.

**2. Initial Scan & High-Level Purpose:**  First, I'd quickly read through the entire code, looking for keywords and structural elements. Things that immediately jump out are:

* `#include` directives: `inject-context.h`, `syscall.h`, `elf.h`, `fcntl.h`, `link.h`, `unistd.h`, `sys/un.h`. These suggest interactions with the operating system, especially around process injection and inter-process communication.
* Function names like `frida_load`, `frida_main`, `frida_connect`, `frida_send_*`, `frida_receive_*`. This indicates the core functionality revolves around loading something and communicating.
* Data structures like `FridaLoaderContext`, `FridaLinuxInjectorState`, `FridaControlMessage`. These hint at the data being exchanged and the overall architecture.
* Use of `dlopen`, `dlsym`, `dlclose`. These strongly point towards dynamic library loading, a key technique in instrumentation.
* Socket operations (`socket`, `connect`, `recvmsg`, `send`). Inter-process communication is a major component.

From this initial scan, I'd form a preliminary hypothesis: This code is responsible for injecting a Frida agent into a target process and establishing communication with the main Frida process.

**3. Function-by-Function Analysis:** Next, I'd go through each function, understanding its specific role:

* **`frida_load`:** The entry point, creating a new thread to run `frida_main`. This confirms it's involved in the initial loading/injection phase.
* **`frida_main`:** The core logic. It handles:
    * Connecting to the Frida server (via a provided control file descriptor or fallback address).
    * Receiving the Frida agent code (as a file descriptor).
    * Dynamically loading the agent (`dlopen`).
    * Resolving the agent's entry point (`dlsym`).
    * Receiving another file descriptor for agent control.
    * Calling the agent's entry point.
    * Handling potential errors during loading.
    * Unloading the agent based on policy.
    * Cleaning up resources.
* **`frida_connect`:** Establishes a connection to a Unix domain socket. This is the mechanism for communication.
* **`frida_send_hello`:** Sends an initial handshake message.
* **`frida_send_ready`:** Signals that the agent is loaded and ready.
* **`frida_receive_ack`:** Waits for acknowledgment from the server.
* **`frida_send_bye`:** Sends a message indicating the agent is unloading.
* **`frida_send_error`:** Sends error messages back to the server.
* **`frida_receive_chunk` and `frida_send_chunk`:**  Low-level functions for reliable data transfer over the socket. They handle potential partial reads/writes.
* **`frida_receive_fd`:** Receives a file descriptor over the socket using `recvmsg` and control messages. This is a crucial part of transferring the agent's code.
* **`frida_enable_close_on_exec`:** Ensures that file descriptors are closed in child processes after an `execve` call. Important for security and resource management.
* **`frida_strlen`:** A custom string length function (potentially for avoiding external dependencies or specific library versions, though the inline assembly is interesting).
* **`frida_gettid`:** Gets the current thread ID.

**4. Connecting to the Request's Specific Points:**

* **Functionality:**  List the purpose of each key function as identified above.
* **Reverse Engineering:**  Identify the core reverse engineering relevance: dynamic instrumentation, code injection, hooking, dynamic analysis. Give concrete examples like intercepting function calls.
* **Binary/Low-Level:** Point out the use of ELF, file descriptors, sockets, system calls (`recvmsg`, `send`, `connect`, `dlopen`, etc.), memory management (through `alloca`), and the `link.h` header. Explain the significance of these.
* **Linux/Android Kernel/Framework:** Mention the reliance on Linux system calls, the `/proc` filesystem, and the concept of shared libraries in the Android framework (though the code is primarily Linux-focused).
* **Logical Reasoning:** Focus on the control flow within `frida_main`: connection attempts, agent loading, communication handshakes, error handling, and the different unload policies. Create simple input/output scenarios, even if hypothetical, to illustrate the logic. For instance: *Input:* Valid control FD. *Output:* Successful agent load. *Input:* Invalid control FD, valid fallback address. *Output:* Successful agent load via fallback. *Input:* Both invalid. *Output:* Agent load failure.
* **User/Programming Errors:**  Think about what could go wrong from a user's perspective or during development. Examples: incorrect socket address, missing agent library, wrong entry point name, permission issues.
* **User Path:** Trace back the steps that would lead to this code being executed. Start with the user initiating Frida (e.g., `frida`, `frida-trace`), then the injection process, and finally the execution of this loader code within the target process.

**5. Refinement and Organization:**  Organize the findings into clear sections as requested by the prompt. Use bullet points and concise language for readability. Ensure that the explanations for low-level concepts and their relevance are accurate and easy to understand.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Maybe `frida_strlen` is just an optimization."  **Correction:** While it might have performance implications, consider that it could also be for avoiding dependencies on `libc` within the injected context, ensuring a minimal footprint.
* **Initial thought:** "Just list the system calls." **Correction:** Explain *why* those system calls are used and their significance in the context of Frida's operation.
* **Initial thought:** Focus solely on the happy path. **Correction:** Dedicate specific sections to error handling and potential issues.

By following this systematic approach, moving from a high-level overview to detailed analysis, and continually connecting the code back to the prompt's requirements, it's possible to generate a comprehensive and accurate explanation of the `loader.c` file's functionality.
This is the source code for `loader.c`, a crucial component of the Frida dynamic instrumentation toolkit. Its primary function is to inject the Frida agent (the code that performs the actual instrumentation) into a target process on Linux. Let's break down its functionalities and their implications:

**Core Functionality:**

1. **Agent Injection and Initialization:**
   - The `frida_load` function is the entry point. It's designed to be executed within the target process after Frida has injected this loader code.
   - It creates a new thread (`frida_main`) to handle the subsequent initialization and communication.

2. **Establishing Communication with the Frida Server:**
   - **Connection via Control File Descriptor:** The loader attempts to use a pre-existing file descriptor (`ctx->ctrlfds[1]`) passed to it by the injector process. This is the preferred and more efficient method.
   - **Fallback Connection via Unix Socket:** If the control file descriptor is invalid or communication fails, it falls back to connecting to the Frida server using a Unix domain socket specified by `ctx->fallback_address`. This provides a backup communication channel.
   - The `frida_connect` function handles the creation and connection to the Unix socket.

3. **Agent Code Transfer and Loading:**
   - **Receiving Agent Code as a File Descriptor:**  The loader receives the actual Frida agent library's code as a file descriptor (`agent_codefd`) over the established communication channel using `frida_receive_fd`. This is a highly efficient way to transfer the binary data.
   - **Dynamic Loading of the Agent:** The loader uses `dlopen` to dynamically load the received agent code into the target process's memory. It constructs a path like `/proc/self/fd/<agent_codefd>` to access the file descriptor as a shared library.
   - **Resolving Agent Entry Point:**  After loading, it uses `dlsym` to find the entry point function (`ctx->agent_entrypoint`) within the loaded agent library.

4. **Agent Execution and Control:**
   - **Receiving Agent Control File Descriptor:**  Another file descriptor (`agent_ctrlfd`) is received for direct communication between the loader and the agent. This can be used for more specific control or data exchange.
   - **Executing the Agent:** The loader calls the agent's entry point function (`ctx->agent_entrypoint_impl`), passing relevant data (`ctx->agent_data`), an unload policy, and the communication file descriptors.

5. **Communication Protocol:**
   - The code defines a simple messaging protocol for communication with the Frida server. This involves sending and receiving messages with specific types (e.g., `FRIDA_MESSAGE_HELLO`, `FRIDA_MESSAGE_READY`, `FRIDA_MESSAGE_ACK`, `FRIDA_MESSAGE_BYE`, `FRIDA_MESSAGE_ERROR`).
   - Functions like `frida_send_hello`, `frida_send_ready`, `frida_receive_ack`, `frida_send_bye`, and `frida_send_error` handle the sending of these messages.
   - `frida_send_chunk` and `frida_receive_chunk` are lower-level functions for sending and receiving raw data chunks over the socket.

6. **Agent Unloading:**
   - The loader respects an unload policy (`unload_policy`) determined by the Frida server.
   - `FRIDA_UNLOAD_POLICY_IMMEDIATE`: Unloads the agent immediately using `dlclose`.
   - `FRIDA_UNLOAD_POLICY_RESIDENT`: Keeps the agent loaded.
   - `FRIDA_UNLOAD_POLICY_DEFERRED`: Defers unloading.
   - The `frida_send_bye` message informs the server about the unload policy being followed.

7. **Error Handling:**
   - The code includes basic error handling, particularly during the agent loading process (`dlopen` and `dlsym`). If loading fails, it sends an error message back to the Frida server.

**Relation to Reverse Engineering:**

This code is *fundamental* to Frida's reverse engineering capabilities. Here's how:

* **Dynamic Instrumentation:** The entire purpose of this code is to enable *dynamic* instrumentation. It injects code into a running process without modifying the original executable on disk. This allows reverse engineers to observe and manipulate the behavior of the target process in real-time.
* **Code Injection:** The process of loading the agent library using `dlopen` is a classic example of code injection. Frida uses this technique to introduce its own code into the address space of the target process.
* **Hooking:** While this specific code doesn't implement the hooking logic directly, it sets the stage for it. The injected agent library (loaded by this code) is where the actual hooking (intercepting function calls, modifying data, etc.) takes place.
* **Dynamic Analysis:** By successfully loading the agent, this code enables a wide range of dynamic analysis techniques, such as:
    - **Function Tracing:** Observing which functions are called and their arguments.
    - **Memory Inspection:** Examining the contents of memory.
    - **Behavioral Analysis:** Understanding how the target process interacts with the system.

**Example:**

Imagine you want to intercept the `open` system call in a target process.

1. **User Action:** You use the Frida client (e.g., Python script) to attach to the target process and specify a script that hooks the `open` function.
2. **Injection:** Frida injects this `loader.c` code into the target process.
3. **Connection:** `frida_main` establishes communication with the Frida server.
4. **Agent Transfer:** The Frida server sends the Frida agent library (which contains the hooking logic) as a file descriptor.
5. **Loading:** This `loader.c` code uses `dlopen` to load the agent.
6. **Agent Execution:** The `loader.c` code calls the agent's entry point.
7. **Hooking (within the Agent):** The agent's code, now running in the target process, uses Frida's APIs to intercept the `open` system call.
8. **Instrumentation:** When the target process calls `open`, the hook in the agent is triggered, allowing you to observe the filename being opened, modify it, or prevent the call altogether.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

* **Binary Bottom (ELF):** The code deals directly with binary concepts through the use of `elf.h` (though not extensively in this particular file). The process of loading a shared library (`dlopen`) relies heavily on the ELF (Executable and Linkable Format) structure of the agent library. Understanding how shared libraries are laid out in memory is crucial.
* **Linux System Calls:**  The code uses various Linux system calls directly or indirectly through the provided `FridaLibcApi`:
    - `pthread_create`: Creates a new thread.
    - `close`: Closes file descriptors.
    - `socket`: Creates a socket for communication.
    - `connect`: Connects to a socket address.
    - `recvmsg`, `send`:  Send and receive data over sockets, including the capability to send file descriptors.
    - `dlopen`, `dlsym`, `dlclose`: Functions for dynamic linking and loading of shared libraries.
    - `fcntl`: Manipulates file descriptor flags (e.g., setting `FD_CLOEXEC`).
    - `gettid`: Gets the thread ID.
* **Linux Inter-Process Communication (IPC):**  The code heavily relies on Unix domain sockets for communication between the injected loader and the Frida server. The passing of file descriptors over the socket is a key Linux IPC mechanism used for efficient agent transfer.
* **`/proc` Filesystem:** The code uses `/proc/self/fd/<fd>` to obtain a path to the agent library's code, which is accessed through a file descriptor. The `/proc` filesystem provides a view into the kernel's data structures and process information.
* **Android Framework (Indirect):** While this code is primarily focused on the Linux kernel, the concepts are highly relevant to Android. Android's runtime environment relies on similar dynamic linking mechanisms. Frida on Android uses similar techniques for injecting agents into Dalvik/ART processes.

**Logical Reasoning (Hypothetical Input & Output):**

**Scenario 1: Successful Injection**

* **Input:**
    - `ctx->ctrlfds[1]` contains a valid file descriptor connected to the Frida server.
    - The Frida server sends a valid file descriptor for the agent library.
    - `ctx->agent_entrypoint` is a valid symbol name in the agent library.
* **Output:**
    - The agent library is successfully loaded into the target process.
    - The agent's entry point function is called.
    - Communication is established between the agent and the Frida server.

**Scenario 2: Fallback Connection**

* **Input:**
    - `ctx->ctrlfds[1]` is invalid (-1).
    - `ctx->fallback_address` contains a valid path to a Unix domain socket.
    - The Frida server is listening on that socket.
* **Output:**
    - The loader successfully connects to the Frida server using the fallback address.
    - Agent loading and execution proceed as in Scenario 1.

**Scenario 3: `dlopen` Failure**

* **Input:**
    - The file descriptor received for the agent library is invalid or corrupted.
    - The agent library is not a valid ELF shared object.
* **Output:**
    - `libc->dlopen` returns NULL.
    - The `dlopen_failed` block is executed.
    - An error message of type `FRIDA_MESSAGE_ERROR_DLOPEN` is sent to the Frida server.
    - The agent is not loaded.

**Scenario 4: `dlsym` Failure**

* **Input:**
    - The agent library is loaded successfully.
    - `ctx->agent_entrypoint` does not exist as a symbol in the agent library.
* **Output:**
    - `libc->dlsym` returns NULL.
    - The `dlsym_failed` block is executed.
    - An error message of type `FRIDA_MESSAGE_ERROR_DLSYM` is sent to the Frida server.
    - The agent's entry point is not called.

**User or Programming Common Usage Errors:**

1. **Incorrect Frida Server Address:** If the `ctx->fallback_address` is misconfigured or the Frida server isn't running at that address, the connection will fail. The error might not be immediately obvious to the user within the target process.

2. **Agent Library Issues:**
   - **Corrupted Agent Library:** If the agent library data sent over the socket is corrupted, `dlopen` will likely fail.
   - **Missing Dependencies:** If the agent library depends on other libraries that are not present or accessible in the target process, loading might fail.
   - **Incorrect Entry Point Name:** If the `ctx->agent_entrypoint` string is incorrect, `dlsym` will fail, preventing the agent from starting.

3. **Permission Issues:** The target process might not have the necessary permissions to create sockets or access the `/proc` filesystem.

4. **File Descriptor Management:** If the file descriptors passed through `ctx->ctrlfds` are not correctly managed by the injector process (e.g., closed prematurely), the loader will be unable to communicate with the server.

**How User Operations Reach Here (Debugging Clues):**

The user's interaction starts with using the Frida client (command-line tools or language bindings). Here's a step-by-step breakdown:

1. **User Initiates Frida:** The user executes a Frida command, for example:
   - `frida <process_name>` (to attach to a running process)
   - `frida -f <executable>` (to spawn a new process and attach)
   - Using Frida's Python bindings to attach to a process.

2. **Frida Client Communication:** The Frida client communicates with the Frida server (a background process).

3. **Injection Request:** The Frida client, based on the user's request, instructs the Frida server to inject the agent into the target process.

4. **Injector Process (frida-inject):** The Frida server often uses a separate injector process (like `frida-inject`) to perform the actual injection. This injector process uses platform-specific techniques (e.g., `ptrace` on Linux) to gain control of the target process.

5. **Memory Allocation and Code Writing:** The injector process allocates memory in the target process and writes the `loader.c` code (compiled into machine code) into that memory.

6. **Setting up Execution Context:** The injector process sets up the execution context in the target process to start executing the injected `frida_load` function. This involves manipulating registers and the instruction pointer.

7. **Execution of `frida_load`:** The `frida_load` function starts executing in the target process within a newly created thread.

8. **Subsequent Steps:** The code in `loader.c` then proceeds with connecting to the server, receiving the agent, and executing it, as described in the "Core Functionality" section.

**Debugging Clues:**

* **Error Messages from Frida Client:** The Frida client often provides error messages that can indicate problems during injection or agent loading. These messages might point to connection issues, agent library problems, or entry point errors.
* **System Logs (dmesg):**  For lower-level issues (e.g., problems with system calls or socket creation), examining the system logs (`dmesg`) might provide valuable information.
* **Debugging the Injector Process:** If the injection itself is failing, debugging the `frida-inject` process (or the equivalent on other platforms) would be necessary.
* **Attaching a Debugger to the Target Process:** In more complex scenarios, attaching a debugger (like GDB) to the target process after injection can help to step through the `loader.c` code and identify the exact point of failure.

In summary, `loader.c` is a critical piece of the Frida puzzle, responsible for the initial and essential step of getting the Frida agent running inside the target process. Its functionality directly underpins Frida's dynamic instrumentation capabilities, making it a key component for reverse engineering and dynamic analysis.

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/linux/helpers/loader.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "inject-context.h"
#include "syscall.h"

#include <alloca.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/un.h>

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif

typedef int FridaUnloadPolicy;
typedef struct _FridaLinuxInjectorState FridaLinuxInjectorState;
typedef union _FridaControlMessage FridaControlMessage;

enum _FridaUnloadPolicy
{
  FRIDA_UNLOAD_POLICY_IMMEDIATE,
  FRIDA_UNLOAD_POLICY_RESIDENT,
  FRIDA_UNLOAD_POLICY_DEFERRED,
};

struct _FridaLinuxInjectorState
{
  int frida_ctrlfd;
  int agent_ctrlfd;
};

union _FridaControlMessage
{
  struct cmsghdr header;
  uint8_t storage[CMSG_SPACE (sizeof (int))];
};

static void * frida_main (void * user_data);

static int frida_connect (const char * address, const FridaLibcApi * libc);
static bool frida_send_hello (int sockfd, pid_t thread_id, const FridaLibcApi * libc);
static bool frida_send_ready (int sockfd, const FridaLibcApi * libc);
static bool frida_receive_ack (int sockfd, const FridaLibcApi * libc);
static bool frida_send_bye (int sockfd, FridaUnloadPolicy unload_policy, const FridaLibcApi * libc);
static bool frida_send_error (int sockfd, FridaMessageType type, const char * message, const FridaLibcApi * libc);

static bool frida_receive_chunk (int sockfd, void * buffer, size_t length, const FridaLibcApi * api);
static int frida_receive_fd (int sockfd, const FridaLibcApi * libc);
static bool frida_send_chunk (int sockfd, const void * buffer, size_t length, const FridaLibcApi * libc);
static void frida_enable_close_on_exec (int fd, const FridaLibcApi * libc);

static size_t frida_strlen (const char * str);

static pid_t frida_gettid (void);

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
void
frida_load (FridaLoaderContext * ctx)
{
  ctx->libc->pthread_create (&ctx->worker, NULL, frida_main, ctx);
}

static void *
frida_main (void * user_data)
{
  FridaLoaderContext * ctx = user_data;
  const FridaLibcApi * libc = ctx->libc;
  pid_t thread_id;
  FridaUnloadPolicy unload_policy;
  int ctrlfd_for_peer, ctrlfd, agent_codefd, agent_ctrlfd;
  FridaLinuxInjectorState injector_state;

  thread_id = frida_gettid ();
  unload_policy = FRIDA_UNLOAD_POLICY_IMMEDIATE;
  ctrlfd = -1;
  agent_codefd = -1;
  agent_ctrlfd = -1;

  ctrlfd_for_peer = ctx->ctrlfds[0];
  if (ctrlfd_for_peer != -1)
    libc->close (ctrlfd_for_peer);

  ctrlfd = ctx->ctrlfds[1];
  if (ctrlfd != -1)
  {
    if (!frida_send_hello (ctrlfd, thread_id, libc))
    {
      libc->close (ctrlfd);
      ctrlfd = -1;
    }
  }
  if (ctrlfd == -1)
  {
    ctrlfd = frida_connect (ctx->fallback_address, libc);
    if (ctrlfd == -1)
      goto beach;

    if (!frida_send_hello (ctrlfd, thread_id, libc))
      goto beach;
  }

  if (ctx->agent_handle == NULL)
  {
    char agent_path[32];
    const void * pretend_caller_addr = libc->close;

    agent_codefd = frida_receive_fd (ctrlfd, libc);
    if (agent_codefd == -1)
      goto beach;

    libc->sprintf (agent_path, "/proc/self/fd/%d", agent_codefd);

    ctx->agent_handle = libc->dlopen (agent_path, libc->dlopen_flags, pretend_caller_addr);
    if (ctx->agent_handle == NULL)
      goto dlopen_failed;

    if (agent_codefd != -1)
    {
      libc->close (agent_codefd);
      agent_codefd = -1;
    }

    ctx->agent_entrypoint_impl = libc->dlsym (ctx->agent_handle, ctx->agent_entrypoint, pretend_caller_addr);
    if (ctx->agent_entrypoint_impl == NULL)
      goto dlsym_failed;
  }

  agent_ctrlfd = frida_receive_fd (ctrlfd, libc);
  if (agent_ctrlfd != -1)
    frida_enable_close_on_exec (agent_ctrlfd, libc);

  if (!frida_send_ready (ctrlfd, libc))
    goto beach;
  if (!frida_receive_ack (ctrlfd, libc))
    goto beach;

  injector_state.frida_ctrlfd = ctrlfd;
  injector_state.agent_ctrlfd = agent_ctrlfd;

  ctx->agent_entrypoint_impl (ctx->agent_data, &unload_policy, &injector_state);

  ctrlfd = injector_state.frida_ctrlfd;
  agent_ctrlfd = injector_state.agent_ctrlfd;

  goto beach;

dlopen_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLOPEN,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to load library",
        libc);
    goto beach;
  }
dlsym_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLSYM,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to find entrypoint",
        libc);
    goto beach;
  }
beach:
  {
    if (unload_policy == FRIDA_UNLOAD_POLICY_IMMEDIATE && ctx->agent_handle != NULL)
      libc->dlclose (ctx->agent_handle);

    if (unload_policy != FRIDA_UNLOAD_POLICY_DEFERRED)
      libc->pthread_detach (ctx->worker);

    if (agent_ctrlfd != -1)
      libc->close (agent_ctrlfd);

    if (agent_codefd != -1)
      libc->close (agent_codefd);

    if (ctrlfd != -1)
    {
      frida_send_bye (ctrlfd, unload_policy, libc);
      libc->close (ctrlfd);
    }

    return NULL;
  }
}

/* TODO: Handle EINTR. */

static int
frida_connect (const char * address, const FridaLibcApi * libc)
{
  bool success = false;
  int sockfd;
  struct sockaddr_un addr;
  size_t len;
  const char * c;
  char ch;

  sockfd = libc->socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1)
    goto beach;

  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  for (c = address, len = 0; (ch = *c) != '\0'; c++, len++)
    addr.sun_path[1 + len] = ch;

  if (libc->connect (sockfd, (struct sockaddr *) &addr, offsetof (struct sockaddr_un, sun_path) + 1 + len) == -1)
    goto beach;

  success = true;

beach:
  if (!success && sockfd != -1)
  {
    libc->close (sockfd);
    sockfd = -1;
  }

  return sockfd;
}

static bool
frida_send_hello (int sockfd, pid_t thread_id, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_HELLO;
  FridaHelloMessage hello = {
    .thread_id = thread_id,
  };

  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return frida_send_chunk (sockfd, &hello, sizeof (hello), libc);
}

static bool
frida_send_ready (int sockfd, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_READY;

  return frida_send_chunk (sockfd, &type, sizeof (type), libc);
}

static bool
frida_receive_ack (int sockfd, const FridaLibcApi * libc)
{
  FridaMessageType type;

  if (!frida_receive_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return type == FRIDA_MESSAGE_ACK;
}

static bool
frida_send_bye (int sockfd, FridaUnloadPolicy unload_policy, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_BYE;
  FridaByeMessage bye = {
    .unload_policy = unload_policy,
  };

  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return frida_send_chunk (sockfd, &bye, sizeof (bye), libc);
}

static bool
frida_send_error (int sockfd, FridaMessageType type, const char * message, const FridaLibcApi * libc)
{
  uint16_t length;

  length = frida_strlen (message);

  #define FRIDA_SEND_VALUE(v) \
      if (!frida_send_chunk (sockfd, &(v), sizeof (v), libc)) \
        return false
  #define FRIDA_SEND_BYTES(data, size) \
      if (!frida_send_chunk (sockfd, data, size, libc)) \
        return false

  FRIDA_SEND_VALUE (type);
  FRIDA_SEND_VALUE (length);
  FRIDA_SEND_BYTES (message, length);

  return true;
}

static bool
frida_receive_chunk (int sockfd, void * buffer, size_t length, const FridaLibcApi * libc)
{
  void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    struct iovec io = {
      .iov_base = cursor,
      .iov_len = remaining
    };
    struct msghdr msg = {
      .msg_name = NULL,
      .msg_namelen = 0,
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = NULL,
      .msg_controllen = 0,
    };
    ssize_t n;

    n = libc->recvmsg (sockfd, &msg, 0);
    if (n <= 0)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static int
frida_receive_fd (int sockfd, const FridaLibcApi * libc)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  FridaControlMessage control;
  struct msghdr msg = {
    .msg_name = NULL,
    .msg_namelen = 0,
    .msg_iov = &io,
    .msg_iovlen = 1,
    .msg_control = &control,
    .msg_controllen = sizeof (control),
  };

  res = libc->recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0 || msg.msg_controllen == 0)
    return -1;

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static bool
frida_send_chunk (int sockfd, const void * buffer, size_t length, const FridaLibcApi * libc)
{
  const void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    ssize_t n;

    n = libc->send (sockfd, cursor, remaining, MSG_NOSIGNAL);
    if (n == -1)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static void
frida_enable_close_on_exec (int fd, const FridaLibcApi * libc)
{
  libc->fcntl (fd, F_SETFD, libc->fcntl (fd, F_GETFD) | FD_CLOEXEC);
}

static size_t
frida_strlen (const char * str)
{
  size_t n = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    asm ("");
    n++;
  }

  return n;
}

static pid_t
frida_gettid (void)
{
  return frida_syscall_0 (SYS_gettid);
}

"""

```