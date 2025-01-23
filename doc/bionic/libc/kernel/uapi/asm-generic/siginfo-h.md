Response:
Let's break down the thought process for answering the user's request about `siginfo.h`.

**1. Understanding the Core Request:**

The user provided a C header file (`siginfo.h`) and wants to know its functionality, its relationship to Android, implementation details (especially for libc and the dynamic linker), common usage errors, and how to trace its usage via Frida. The key is to systematically address each of these points.

**2. Initial Analysis of `siginfo.h`:**

* **Purpose:** The file defines structures and constants related to signal information. Signals are a fundamental mechanism in POSIX systems for inter-process communication and handling exceptional events. The `siginfo_t` structure carries detailed information about a signal.
* **Key Components:** The header defines:
    * `sigval_t`:  A union to pass either an integer or a pointer along with a signal.
    * `__sifields`: A union containing different structures depending on the signal's origin (kill, timer, real-time signal, child process status change, fault, poll, syscall).
    * `__SIGINFO`:  A structure containing the signal number (`si_signo`), error number (`si_errno`), signal code (`si_code`), and the `__sifields` union.
    * `siginfo_t`:  The main structure, essentially a wrapper around `__SIGINFO` with potential padding.
    * Macros:  Many macros are defined to access specific fields within `siginfo_t` and to represent different signal codes and sources.
    * `sigevent_t`: A structure related to asynchronous signal notification.

**3. Addressing Each Point Systematically:**

* **Functionality:**  The core functionality is describing signal information. List the key data carried by `siginfo_t` and how it helps understand the reason for a signal.
* **Relationship to Android:** Since this is part of Bionic (Android's C library), it's inherently tied to Android. Provide concrete examples of how signals and `siginfo_t` are used in Android: process termination (SIGCHLD), memory access violations (SIGSEGV), timers (SIGALRM, SIGVTALRM, SIGPROF).
* **libc Function Implementation:**  `siginfo.h` itself doesn't *implement* libc functions. It *defines the data structures* used by libc functions related to signals. Focus on functions that *use* `siginfo_t`: `sigaction`, `sigqueue`, signal handlers. For each function, explain its purpose and how `siginfo_t` is involved in providing detailed information.
* **Dynamic Linker:**  While `siginfo.h` isn't directly a *dynamic linker* component, signals can arise from the dynamic linker. Explain scenarios like unresolved symbols causing a SIGSEGV. Provide a simplified `so` layout and the general linking process, highlighting where errors might lead to signals.
* **Logic Reasoning (Hypothetical Input/Output):**  Construct a simple scenario, like sending a SIGUSR1 signal to a process using `kill()`. Describe the relevant fields in `siginfo_t` and their potential values. This helps illustrate how the data structure is populated.
* **Common Usage Errors:** Focus on common pitfalls when dealing with signals and `siginfo_t`. Examples include forgetting to check `si_code`, assuming `si_pid` is always valid, and incorrect signal handler setup.
* **Android Framework/NDK Path:** Trace how a signal might originate from an app and propagate down to the kernel and then back up to the application's signal handler, involving the framework and NDK along the way.
* **Frida Hook Example:**  Provide a practical Frida snippet to intercept a signal handler and log the contents of the `siginfo_t` structure. This demonstrates how to inspect the data in a real-world scenario.

**4. Detailing the Explanations:**

For each point, provide sufficient detail without getting bogged down in unnecessary technical jargon. Use clear and concise language. When explaining libc functions, focus on their role in signal handling. For the dynamic linker, keep the explanation at a high level of how it loads libraries and resolves symbols.

**5. Structuring the Response:**

Organize the response logically, following the user's request. Use headings and subheadings to make it easy to read and understand.

**6. Language and Tone:**

Use Chinese as requested by the user. Maintain a helpful and informative tone.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps focus on the low-level kernel details of signal delivery.
* **Correction:**  The user is asking about the *header file* within Bionic. Shift focus to the data structures and how they are used by higher-level functions in libc and the interactions with the dynamic linker and Android framework.
* **Initial thought:** Provide a very complex dynamic linker layout.
* **Correction:**  Simplify the `so` layout for clarity, focusing on the key elements relevant to potential linking errors that could cause signals.
* **Initial thought:**  Only provide theoretical explanations.
* **Correction:** Include a practical Frida example to make the information more tangible.

By following this structured approach and refining the explanation along the way, we can generate a comprehensive and helpful answer that addresses all aspects of the user's request.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/asm-generic/siginfo.h` 这个头文件。

**功能列举:**

`siginfo.h` 文件定义了与信号相关的信息结构体 `siginfo_t` 和一些相关的宏定义。它的主要功能是：

1. **定义信号信息的结构体 `siginfo_t`:** 这个结构体用于携带关于信号的详细信息，例如信号的来源、原因以及其他上下文数据。当一个信号被传递给进程时，内核会填充这个结构体，然后传递给进程的信号处理函数。

2. **定义 `sigval_t` 联合体:**  用于在实时信号中传递额外的数据，可以是一个整数或者一个指针。

3. **定义不同信号来源的联合体 `__sifields`:**  这是一个关键的联合体，它根据信号的来源（例如，来自 `kill` 系统调用、定时器、子进程状态变化、内存访问错误等）包含不同的结构体成员。这样可以根据不同的信号类型存储不同的相关信息。

4. **定义用于访问 `siginfo_t` 成员的宏:**  例如 `si_pid`、`si_uid`、`si_addr` 等，方便程序员访问结构体中的特定字段。

5. **定义信号来源的常量:**  例如 `SI_USER` (来自用户空间), `SI_KERNEL` (来自内核), `SI_TIMER` (来自定时器) 等。

6. **定义不同类型信号的 code 值:**  例如 `ILL_ILLOPC` (非法操作码), `SEGV_MAPERR` (地址未映射错误), `CLD_EXITED` (子进程正常退出) 等。这些 code 值提供了关于信号更精确的原因。

7. **定义 `sigevent_t` 结构体:**  用于异步信号通知，例如在使用 `timer_create` 创建定时器时，可以指定当定时器到期时如何通知进程（通过信号、线程等）。

**与 Android 功能的关系及举例说明:**

`siginfo.h` 是 Bionic C 库的一部分，因此与 Android 的基础功能息息相关。信号机制是 Linux 和 Android 系统中进程间通信和异常处理的重要方式。

* **进程管理:** 当一个进程使用 `kill()` 系统调用向另一个进程发送信号时，接收信号的进程的信号处理函数可以通过 `siginfo_t` 结构体获取发送进程的 PID 和 UID (`si_pid`, `si_uid`)。Android 的应用进程管理（例如，ActivityManagerService）可能会使用信号来通知应用进程某些状态变化或请求终止。

* **内存管理:** 当应用访问了无效的内存地址时，内核会发送 `SIGSEGV` 信号。`siginfo_t` 结构体的 `si_addr` 成员会包含导致错误的内存地址。Android 的 Dalvik/ART 虚拟机在处理内存访问错误时也会依赖这些信息。

* **定时器:**  Android 可以使用 POSIX 定时器 (`timer_create`)。当定时器到期时，会发送一个信号（例如 `SIGALRM`）。`siginfo_t` 结构体的 `si_tid` 会包含定时器的 ID，`si_overrun` 会指示定时器超时的次数。Android Framework 中的 AlarmManager 等服务底层可能使用了这些机制。

* **进程状态变化:** 当一个子进程退出或被停止时，父进程会收到 `SIGCHLD` 信号。`siginfo_t` 结构体的 `si_pid` 包含子进程的 PID，`si_status` 包含子进程的退出状态或导致停止的信号。Android 中启动新进程和管理进程生命周期时会用到这些信息。

* **文件 I/O 事件:**  可以使用信号驱动的 I/O（例如通过 `fcntl` 设置 `O_ASYNC` 和 `F_SETSIG`）。当文件描述符上有数据可读或可写时，进程会收到 `SIGIO` 或 `SIGPOLL` 信号。`siginfo_t` 结构体的 `si_band` 和 `si_fd` 会包含相关信息。

**libc 函数的功能实现 (以 `sigaction` 为例):**

`siginfo.h` 本身不包含 libc 函数的实现，它只是定义了数据结构。libc 中与信号相关的函数（例如 `sigaction`, `signal`, `kill`, `sigqueue` 等）会使用 `siginfo_t` 结构体。

以 `sigaction` 函数为例，它的功能是设置指定信号的处理方式。

```c
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
```

`sigaction` 函数的第二个参数 `act` 是一个指向 `sigaction` 结构体的指针，该结构体包含了信号处理函数的地址，以及一些控制信号处理行为的标志。如果信号处理函数是通过 `SA_SIGINFO` 标志注册的，那么该处理函数的原型如下：

```c
void handler(int sig, siginfo_t *info, void *ucontext);
```

在这个信号处理函数中，`info` 参数就是一个指向 `siginfo_t` 结构体的指针。内核在传递信号时会填充这个结构体，然后传递给信号处理函数，使得信号处理函数能够获取关于信号的详细信息。

**实现细节：**

1. 当一个事件发生导致内核需要向进程发送信号时（例如，`kill()` 系统调用，硬件异常，定时器到期等），内核会分配并填充一个 `siginfo_t` 结构体。

2. 填充的内容取决于信号的类型和来源。例如，如果是 `kill()` 系统调用，会填充发送进程的 PID 和 UID；如果是内存访问错误，会填充出错的地址。

3. 如果信号处理函数是通过 `SA_SIGINFO` 注册的，内核会将填充好的 `siginfo_t` 结构体的地址作为第二个参数传递给信号处理函数。

4. 信号处理函数可以通过访问 `siginfo_t` 结构体的成员来获取关于信号的详细信息，并根据这些信息采取相应的处理措施。

**动态链接器功能 (与信号的关系) 及 SO 布局样本和链接处理过程:**

动态链接器 (`linker` 或 `ld-linux.so`) 本身不直接操作 `siginfo_t` 结构体，但某些与动态链接相关的错误可能会导致信号的产生，并且 `siginfo_t` 会携带相关信息。

**可能导致信号的动态链接错误示例：**

* **未定义的符号 (undefined symbol):** 如果一个共享库依赖于另一个共享库中的符号，但在链接时找不到该符号，动态链接器可能会发送一个 `SIGSEGV` 信号，因为尝试访问未加载的代码或数据。

**SO 布局样本:**

假设我们有两个共享库 `liba.so` 和 `libb.so`，以及一个可执行文件 `app`。

**liba.so:**

```
地址空间起始
|-------------------|
| .text (代码段)    |  <- 包含 liba_func 函数
|-------------------|
| .data (已初始化数据)|
|-------------------|
| .bss (未初始化数据) |
|-------------------|
| .dynsym (动态符号表) | <- 包含 liba_func 的符号信息
|-------------------|
| .dynstr (动态字符串表)|
|-------------------|
地址空间结束
```

**libb.so:**

```
地址空间起始
|-------------------|
| .text (代码段)    |  <- 包含 libb_func，它调用了 liba_func
|-------------------|
| .data (已初始化数据)|
|-------------------|
| .bss (未初始化数据) |
|-------------------|
| .dynsym (动态符号表) | <- 包含 libb_func 的符号信息，可能包含对 liba_func 的 "未定义" 引用
|-------------------|
| .dynstr (动态字符串表)|
|-------------------|
地址空间结束
```

**app (可执行文件):**

```
地址空间起始
|-------------------|
| .text (代码段)    |  <- 调用 libb_func
|-------------------|
| .data (已初始化数据)|
|-------------------|
| .bss (未初始化数据) |
|-------------------|
| .dynsym (动态符号表) | <- 包含 app 中定义的符号，可能包含对 libb_func 的引用
|-------------------|
| .dynstr (动态字符串表)|
|-------------------|
| .plt (过程链接表)   | <- 用于延迟绑定外部符号
|-------------------|
| .got (全局偏移表)   | <- 存储外部符号的地址
|-------------------|
地址空间结束
```

**链接处理过程 (简化):**

1. **加载:** 操作系统加载可执行文件 `app` 到内存。
2. **动态链接器启动:** 动态链接器被加载并开始工作。
3. **依赖解析:** 动态链接器读取 `app` 的动态链接信息，找到它依赖的共享库，例如 `libb.so`。
4. **加载共享库:** 动态链接器加载 `libb.so` 到内存。
5. **符号解析:** 动态链接器解析 `libb.so` 中的符号引用。如果 `libb.so` 调用了 `liba_func`，但 `liba.so` 没有被加载或者 `liba_func` 在 `liba.so` 中不存在或未导出，就会发生链接错误。
6. **错误处理 (可能导致信号):** 如果在符号解析阶段找不到需要的符号，动态链接器通常会报错并可能导致程序终止。在某些情况下，如果程序尝试调用一个未解析的函数地址，可能会导致内存访问错误，从而产生 `SIGSEGV` 信号。此时，`siginfo_t` 的 `si_addr` 可能会指向尝试调用的无效地址。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 一个进程接收到 `SIGSEGV` 信号。
* `siginfo_t` 结构体被传递给信号处理函数。

**输出 (可能的 `siginfo_t` 内容):**

```
si_signo: 11 (SIGSEGV)
si_errno: 0
si_code: 1 (SEGV_MAPERR - 地址未映射错误)
_sifields._sigfault._addr: 0xdeadbeef  // 导致错误的内存地址
```

在这个例子中，`si_code` 表明是由于访问了一个未映射的内存地址造成的段错误，`si_addr` 提供了出错的地址 `0xdeadbeef`。

**用户或编程常见的使用错误:**

1. **未检查 `si_code`:**  很多程序员在信号处理函数中只关注信号的类型 (`si_signo`)，而忽略了 `si_code`。`si_code` 提供了关于信号更精确的原因，这对于调试和错误处理至关重要。例如，对于 `SIGSEGV`，`si_code` 可以区分是地址未映射 (`SEGV_MAPERR`) 还是访问权限错误 (`SEGV_ACCERR`)。

   **错误示例:**

   ```c
   void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
       printf("Caught SIGSEGV!\n");
       // 没有检查 info->si_code
       exit(1);
   }
   ```

   **正确示例:**

   ```c
   void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
       printf("Caught SIGSEGV!\n");
       if (info->si_code == SEGV_MAPERR) {
           printf("Error: Attempted to access unmapped memory at address %p\n", info->si_addr);
       } else if (info->si_code == SEGV_ACCERR) {
           printf("Error: Permission denied while accessing memory at address %p\n", info->si_addr);
       }
       exit(1);
   }
   ```

2. **假设 `si_pid` 总是有效:**  并非所有信号都来自另一个进程。例如，由定时器或自身错误产生的信号，`si_pid` 可能没有意义。

3. **在信号处理函数中执行不安全的操作:** 信号处理函数应该尽可能简单和可重入。执行像 `printf` 或 `malloc` 这样的操作可能导致问题，尤其是在异步信号处理函数中。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

1. **Android Framework 发起操作:** 假设一个 Android 应用触发了一个导致 native 代码崩溃的操作，例如访问了无效的内存。

2. **NDK 代码执行:** 应用的 native 代码（通常是用 C/C++ 编写并通过 NDK 编译）执行到出错的位置。

3. **内核捕获异常:** CPU 或 MMU 检测到内存访问错误，内核捕获到这个异常。

4. **内核发送信号:** 内核确定需要向出错的进程发送 `SIGSEGV` 信号。

5. **填充 `siginfo_t`:** 内核填充 `siginfo_t` 结构体，包含信号编号、错误码、出错地址等信息。

6. **传递信号:** 内核将信号传递给进程，调用进程注册的信号处理函数（如果已注册）。

7. **信号处理:** 如果应用注册了 `SIGSEGV` 的信号处理函数，该函数会被调用，并接收到指向 `siginfo_t` 结构体的指针。

**Frida Hook 示例:**

假设我们想在 native 代码中 `SIGSEGV` 信号处理函数被调用时，打印 `siginfo_t` 的内容。

首先，我们需要找到应用中注册的 `SIGSEGV` 信号处理函数的地址。这可能比较复杂，因为 Android 应用的信号处理可能由 ART 虚拟机或底层库管理。一个更简单的方法是 hook `sigaction` 函数，查看哪些函数被注册为 `SIGSEGV` 的处理函数。

**Frida Script:**

```javascript
Interceptor.attach(Module.findExportByName(null, "sigaction"), {
  onEnter: function (args) {
    const signum = args[0].toInt32();
    const act = ptr(args[1]);
    const oldact = ptr(args[2]);

    if (signum === 11) { // SIGSEGV
      console.log("sigaction called for SIGSEGV");
      if (!act.isNull()) {
        const sa_handler = act.readPointer();
        const sa_sigaction = act.add(Process.pointerSize).readPointer();
        const sa_flags = act.add(Process.pointerSize * 2).readInt32();

        console.log("  sa_handler:", sa_handler);
        console.log("  sa_sigaction:", sa_sigaction);
        console.log("  sa_flags:", sa_flags);

        if (sa_flags & 0x00000004) { // SA_SIGINFO flag
          this.sigsegv_handler = sa_sigaction;
        } else {
          this.sigsegv_handler = sa_handler;
        }
      }
    }
  },
});

// Hook 找到的 SIGSEGV 信号处理函数
Interceptor.ensureInitialized(() => {
  Interceptor.attach(this.sigsegv_handler, {
    onEnter: function (args) {
      const sig = args[0].toInt32();
      const info = ptr(args[1]);

      if (sig === 11 && !info.isNull()) {
        console.log("SIGSEGV handler called!");
        console.log("  si_signo:", Memory.readS32(info));
        console.log("  si_errno:", Memory.readS32(info.add(4)));
        console.log("  si_code:", Memory.readS32(info.add(8)));
        console.log("  si_addr:", ptr(Memory.readULong(info.add(16)))); // 假设 _sifields 偏移量
      }
    },
  });
});
```

**解释:**

1. **Hook `sigaction`:** 我们首先 hook 了 `sigaction` 函数，以便找到哪些函数被注册为 `SIGSEGV` 的处理函数。
2. **检测 `SA_SIGINFO`:**  检查 `sa_flags` 是否设置了 `SA_SIGINFO`，以确定使用哪个字段（`sa_handler` 或 `sa_sigaction`）来获取信号处理函数的地址。
3. **Hook 信号处理函数:**  一旦找到 `SIGSEGV` 的处理函数地址，我们就 hook 这个函数。
4. **读取 `siginfo_t`:** 在 `SIGSEGV` 处理函数被调用时，我们读取 `siginfo_t` 结构体的成员，并打印出来。

**注意:** 这个 Frida 脚本只是一个示例，实际情况可能更复杂，例如，信号处理可能在不同的库中注册，或者有更复杂的处理逻辑。你需要根据具体的目标应用进行调整。

希望这个详细的解释能够帮助你理解 `siginfo.h` 文件的功能以及它在 Android 中的应用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-generic/siginfo.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_ASM_GENERIC_SIGINFO_H
#define _UAPI_ASM_GENERIC_SIGINFO_H
#include <linux/compiler.h>
#include <linux/types.h>
typedef union sigval {
  int sival_int;
  void  * sival_ptr;
} sigval_t;
#define SI_MAX_SIZE 128
#ifndef __ARCH_SI_BAND_T
#define __ARCH_SI_BAND_T long
#endif
#ifndef __ARCH_SI_CLOCK_T
#define __ARCH_SI_CLOCK_T __kernel_clock_t
#endif
#ifndef __ARCH_SI_ATTRIBUTES
#define __ARCH_SI_ATTRIBUTES
#endif
union __sifields {
  struct {
    __kernel_pid_t _pid;
    __kernel_uid32_t _uid;
  } _kill;
  struct {
    __kernel_timer_t _tid;
    int _overrun;
    sigval_t _sigval;
    int _sys_private;
  } _timer;
  struct {
    __kernel_pid_t _pid;
    __kernel_uid32_t _uid;
    sigval_t _sigval;
  } _rt;
  struct {
    __kernel_pid_t _pid;
    __kernel_uid32_t _uid;
    int _status;
    __ARCH_SI_CLOCK_T _utime;
    __ARCH_SI_CLOCK_T _stime;
  } _sigchld;
  struct {
    void  * _addr;
#define __ADDR_BND_PKEY_PAD (__alignof__(void *) < sizeof(short) ? sizeof(short) : __alignof__(void *))
    union {
      int _trapno;
      short _addr_lsb;
      struct {
        char _dummy_bnd[__ADDR_BND_PKEY_PAD];
        void  * _lower;
        void  * _upper;
      } _addr_bnd;
      struct {
        char _dummy_pkey[__ADDR_BND_PKEY_PAD];
        __u32 _pkey;
      } _addr_pkey;
      struct {
        unsigned long _data;
        __u32 _type;
        __u32 _flags;
      } _perf;
    };
  } _sigfault;
  struct {
    __ARCH_SI_BAND_T _band;
    int _fd;
  } _sigpoll;
  struct {
    void  * _call_addr;
    int _syscall;
    unsigned int _arch;
  } _sigsys;
};
#ifndef __ARCH_HAS_SWAPPED_SIGINFO
#define __SIGINFO struct { int si_signo; int si_errno; int si_code; union __sifields _sifields; \
}
#else
#define __SIGINFO struct { int si_signo; int si_code; int si_errno; union __sifields _sifields; \
}
#endif
typedef struct siginfo {
  union {
    __SIGINFO;
    int _si_pad[SI_MAX_SIZE / sizeof(int)];
  };
} __ARCH_SI_ATTRIBUTES siginfo_t;
#define si_pid _sifields._kill._pid
#define si_uid _sifields._kill._uid
#define si_tid _sifields._timer._tid
#define si_overrun _sifields._timer._overrun
#define si_sys_private _sifields._timer._sys_private
#define si_status _sifields._sigchld._status
#define si_utime _sifields._sigchld._utime
#define si_stime _sifields._sigchld._stime
#define si_value _sifields._rt._sigval
#define si_int _sifields._rt._sigval.sival_int
#define si_ptr _sifields._rt._sigval.sival_ptr
#define si_addr _sifields._sigfault._addr
#define si_trapno _sifields._sigfault._trapno
#define si_addr_lsb _sifields._sigfault._addr_lsb
#define si_lower _sifields._sigfault._addr_bnd._lower
#define si_upper _sifields._sigfault._addr_bnd._upper
#define si_pkey _sifields._sigfault._addr_pkey._pkey
#define si_perf_data _sifields._sigfault._perf._data
#define si_perf_type _sifields._sigfault._perf._type
#define si_perf_flags _sifields._sigfault._perf._flags
#define si_band _sifields._sigpoll._band
#define si_fd _sifields._sigpoll._fd
#define si_call_addr _sifields._sigsys._call_addr
#define si_syscall _sifields._sigsys._syscall
#define si_arch _sifields._sigsys._arch
#define SI_USER 0
#define SI_KERNEL 0x80
#define SI_QUEUE - 1
#define SI_TIMER - 2
#define SI_MESGQ - 3
#define SI_ASYNCIO - 4
#define SI_SIGIO - 5
#define SI_TKILL - 6
#define SI_DETHREAD - 7
#define SI_ASYNCNL - 60
#define SI_FROMUSER(siptr) ((siptr)->si_code <= 0)
#define SI_FROMKERNEL(siptr) ((siptr)->si_code > 0)
#define ILL_ILLOPC 1
#define ILL_ILLOPN 2
#define ILL_ILLADR 3
#define ILL_ILLTRP 4
#define ILL_PRVOPC 5
#define ILL_PRVREG 6
#define ILL_COPROC 7
#define ILL_BADSTK 8
#define ILL_BADIADDR 9
#define __ILL_BREAK 10
#define __ILL_BNDMOD 11
#define NSIGILL 11
#define FPE_INTDIV 1
#define FPE_INTOVF 2
#define FPE_FLTDIV 3
#define FPE_FLTOVF 4
#define FPE_FLTUND 5
#define FPE_FLTRES 6
#define FPE_FLTINV 7
#define FPE_FLTSUB 8
#define __FPE_DECOVF 9
#define __FPE_DECDIV 10
#define __FPE_DECERR 11
#define __FPE_INVASC 12
#define __FPE_INVDEC 13
#define FPE_FLTUNK 14
#define FPE_CONDTRAP 15
#define NSIGFPE 15
#define SEGV_MAPERR 1
#define SEGV_ACCERR 2
#define SEGV_BNDERR 3
#ifdef __ia64__
#define __SEGV_PSTKOVF 4
#else
#define SEGV_PKUERR 4
#endif
#define SEGV_ACCADI 5
#define SEGV_ADIDERR 6
#define SEGV_ADIPERR 7
#define SEGV_MTEAERR 8
#define SEGV_MTESERR 9
#define SEGV_CPERR 10
#define NSIGSEGV 10
#define BUS_ADRALN 1
#define BUS_ADRERR 2
#define BUS_OBJERR 3
#define BUS_MCEERR_AR 4
#define BUS_MCEERR_AO 5
#define NSIGBUS 5
#define TRAP_BRKPT 1
#define TRAP_TRACE 2
#define TRAP_BRANCH 3
#define TRAP_HWBKPT 4
#define TRAP_UNK 5
#define TRAP_PERF 6
#define NSIGTRAP 6
#define TRAP_PERF_FLAG_ASYNC (1u << 0)
#define CLD_EXITED 1
#define CLD_KILLED 2
#define CLD_DUMPED 3
#define CLD_TRAPPED 4
#define CLD_STOPPED 5
#define CLD_CONTINUED 6
#define NSIGCHLD 6
#define POLL_IN 1
#define POLL_OUT 2
#define POLL_MSG 3
#define POLL_ERR 4
#define POLL_PRI 5
#define POLL_HUP 6
#define NSIGPOLL 6
#define SYS_SECCOMP 1
#define SYS_USER_DISPATCH 2
#define NSIGSYS 2
#define EMT_TAGOVF 1
#define NSIGEMT 1
#define SIGEV_SIGNAL 0
#define SIGEV_NONE 1
#define SIGEV_THREAD 2
#define SIGEV_THREAD_ID 4
#ifndef __ARCH_SIGEV_PREAMBLE_SIZE
#define __ARCH_SIGEV_PREAMBLE_SIZE (sizeof(int) * 2 + sizeof(sigval_t))
#endif
#define SIGEV_MAX_SIZE 64
#define SIGEV_PAD_SIZE ((SIGEV_MAX_SIZE - __ARCH_SIGEV_PREAMBLE_SIZE) / sizeof(int))
typedef struct sigevent {
  sigval_t sigev_value;
  int sigev_signo;
  int sigev_notify;
  union {
    int _pad[SIGEV_PAD_SIZE];
    int _tid;
    struct {
      void(* _function) (sigval_t);
      void * _attribute;
    } _sigev_thread;
  } _sigev_un;
} sigevent_t;
#define sigev_notify_function _sigev_un._sigev_thread._function
#define sigev_notify_attributes _sigev_un._sigev_thread._attribute
#define sigev_notify_thread_id _sigev_un._tid
#endif
```