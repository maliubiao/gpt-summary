Response:
Let's break down the thought process for analyzing the provided C header file (`eventlib_p.h`).

**1. Understanding the Context:**

The first step is to acknowledge the provided context: the file is `eventlib_p.h` located within the `bionic/libc/upstream-netbsd/lib/libc/isc/eventlib_p.handroid` directory. This immediately tells us:

* **Bionic:**  It's part of Android's C library.
* **Upstream NetBSD:** It's likely derived from or related to the NetBSD operating system's libc.
* **Private Header:** The `_p.h` suffix strongly suggests this is a *private* header, meaning it's not intended for direct use by application developers. It defines internal structures and functions used by the `eventlib`.
* **`isc`:** This likely stands for "Internet Systems Consortium," a common source for networking-related code.
* **`eventlib`:** The name clearly indicates this is a library for managing events, likely related to I/O operations, timers, and other asynchronous activities.

**2. Initial Scan and High-Level Analysis:**

Quickly reading through the file reveals several key areas:

* **Includes:** Standard system headers like `<sys/param.h>`, `<sys/types.h>`, `<sys/socket.h>`, `<netinet/in.h>`, `<sys/un.h>`, etc., and ISC-specific headers like `<isc/heap.h>`, `<isc/list.h>`, `<isc/memcluster.h>`. This confirms its role in low-level system programming and its reliance on ISC's utility libraries.
* **Macros:**  A plethora of macros like `EVENTLIB_DEBUG`, `EV_MASK_ALL`, `EV_ERR`, `OK`, `NEW`, `FREE`, `FILL`. These are likely used for error handling, memory management, and debugging.
* **Typedefs:** Definitions for structures like `evConn`, `evAccept`, `evFile`, `evStream`, `evTimer`, `evWait`, `evWaitList`, and `evEvent_p`. These represent the core data structures of the event library.
* **Function Prototypes (with Macros):**  Macros like `evPrintf`, `evCreateTimers`, `evDestroyTimers`, `evFreeWait` likely hide the actual function names.
* **Conditional Compilation:**  `#ifdef USE_POLL` indicates support for `poll()` as an alternative to `select()`.
* **Global Variable:** `__evOptMonoTime` is declared as `extern int`, suggesting a global option.

**3. Deeper Dive into Key Structures:**

Now, focus on understanding the purpose of each major structure:

* **`evConn`:** Represents a connection, likely for sockets. It stores the file descriptor (`fd`), associated function (`func`), user data pointer (`uap`), and flags indicating whether it's a listener or selected.
* **`evAccept`:** Holds information about an accepted connection on a listening socket, including the local and remote addresses and file descriptor.
* **`evFile`:** Represents a file descriptor being monitored for events (read, write, exception). It stores the file descriptor, event mask, and associated function.
* **`evStream`:**  Deals with I/O on a file descriptor using `iovec` for scatter/gather operations. It tracks the progress of the I/O operation and any associated timer.
* **`evTimer`:** Represents a timer event, storing the due time, interval, and associated function.
* **`evWait` and `evWaitList`:**  Used for synchronization or waiting for specific conditions. The `tag` field suggests a mechanism for identifying the wait condition.
* **`evEvent_p`:** A central structure that seems to encapsulate different types of events using a union. This is a common pattern in event-driven systems.
* **`evContext_p`:** The main context structure that holds all the state of the event library, including lists of connections, files, streams, timers, and wait lists. It also contains data structures related to `select()` or `poll()`.

**4. Identifying Functionality and Connections to Android:**

Based on the structure definitions, the core functionality of `eventlib` appears to be:

* **Event Monitoring:**  Tracking file descriptors for read, write, and exception events.
* **Timer Management:** Scheduling and triggering timer events.
* **Connection Management:** Handling incoming connections on listening sockets.
* **Asynchronous I/O:** Managing non-blocking I/O operations.
* **Synchronization:** Providing mechanisms to wait for specific events.

The connection to Android lies in its presence within Bionic, the core C library. This implies that parts of the Android framework or native code rely on this `eventlib` for handling asynchronous operations. Examples include:

* **Networking:**  Handling network connections in system services or applications.
* **Input/Output:** Monitoring file descriptors for data availability or state changes.
* **Inter-Process Communication (IPC):**  Potentially used for communication between processes.

**5. Explaining libc Function Implementations (Conceptual):**

Since this is a *private* header, it doesn't directly define the implementation of standard libc functions. Instead, it *uses* them. The header uses functions like `memset`, `malloc` (via `memget`), `free` (via `memput`), and functions related to sockets (`socket`, `bind`, `listen`, `accept`, `read`, `write`). The actual implementations reside in other parts of Bionic's libc. The header focuses on how *this specific event library* utilizes those underlying libc functionalities.

**6. Dynamic Linker and SO Layout (Conceptual):**

As a private header, `eventlib_p.h` doesn't directly interact with the dynamic linker. The dynamic linker's job is to resolve symbols and load shared libraries at runtime. The `eventlib` itself would likely be compiled into a static or shared library.

If it's a shared library, the layout might look like this:

```
libevent.so:
    .text       # Code for eventlib functions
    .rodata     # Read-only data
    .data       # Initialized data (e.g., __evOptMonoTime)
    .bss        # Uninitialized data
    .symtab     # Symbol table
    .dynsym     # Dynamic symbol table (for linking)
    .rel.dyn    # Relocations for dynamic linking
    .rel.plt    # Relocations for the Procedure Linkage Table
```

The linking process would involve:

1. **Compilation:** Source code using `eventlib` is compiled into object files.
2. **Linking:** The linker resolves symbols (function calls, global variables) by looking them up in the `libevent.so`'s symbol tables.
3. **Dynamic Linking (at runtime):** When the program starts, the dynamic linker loads `libevent.so` into memory and performs any necessary relocations to adjust addresses.

**7. Logic Inference and Assumptions (Example):**

Consider the `evFile` structure and its potential use in a simple file monitoring scenario.

* **Assumption:**  We want to be notified when data is available to read from a file descriptor.
* **Input:** A file descriptor opened for reading (`fd`), a callback function (`my_read_handler`).
* **Internal Logic (Hypothetical):** The `eventlib` would create an `evFile` structure, store the `fd` and `my_read_handler`, and add it to its internal list of monitored file descriptors. It would then use `select()` or `poll()` to wait for read events on that `fd`.
* **Output:** When data is available, the `select()`/`poll()` call would return, and the `eventlib` would invoke `my_read_handler` with the `fd`.

**8. Common Usage Errors (Example):**

* **Forgetting to initialize the event context:**  Many event libraries require an initialization step to set up internal data structures. Failure to do so can lead to crashes or undefined behavior.
* **Incorrectly setting event masks:** Specifying the wrong event mask (e.g., only listening for write events when you need to read) will result in missed events.
* **Not handling errors from event functions:** Event libraries often return error codes. Ignoring these errors can lead to unexpected program behavior.
* **Memory leaks:** If event structures or associated data are not properly freed, it can lead to memory leaks.

**9. Android Framework/NDK Usage and Frida Hooking:**

To trace how Android reaches this code:

1. **Identify Potential Entry Points:** Look for Android framework components or NDK APIs that involve asynchronous operations or I/O. Examples might include `AsyncTasks`, `Handler`s, `Looper`s, or native networking APIs.
2. **Hypothesize Call Stack:**  Trace the potential function calls from the high-level framework down into the native layer. For example, an `AsyncTask` might use a `Handler`, which internally uses a `Looper`, which might eventually interact with file descriptors and trigger the `eventlib`.
3. **Frida Hooking:** Use Frida to intercept function calls at various points in the suspected call stack. Focus on hooking functions related to file descriptor management (`open`, `read`, `write`, `select`, `poll`) and event handling within Bionic.

**Frida Example (Illustrative - Might need adjustments):**

```javascript
// Hook the open system call
Interceptor.attach(Module.findExportByName(null, "open"), {
  onEnter: function(args) {
    console.log("open(" + Memory.readUtf8String(args[0]) + ")");
  },
  onLeave: function(retval) {
    console.log("open returned: " + retval);
  }
});

// Hook a potential eventlib function (replace with actual function name)
Interceptor.attach(Module.findExportByName("libc.so", "__evSelectFD"), {
  onEnter: function(args) {
    console.log("__evSelectFD called with fd: " + args[0]);
  }
});

// You might need to explore the `libbase.so` or other system libraries
// to find the exact entry points and function names.
```

This detailed thought process combines code analysis, contextual understanding, and reasoned assumptions to provide a comprehensive explanation of the provided header file and its role within the Android ecosystem. It also outlines how to further investigate its usage using dynamic analysis tools like Frida.
这个头文件 `eventlib_p.h` 定义了 `eventlib` 库的私有接口。`eventlib` 是一个事件驱动的库，它允许程序监控文件描述符上的事件（例如，可读、可写）和定时器事件，并在事件发生时执行回调函数。由于它是 `_p.h` 结尾，表明这是内部使用的头文件，不应该被外部直接包含。

**`eventlib` 的功能:**

1. **文件描述符事件监控:**  `eventlib` 允许程序注册对特定文件描述符的读、写或异常事件的兴趣。当这些事件发生时，`eventlib` 会调用预先注册的回调函数。
2. **定时器事件:**  `eventlib` 可以设置定时器，并在指定的时间到达时触发回调函数。定时器可以是一次性的或周期性的。
3. **连接管理:**  `eventlib` 提供了一些结构（如 `evConn` 和 `evAccept`）来管理网络连接，特别是监听套接字上新连接的到来。
4. **流式 I/O 管理:**  `evStream` 结构用于管理非阻塞的流式 I/O 操作，允许程序在多个缓冲区中进行读写操作。
5. **等待条件:** `evWait` 和 `evWaitList` 结构允许程序等待特定的条件满足。

**与 Android 功能的关系及举例:**

`eventlib` 作为 Bionic 的一部分，很可能被 Android 内部的各种组件和服务使用，以实现高效的事件处理。

* **网络服务:** Android 的网络服务（例如，负责处理网络连接的 `netd` 守护进程）可能会使用 `eventlib` 来监控套接字上的事件，例如新连接的到来或数据的可读性。当一个应用尝试建立网络连接时，底层的网络库可能会使用 `eventlib` 来异步地等待连接建立完成。
* **输入系统:** Android 的输入系统可能使用 `eventlib` 来监控来自输入设备的事件（例如，触摸屏或键盘）。
* **Binder IPC:** 虽然 Binder 有自己的事件循环机制，但底层的某些 socket 操作可能也依赖于 `eventlib`。
* **文件系统监控:** 某些需要监控文件系统事件的 Android 服务可能会使用 `eventlib` 来监听文件描述符上的事件。

**举例说明:** 假设一个网络服务器应用需要监听端口 8080 上的新连接。

1. 它会创建一个监听套接字，并将其绑定到 8080 端口。
2. 它会使用 `eventlib` 的相关函数（例如，基于 `evConn` 的机制）注册对该监听套接字的读事件的兴趣。
3. 当有新的连接请求到达时，监听套接字会变为可读。
4. `eventlib` 检测到该事件，并调用预先注册的回调函数。
5. 回调函数会调用 `accept()` 系统调用来接受新的连接，并可能创建一个新的 `evConn` 结构来管理这个新的连接。

**libc 函数的实现解释:**

这个头文件本身并不实现 libc 函数，而是使用了 libc 提供的函数。让我们解释其中一些常见 libc 函数的功能以及它们在 `eventlib` 中的可能用法：

* **`errno.h`:** 定义了错误代码。`eventlib` 使用 `errno` 来报告错误，例如在 `EV_ERR(e)` 宏中。
* **`fcntl.h`:**  包含了文件控制相关的函数，例如 `fcntl()` 可以用于设置文件描述符为非阻塞模式。`eventlib` 在处理非阻塞 I/O 时可能会使用 `fcntl()`。
* **`stdio.h`:**  提供了标准输入输出函数，例如 `printf()`。`eventlib` 中的 `evPrintf` 宏（实际可能映射到内部的打印函数）用于调试输出。
* **`stdlib.h`:**  包含了通用工具函数，例如 `malloc()` 和 `free()`。`eventlib` 使用 `memget` 和 `memput` 宏（很可能封装了 `malloc` 和 `free` 或自定义的内存管理机制）来分配和释放内存。
* **`string.h`:**  提供了字符串操作函数，例如 `memset()`。`eventlib` 使用 `memset()` 在 `FILL(p)` 宏中对新分配的内存进行初始化（在调试模式下填充特定的值）。
* **`sys/socket.h` 和 `netinet/in.h`:** 提供了套接字编程相关的结构和函数，例如 `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `read()`, `write()` 等。`eventlib` 的连接管理和流式 I/O 功能会大量使用这些函数。
* **`sys/un.h`:** 提供了 Unix 域套接字相关的结构。`eventlib` 的 `evAccept` 结构中包含了 `sockaddr_un`，表明它支持 Unix 域套接字。

**涉及 dynamic linker 的功能及处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 负责在程序启动时加载共享库，并解析符号引用。

如果 `eventlib` 被编译成一个共享库（例如 `libevent.so`），那么当其他库或可执行文件使用 `eventlib` 提供的功能时，dynamic linker 会负责加载 `libevent.so` 并解析对其中符号的引用。

**SO 布局样本 (假设 `eventlib` 被编译成 `libevent.so`):**

```
libevent.so:
    .text           # 包含 eventlib 的代码段
    .rodata         # 只读数据段，例如字符串常量
    .data           # 已初始化的数据段，例如全局变量
    .bss            # 未初始化的数据段
    .symtab         # 符号表，包含导出的符号信息
    .strtab         # 字符串表，包含符号名称字符串
    .dynsym         # 动态符号表，用于动态链接
    .dynstr         # 动态字符串表
    .rel.dyn        # 动态重定位表，用于在加载时修改地址
    .rel.plt        # PLT (Procedure Linkage Table) 的重定位表
    ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译依赖 `libevent.so` 的代码时，编译器会生成对 `libevent.so` 中符号的未解析引用。
2. **动态链接时加载:** 当程序启动时，dynamic linker 会读取程序头中的 `PT_DYNAMIC` 段，该段包含了动态链接所需的信息。
3. **查找依赖库:** Dynamic linker 根据程序的依赖关系找到 `libevent.so`。
4. **加载共享库:** Dynamic linker 将 `libevent.so` 加载到内存中的某个地址。
5. **符号解析:** Dynamic linker 遍历程序的 GOT (Global Offset Table) 和 PLT，并使用 `libevent.so` 的动态符号表来解析未解析的符号引用，将 GOT 和 PLT 中的条目指向 `libevent.so` 中相应的函数或数据。
6. **重定位:** Dynamic linker 根据重定位表修改 `libevent.so` 中需要调整的地址，使其适应当前加载的内存地址。

**逻辑推理、假设输入与输出 (以文件描述符事件监控为例):**

假设我们使用 `eventlib` 监控一个管道的读端。

**假设输入:**

* `fd`: 代表管道读端的文件描述符。
* `callback_function`:  一个当管道中有数据可读时被调用的函数。
* `event_mask`: 设置为 `EV_READ`，表示我们关注读事件。

**内部逻辑推理:**

1. `eventlib` 会创建一个 `evFile` 结构，存储 `fd`, `callback_function` 和 `event_mask`。
2. 它会将这个 `evFile` 结构添加到其内部的文件描述符监控列表中。
3. `eventlib` 内部会使用 `select()` 或 `poll()` 系统调用来监听所有被监控的文件描述符上的事件。当 `fd` 变为可读时，`select()` 或 `poll()` 会返回。
4. `eventlib` 会遍历其监控列表，找到与可读 `fd` 对应的 `evFile` 结构。
5. `eventlib` 调用 `evFile` 结构中存储的 `callback_function`。

**假设输出:**

当管道中有数据写入时，`callback_function` 会被执行。

**用户或编程常见的使用错误:**

1. **忘记初始化 `eventlib` 上下文:** 某些 `eventlib` 实现可能需要先初始化一个上下文结构。
2. **错误的事件掩码:** 注册了错误的事件掩码，例如只想监听读事件却注册了写事件。
3. **忘记处理错误返回值:** `eventlib` 的函数可能会返回错误代码，用户需要检查并处理这些错误。
4. **内存泄漏:** 如果动态分配的与事件相关的结构没有被正确释放，可能会导致内存泄漏。
5. **在回调函数中执行阻塞操作:** 由于 `eventlib` 通常是单线程的，在回调函数中执行阻塞操作会导致整个事件循环停止响应。
6. **文件描述符失效:** 如果监控的文件描述符在 `eventlib` 仍然监控它的情况下被关闭，可能会导致未定义的行为。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例调试步骤:**

要追踪 Android Framework 或 NDK 如何使用 `eventlib`，需要进行动态分析。以下是一个使用 Frida Hook 的示例，用于调试 `eventlib` 中与文件描述符监控相关的函数：

**假设我们想跟踪 `evSelectFD` 函数的调用 (虽然这个头文件里没有直接定义这个函数，但它可能在相关的 `.c` 文件中定义并被宏 `OK` 或其他地方调用)。**

1. **找到目标进程:**  确定你想要分析的 Android 进程的 PID 或进程名。
2. **编写 Frida 脚本:**

```javascript
function hook_evSelectFD() {
    var symbols = Process.enumerateSymbols("libc.so"); // 假设 evSelectFD 在 libc.so 中
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("evSelectFD") !== -1) { // 模糊匹配，可能需要更精确的匹配
            console.log("Found evSelectFD symbol at: " + symbol.address);
            Interceptor.attach(symbol.address, {
                onEnter: function (args) {
                    console.log("evSelectFD called with fd: " + args[0]);
                    // 可以进一步打印其他参数
                },
                onLeave: function (retval) {
                    console.log("evSelectFD returned: " + retval);
                }
            });
            return;
        }
    }
    console.log("evSelectFD symbol not found.");
}

setImmediate(hook_evSelectFD);
```

3. **运行 Frida:** 使用 Frida 客户端连接到目标 Android 进程并执行脚本。例如：

```bash
frida -U -f <package_name> -l your_frida_script.js --no-pause
# 或者连接到正在运行的进程
frida -U <process_name_or_pid> -l your_frida_script.js
```

4. **触发事件:** 在 Android 设备或模拟器上执行操作，这些操作可能会导致 Framework 或 NDK 使用 `eventlib`。例如，进行网络请求、触摸屏幕等。
5. **查看 Frida 输出:** Frida 会打印出 `evSelectFD` 被调用的信息，包括文件描述符的值和返回值。通过分析这些信息，你可以了解哪些组件在何时使用了 `eventlib`。

**更进一步的调试:**

* **跟踪 `select` 或 `poll` 系统调用:**  可以 Hook `select` 或 `poll` 系统调用，以查看哪些文件描述符被监听以及何时返回。
* **分析调用栈:**  在 Frida 的 `onEnter` 中使用 `Thread.backtrace().map(DebugSymbol.fromAddress).join('\\n')` 可以查看 `evSelectFD` 的调用栈，从而了解是哪个函数或模块调用了它。
* **结合源码:**  参考 Bionic 的源代码，可以更深入地理解 `eventlib` 的实现和使用方式。

请注意，由于 `eventlib_p.h` 是私有头文件，直接使用的函数可能不在其中声明，需要查看相关的 `.c` 文件才能找到具体的函数实现和调用关系。 此外，实际的函数名称可能与宏定义有关，需要仔细分析代码才能确定。

### 提示词
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/isc/eventlib_p.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: eventlib_p.h,v 1.3 2009/04/12 17:07:17 christos Exp $	*/

/*
 * Copyright (c) 2005 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1995-1999 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*! \file 
 * \brief private interfaces for eventlib
 * \author vix 09sep95 [initial]
 *
 * Id: eventlib_p.h,v 1.9 2006/03/09 23:57:56 marka Exp
 */

#ifndef _EVENTLIB_P_H
#define _EVENTLIB_P_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#define EVENTLIB_DEBUG 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/heap.h>
#include <isc/list.h>
#include <isc/memcluster.h>

#define	EV_MASK_ALL	(EV_READ | EV_WRITE | EV_EXCEPT)
#define EV_ERR(e)		return (errno = (e), -1)
#define OK(x)		if ((x) < 0) EV_ERR(errno); else (void)NULL
#define OKFREE(x, y)	if ((x) < 0) { FREE((y)); EV_ERR(errno); } \
			else (void)NULL

#define	NEW(p)		if (((p) = memget(sizeof *(p))) != NULL) \
				FILL(p); \
			else \
				(void)NULL;
#define OKNEW(p)	if (!((p) = memget(sizeof *(p)))) { \
				errno = ENOMEM; \
				return (-1); \
			} else \
				FILL(p)
#define FREE(p)		memput((p), sizeof *(p))

#if EVENTLIB_DEBUG
#define FILL(p)		memset((p), 0xF5, sizeof *(p))
#else
#define FILL(p)
#endif

#ifdef USE_POLL
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#include <poll.h>
#endif /* USE_POLL */

typedef struct evConn {
	evConnFunc	func;
	void *		uap;
	int		fd;
	int		flags;
#define EV_CONN_LISTEN		0x0001		/*%< Connection is a listener. */
#define EV_CONN_SELECTED	0x0002		/*%< evSelectFD(conn->file). */
#define EV_CONN_BLOCK		0x0004		/*%< Listener fd was blocking. */
	evFileID	file;
	struct evConn *	prev;
	struct evConn *	next;
} evConn;

typedef struct evAccept {
	int		fd;
	union {
		struct sockaddr		sa;
		struct sockaddr_in	in;
#ifndef NO_SOCKADDR_UN
		struct sockaddr_un	un;
#endif
	}		la;
	ISC_SOCKLEN_T	lalen;
	union {
		struct sockaddr		sa;
		struct sockaddr_in	in;
#ifndef NO_SOCKADDR_UN
		struct sockaddr_un	un;
#endif
	}		ra;
	ISC_SOCKLEN_T	ralen;
	int		ioErrno;
	evConn *	conn;
	LINK(struct evAccept) link;
} evAccept;

typedef struct evFile {
	evFileFunc	func;
	void *		uap;
	int		fd;
	int		eventmask;
	int		preemptive;
	struct evFile *	prev;
	struct evFile *	next;
	struct evFile *	fdprev;
	struct evFile *	fdnext;
} evFile;

typedef struct evStream {
	evStreamFunc	func;
	void *		uap;
	evFileID	file;
	evTimerID	timer;
	int		flags;
#define EV_STR_TIMEROK	0x0001	/*%< IFF timer valid. */
	int		fd;
	struct iovec *	iovOrig;
	int		iovOrigCount;
	struct iovec *	iovCur;
	int		iovCurCount;
	int		ioTotal;
	int		ioDone;
	int		ioErrno;
	struct evStream	*prevDone, *nextDone;
	struct evStream	*prev, *next;
} evStream;

typedef struct evTimer {
	evTimerFunc	func;
	void *		uap;
	struct timespec	due, inter;
	int		index;
	int		mode;
#define EV_TMR_RATE	1
} evTimer;

typedef struct evWait {
	evWaitFunc	func;
	void *		uap;
	const void *	tag;
	struct evWait *	next;
} evWait;

typedef struct evWaitList {
	evWait *		first;
	evWait *		last;
	struct evWaitList *	prev;
	struct evWaitList *	next;
} evWaitList;

typedef struct evEvent_p {
	enum {  Accept, File, Stream, Timer, Wait, Free, Null  } type;
	union {
		struct {  evAccept *this;  }			accept;
		struct {  evFile *this; int eventmask;  }	file;
		struct {  evStream *this;  }			stream;
		struct {  evTimer *this;  }			timer;
		struct {  evWait *this;  }			wait;
		struct {  struct evEvent_p *next;  }		free;
		struct {  const void *placeholder;  }		null;
	} u;
} evEvent_p;

#ifdef USE_POLL
typedef struct { 
	void		*ctx;	/* pointer to the evContext_p   */ 
	uint32_t	type;	/* READ, WRITE, EXCEPT, nonblk  */ 
	uint32_t	result;	/* 1 => revents, 0 => events    */ 
} __evEmulMask; 

#define emulMaskInit(ctx, field, ev, lastnext) \
	ctx->field.ctx = ctx; \
	ctx->field.type = ev; \
	ctx->field.result = lastnext; 
  
extern short	*__fd_eventfield(int fd, __evEmulMask *maskp); 
extern short	__poll_event(__evEmulMask *maskp); 
extern void		__fd_clr(int fd, __evEmulMask *maskp); 
extern void		__fd_set(int fd, __evEmulMask *maskp); 

#undef  FD_ZERO 
#define FD_ZERO(maskp) 
  
#undef  FD_SET 
#define FD_SET(fd, maskp) \
	__fd_set(fd, maskp) 

#undef  FD_CLR 
#define FD_CLR(fd, maskp) \
	__fd_clr(fd, maskp) 

#undef  FD_ISSET 
#define FD_ISSET(fd, maskp) \
	((*__fd_eventfield(fd, maskp) & __poll_event(maskp)) != 0) 

#endif /* USE_POLL */

typedef struct {
	/* Global. */
	const evEvent_p	*cur;
	/* Debugging. */
	int		debug;
	FILE		*output;
	/* Connections. */
	evConn		*conns;
	LIST(evAccept)	accepts;
	/* Files. */
	evFile		*files, *fdNext;
#ifndef USE_POLL
	fd_set		rdLast, rdNext;
	fd_set		wrLast, wrNext;
	fd_set		exLast, exNext;
	fd_set		nonblockBefore;
	int		fdMax, fdCount, highestFD;
	evFile		*fdTable[FD_SETSIZE];
#else
	struct pollfd	*pollfds;	/* Allocated as needed  */ 
	evFile		**fdTable;	/* Ditto                */ 
	int		maxnfds;	/* # elements in above  */ 
	int		firstfd;	/* First active fd      */ 
	int		fdMax;		/* Last active fd       */ 
	int		fdCount;	/* # fd:s with I/O      */ 
	int		highestFD;	/* max fd allowed by OS */ 
	__evEmulMask	rdLast, rdNext; 
	__evEmulMask	wrLast, wrNext; 
	__evEmulMask	exLast, exNext; 
	__evEmulMask	nonblockBefore; 
#endif /* USE_POLL */
#ifdef EVENTLIB_TIME_CHECKS
	struct timespec	lastSelectTime;
	int		lastFdCount;
#endif
	/* Streams. */
	evStream	*streams;
	evStream	*strDone, *strLast;
	/* Timers. */
	struct timespec	lastEventTime;
	heap_context	timers;
	/* Waits. */
	evWaitList	*waitLists;
	evWaitList	waitDone;
} evContext_p;

/* eventlib.c */
#define evPrintf __evPrintf
void evPrintf(const evContext_p *ctx, int level, const char *fmt, ...)
     ISC_FORMAT_PRINTF(3, 4);

#ifdef USE_POLL
extern int evPollfdRealloc(evContext_p *ctx, int pollfd_chunk_size, int fd);
#endif /* USE_POLL */

/* ev_timers.c */
#define evCreateTimers __evCreateTimers
heap_context evCreateTimers(const evContext_p *);
#define evDestroyTimers __evDestroyTimers
void evDestroyTimers(const evContext_p *);

/* ev_waits.c */
#define evFreeWait __evFreeWait
evWait *evFreeWait(evContext_p *ctx, evWait *old);

/* Global options */
extern int	__evOptMonoTime;

#endif /*_EVENTLIB_P_H*/
```