Response:
Thinking Process:

1. **Understand the Goal:** The request asks for a comprehensive analysis of the `eventlib.h` header file, focusing on its functionality, relationship to Android, implementation details (especially libc functions), dynamic linking aspects, potential errors, and its integration with the Android framework/NDK.

2. **Initial Analysis of the Header File:**  The header file defines data structures (`evConnID`, `evFileID`, etc.), function pointer types (`evConnFunc`, `evFileFunc`, etc.), macros (`EV_BYTEMASK_SET`, `EV_READ`, etc.), and function prototypes. It clearly outlines an event-driven programming model. The presence of copyright notices from ISC and mentions of NetBSD suggest it's derived from or related to those projects.

3. **Categorize Functionality:**  Group the defined macros and function prototypes into logical categories:
    * **Core Event Management:**  Creating, dispatching, and destroying event contexts (`evCreate`, `evDispatch`, `evDestroy`).
    * **Connection Handling:** Listening, connecting, accepting connections (`evListen`, `evConnect`, `evTryAccept`).
    * **File Descriptor Handling:** Selecting and deselecting file descriptors for events (`evSelectFD`, `evDeselectFD`).
    * **Stream I/O:** Reading and writing data streams (`evRead`, `evWrite`).
    * **Timers:** Setting, clearing, and managing timers (`evSetTimer`, `evClearTimer`).
    * **Waiting and Deferred Actions:**  Waiting for specific conditions and deferring actions (`evWaitFor`, `evDefer`).
    * **Utility Functions:**  Time manipulation, debugging, and options (`evConsTime`, `evSetDebug`, `evSetOption`).

4. **Relate to Android:**  Consider how an event library like this would be useful in Android. Key areas include:
    * **Networking:** Handling network connections (sockets). This aligns with the connection handling functions.
    * **File I/O:** Monitoring file descriptors for readability or writability. This matches the file descriptor handling functions.
    * **Timers:** Implementing timeouts and periodic tasks. This directly relates to the timer functions.
    * **Inter-Process Communication (IPC):** While not explicitly stated, the generic event handling could be adapted for IPC mechanisms.

5. **Implementation of libc Functions:**  Recognize that this header *defines interfaces*. The actual *implementation* resides in corresponding `.c` files (e.g., `ev_connects.c`, `ev_timers.c`). The header uses preprocessor macros (`#define evCreate __evCreate`) to potentially rename functions or provide internal implementations. The question asks about libc function implementation. The header itself doesn't show the *implementation* of libc functions, but it *uses* libc functions (like those defined in `<sys/types.h>`, `<sys/time.h>`, `<stdio.h>`). Explain that the implementation details are in the source files and these functions likely wrap or interact with lower-level system calls.

6. **Dynamic Linker:** The header doesn't directly expose dynamic linker functionality. However, the fact it's part of `bionic` (Android's C library) means its compiled code will be linked. Discuss how the dynamic linker resolves symbols at runtime, provide a basic SO layout, and explain the linking process. Emphasize that the header itself doesn't contain the dynamic linking logic.

7. **Logical Reasoning (Hypothetical):** Create simple scenarios to illustrate how some functions might be used. For example, setting a timer and having a callback function executed.

8. **Common Usage Errors:** Think about mistakes developers might make when using an event library: forgetting to initialize the context, using invalid file descriptors, incorrect timer values, etc.

9. **Android Framework/NDK Integration:** Explain how an Android app (using the NDK) might eventually call into these `eventlib` functions. This involves a chain of calls, starting from Java/Kotlin code, potentially going through framework services, down to native libraries, and finally into bionic's libc.

10. **Frida Hooking:**  Demonstrate how Frida could be used to intercept calls to functions defined in the header. Provide a basic JavaScript example targeting a specific function.

11. **Structure and Language:** Organize the information clearly with headings and subheadings. Use precise and accurate Chinese terminology. Ensure all parts of the request are addressed. Review and refine the language for clarity and correctness.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Perhaps dive deeply into the *potential* underlying system calls.
* **Correction:**  The header file doesn't *reveal* the exact system calls used. Focus on the *intended functionality* and how it relates to common system-level operations.
* **Initial Thought:**  Provide very complex dynamic linking scenarios.
* **Correction:**  Keep the dynamic linking explanation concise and focused on the core concepts relevant to this header file's context.
* **Initial Thought:**  Overcomplicate the Frida example.
* **Correction:**  Provide a simple, illustrative Frida hook to demonstrate the concept.

By following this thought process, breaking down the request into manageable parts, and constantly refining the approach, a comprehensive and accurate answer can be constructed.


这是一个位于 Android Bionic C 库中的头文件，来源于 NetBSD 的 `libc` 库。它的主要目的是定义一个事件库（`eventlib`）的接口，用于实现基于事件驱动的编程模型。

**它的功能:**

`eventlib` 提供了一套用于处理各种事件的抽象，允许程序异步地处理 I/O 操作、定时器以及其他类型的事件。其主要功能可以归纳为：

1. **事件上下文管理:**
   - `evCreate`: 创建一个事件上下文 (`evContext`)，它是管理所有事件的基础。
   - `evDestroy`: 销毁一个事件上下文，释放相关资源。

2. **连接管理 (用于网络编程):**
   - `evListen`: 监听指定端口的连接请求。
   - `evConnect`: 发起连接到指定地址。
   - `evTryAccept`: 尝试接受一个连接。
   - `evCancelConn`: 取消一个连接操作。
   - `evHold`/`evUnhold`: 暂停/恢复连接事件的处理。

3. **文件描述符事件管理:**
   - `evSelectFD`: 监控一个文件描述符的可读、可写或异常事件。
   - `evDeselectFD`: 停止监控一个文件描述符的事件。

4. **流式 I/O 操作:**
   - `evWrite`: 异步写入数据到文件描述符。
   - `evRead`: 异步从文件描述符读取数据。
   - `evTimeRW`/`evUntimeRW`: 为读写操作设置/取消超时。
   - `evCancelRW`: 取消一个进行中的读写操作。

5. **定时器管理:**
   - `evSetTimer`: 设置一个定时器，在指定时间后触发回调函数。
   - `evClearTimer`: 取消一个定时器。
   - `evConfigTimer`: 配置定时器参数。
   - `evResetTimer`: 重置定时器。
   - `evSetIdleTimer`/`evClearIdleTimer`/`evResetIdleTimer`/`evTouchIdleTimer`: 管理空闲定时器，用于在一段时间没有事件发生时触发。

6. **等待条件和延迟执行:**
   - `evWaitFor`: 等待特定条件满足时触发回调。
   - `evDo`: 立即执行与特定条件相关的回调。
   - `evUnwait`: 取消等待特定条件。
   - `evDefer`: 延迟执行一个回调函数。

7. **事件循环:**
   - `evMainLoop`: 进入主事件循环，监听并分发事件。
   - `evGetNext`: 获取下一个发生的事件。
   - `evDispatch`: 分发一个事件到相应的处理函数。
   - `evDrop`: 丢弃一个事件。

8. **其他工具函数:**
   - `evSetDebug`: 设置调试级别和输出文件。
   - `evHighestFD`: 获取当前监控的最高文件描述符。
   - `evGetOption`/`evSetOption`: 获取/设置事件库选项。
   - 时间相关的操作函数，如 `evConsTime`, `evAddTime`, `evSubTime`, `evCmpTime` 等。

**与 Android 功能的关系及举例说明:**

`eventlib` 提供的事件驱动模型与 Android 的异步处理机制密切相关。虽然 Android Framework 层面更多地使用 Looper、Handler、AsyncTask 等高级抽象，但在底层 Native 层，特别是网络和 I/O 操作中，类似 `eventlib` 的机制被广泛使用。

**举例说明:**

* **网络连接:** Android 的 Socket 实现底层可能使用类似 `evListen`、`evConnect` 和相关的回调函数来处理网络事件，例如新的连接到达或数据可读。当一个 Java 层的 `ServerSocket` 接收到连接请求时，底层的 native 代码可能会调用 `evListen` 注册一个监听事件，当有新的连接到达时，`eventlib` 会调用预先注册的回调函数，从而通知上层有新连接。

* **文件 I/O:**  在进行非阻塞的文件 I/O 操作时，Android 的 native 代码可以使用 `evSelectFD` 来监控文件描述符的状态。例如，当一个 native 的文件读取操作设置为非阻塞时，可以使用 `evSelectFD` 监控该文件描述符是否可读，并在可读时通过回调函数通知读取数据。

* **定时器:**  Android 的 `AlarmManager` 或 `Handler` 的 `postDelayed` 方法在底层实现中，可能利用类似 `evSetTimer` 的机制来设置定时器，到期后执行相应的操作。

**详细解释 libc 函数的实现:**

这个头文件 `eventlib.h` 自身**不包含 libc 函数的实现**，它只是定义了事件库的接口。真正的实现代码位于同目录下的 `.c` 文件中（例如 `ev_connects.c`, `ev_files.c`, `ev_timers.c` 等）。

这些实现文件中会调用底层的系统调用 (system calls)，这些系统调用才是 libc 提供的功能。例如：

* `evListen` 的实现最终会调用 `socket()`, `bind()`, `listen()` 系统调用来创建和监听 socket。
* `evConnect` 的实现会调用 `socket()` 和 `connect()` 系统调用来建立连接。
* `evSelectFD` 的实现很可能基于 `poll()` 或 `epoll()` 系统调用，用于多路复用 I/O。
* 定时器功能可能使用 `timerfd_create()`, `timerfd_settime()` 等 Linux 特有的定时器接口，或者更传统的 `select()`/`poll()` 加上时间计算。

**涉及 dynamic linker 的功能、SO 布局样本和链接处理过程:**

`eventlib.h` 本身不直接涉及 dynamic linker 的功能，但作为 Bionic 的一部分，其编译产出的代码会被链接到其他共享库或可执行文件中。

**SO 布局样本:**

假设 `eventlib` 的实现被编译到一个名为 `libevent.so` 的共享库中，其布局可能如下：

```
libevent.so:
  .text         # 包含 evCreate, evListen 等函数的机器码
  .data         # 包含全局变量和已初始化的静态变量
  .bss          # 包含未初始化的全局变量和静态变量
  .rodata       # 包含只读数据，例如字符串常量
  .dynsym       # 动态符号表，列出导出的符号
  .dynstr       # 动态字符串表，存储符号名称
  .plt          # 程序链接表，用于延迟绑定
  .got          # 全局偏移表，用于访问外部符号
  ... 其他段 ...
```

**链接的处理过程:**

1. **编译时:** 当其他模块（例如 Android Framework 的 native 组件或 NDK 开发的库）使用 `eventlib.h` 中定义的函数时，编译器会生成对这些函数的未解析引用。

2. **链接时:** 链接器（在 Android 中通常是 `lld`）会将这些未解析的引用与 `libevent.so` 中导出的符号进行匹配。链接器会记录这些符号的地址需要在运行时进行解析。

3. **运行时:** 当程序加载时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库，包括 `libevent.so`。Dynamic linker 会解析 `.plt` 和 `.got` 中的条目，将外部函数的地址填充到 `.got` 中。当程序首次调用 `evCreate` 等函数时，会通过 `.plt` 跳转到 `.got` 中对应的条目，dynamic linker 会找到 `evCreate` 在 `libevent.so` 中的实际地址并填充到 `.got`，后续的调用将直接跳转到该地址，这就是**延迟绑定**。

**假设输入与输出 (逻辑推理):**

假设一个简单的场景：使用 `eventlib` 监听一个端口并在有连接到来时打印消息。

**假设输入:**

* 调用 `evCreate` 创建一个事件上下文。
* 调用 `evListen` 监听端口 8080，并注册一个回调函数 `on_connect`。
* 客户端尝试连接到该端口。

**输出:**

* 当客户端连接成功时，`eventlib` 的事件循环检测到连接事件。
* `eventlib` 调用事先注册的 `on_connect` 回调函数，并将连接信息作为参数传递给它。
* `on_connect` 函数打印一条消息，例如 "New connection accepted"。

**用户或编程常见的使用错误:**

1. **未初始化事件上下文:** 在调用任何 `ev` 开头的函数之前，忘记调用 `evCreate` 初始化事件上下文。
   ```c
   evContext ctx;
   // 忘记调用 evCreate(&ctx);
   evListen(&ctx, ...); // 错误使用，可能导致崩溃或未定义行为
   ```

2. **文件描述符错误:** 传递无效的文件描述符给 `evSelectFD`、`evWrite` 或 `evRead` 等函数。
   ```c
   int fd = open("nonexistent_file", O_RDONLY);
   if (fd == -1) {
       perror("open");
       // 错误：应该处理错误，而不是继续使用无效的 fd
   }
   evSelectFD(ctx, fd, EV_READ, ...);
   ```

3. **回调函数未正确处理事件:**  在回调函数中没有正确处理接收到的事件，例如没有读取数据导致缓冲区满，或者没有关闭连接导致资源泄漏。

4. **定时器设置不当:**  设置了过短或过长的定时器间隔，或者在定时器回调函数中执行了耗时操作，阻塞了事件循环。

5. **忘记取消注册的事件:**  使用 `evSelectFD` 或 `evSetTimer` 注册了事件后，在不再需要时忘记调用 `evDeselectFD` 或 `evClearTimer`，可能导致资源泄漏或意外的回调触发。

**Android Framework 或 NDK 如何到达这里，以及 Frida hook 示例:**

1. **Android Framework:**  Android Framework 的某些底层组件（尤其是涉及到网络和 I/O 的部分）会调用 Bionic 提供的 C 库函数。例如，`java.net.Socket` 的实现最终会调用 native 代码，这些 native 代码可能会使用到类似 `eventlib` 提供的功能，尽管可能不是直接使用这些函数，而是通过更高层的抽象接口。

2. **NDK:**  使用 NDK 开发的应用程序可以直接调用 Bionic 提供的 C 库函数。如果 NDK 开发者想要实现底层的网络或 I/O 操作，他们可能会使用到与 `eventlib` 功能类似的函数，甚至有可能直接使用这些函数（如果它们是 Bionic 中公开的接口）。

**步骤示例 (NDK):**

一个 NDK 应用程序可能通过以下步骤到达 `eventlib` 的相关函数：

1. **Java 代码发起请求:**  Java 代码创建一个 Socket 或进行文件操作。
2. **Framework 调用 Native 代码:**  Framework 将请求传递给相应的 native 实现。
3. **Native 代码调用 Bionic 函数:**  Native 代码（例如 `libnetd.so` 或应用自己的 native 库）调用 Bionic 的网络或 I/O 相关函数。
4. **Bionic 函数使用 `eventlib` 功能:**  Bionic 的网络或 I/O 函数的实现内部可能使用了 `eventlib` 提供的机制来处理异步事件。

**Frida Hook 示例:**

假设你想 hook `evListen` 函数来观察其调用情况。

```javascript
if (Process.platform === 'android') {
  const libevent = Module.findExportByName("libc.so", "__evListen"); // 假设编译后的函数名为 __evListen

  if (libevent) {
    Interceptor.attach(libevent, {
      onEnter: function (args) {
        console.log("[+] evListen called");
        console.log("    Context:", args[0]);
        console.log("    Socket FD:", args[1]);
        console.log("    Backlog:", args[2].toInt32());
        console.log("    Callback Function:", args[3]);
        console.log("    User Data:", args[4]);
        console.log("    ConnID:", args[5]);
      },
      onLeave: function (retval) {
        console.log("[+] evListen returned:", retval);
      }
    });
  } else {
    console.log("[-] evListen not found in libc.so");
  }
}
```

**解释 Frida 代码:**

1. `Process.platform === 'android'`: 确保这段代码只在 Android 平台上执行。
2. `Module.findExportByName("libc.so", "__evListen")`: 在 `libc.so` 中查找名为 `__evListen` 的导出函数。由于头文件中使用了 `#define evListen __evListen`，实际编译后的符号名可能是 `__evListen`。
3. `Interceptor.attach(libevent, ...)`:  使用 Frida 的 `Interceptor` 拦截对 `__evListen` 函数的调用。
4. `onEnter`: 在函数调用之前执行，可以访问函数的参数 (`args`)。
5. `onLeave`: 在函数调用之后执行，可以访问函数的返回值 (`retval`).
6. `console.log(...)`: 打印函数的参数和返回值，用于调试。

通过这个 Frida 脚本，你可以在 Android 设备上运行目标进程，观察何时调用了 `evListen` 函数，以及传递了哪些参数，从而帮助理解 Android 系统或 NDK 应用如何使用底层的事件处理机制。

总结来说，`eventlib.h` 定义了一个底层的事件驱动框架，为 Bionic C 库提供了处理异步事件的能力，这对于构建高效的网络和 I/O 操作至关重要，并在 Android 系统的底层组件和 NDK 开发中扮演着重要角色。

Prompt: 
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/include/isc/eventlib.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: eventlib.h,v 1.3 2009/04/12 17:07:16 christos Exp $	*/

/*
 * Copyright (C) 2004, 2005, 2008  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1995-1999, 2001, 2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* eventlib.h - exported interfaces for eventlib
 * vix 09sep95 [initial]
 *
 * Id: eventlib.h,v 1.7 2008/11/14 02:36:51 marka Exp
 */

#ifndef _EVENTLIB_H
#define _EVENTLIB_H

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <stdio.h>

#ifndef __P
# define __EVENTLIB_P_DEFINED
# ifdef __STDC__
#  define __P(x) x
# else
#  define __P(x) ()
# endif
#endif

/* In the absence of branded types... */
typedef struct { void *opaque; } evConnID;
typedef struct { void *opaque; } evFileID;
typedef struct { void *opaque; } evStreamID;
typedef struct { void *opaque; } evTimerID;
typedef struct { void *opaque; } evWaitID;
typedef struct { void *opaque; } evContext;
typedef struct { void *opaque; } evEvent;

#define	evInitID(id) ((id)->opaque = NULL)
#define	evTestID(id) ((id).opaque != NULL)

typedef void (*evConnFunc)__P((evContext, void *, int, const void *, int,
			       const void *, int));
typedef void (*evFileFunc)__P((evContext, void *, int, int));
typedef	void (*evStreamFunc)__P((evContext, void *, int, int));
typedef void (*evTimerFunc)__P((evContext, void *,
				struct timespec, struct timespec));
typedef	void (*evWaitFunc)__P((evContext, void *, const void *));

typedef	struct { unsigned char mask[256/8]; } evByteMask;
#define	EV_BYTEMASK_BYTE(b) ((b) / 8)
#define	EV_BYTEMASK_MASK(b) (1 << ((b) % 8))
#define	EV_BYTEMASK_SET(bm, b) \
	((bm).mask[EV_BYTEMASK_BYTE(b)] |= EV_BYTEMASK_MASK(b))
#define	EV_BYTEMASK_CLR(bm, b) \
	((bm).mask[EV_BYTEMASK_BYTE(b)] &= ~EV_BYTEMASK_MASK(b))
#define	EV_BYTEMASK_TST(bm, b) \
	((bm).mask[EV_BYTEMASK_BYTE(b)] & EV_BYTEMASK_MASK(b))

#define	EV_POLL		1
#define	EV_WAIT		2
#define	EV_NULL		4

#define	EV_READ		1
#define	EV_WRITE	2
#define	EV_EXCEPT	4

#define EV_WASNONBLOCKING 8	/* Internal library use. */

/* eventlib.c */
#define evCreate	__evCreate
#define evSetDebug	__evSetDebug
#define evDestroy	__evDestroy
#define evGetNext	__evGetNext
#define evDispatch	__evDispatch
#define evDrop		__evDrop
#define evMainLoop	__evMainLoop
#define evHighestFD	__evHighestFD
#define evGetOption	__evGetOption
#define evSetOption	__evSetOption

int  evCreate __P((evContext *));
void evSetDebug __P((evContext, int, FILE *));
int  evDestroy __P((evContext));
int  evGetNext __P((evContext, evEvent *, int));
int  evDispatch __P((evContext, evEvent));
void evDrop __P((evContext, evEvent));
int  evMainLoop __P((evContext));
int  evHighestFD __P((evContext));
int  evGetOption __P((evContext *, const char *, int *));
int  evSetOption __P((evContext *, const char *, int));

/* ev_connects.c */
#define evListen	__evListen
#define evConnect	__evConnect
#define evCancelConn	__evCancelConn
#define evHold		__evHold
#define evUnhold	__evUnhold
#define evTryAccept	__evTryAccept

int evListen __P((evContext, int, int, evConnFunc, void *, evConnID *));
int evConnect __P((evContext, int, const void *, int,
		   evConnFunc, void *, evConnID *));
int evCancelConn __P((evContext, evConnID));
int evHold __P((evContext, evConnID));
int evUnhold __P((evContext, evConnID));
int evTryAccept __P((evContext, evConnID, int *));

/* ev_files.c */
#define evSelectFD	__evSelectFD
#define evDeselectFD	__evDeselectFD

int evSelectFD __P((evContext, int, int, evFileFunc, void *, evFileID *));
int evDeselectFD __P((evContext, evFileID));

/* ev_streams.c */
#define evConsIovec	__evConsIovec
#define evWrite		__evWrite
#define evRead		__evRead
#define evTimeRW	__evTimeRW
#define evUntimeRW	__evUntimeRW
#define	evCancelRW	__evCancelRW

struct iovec evConsIovec __P((void *, size_t));
int evWrite __P((evContext, int, const struct iovec *, int,
		 evStreamFunc func, void *, evStreamID *));
int evRead __P((evContext, int, const struct iovec *, int,
		evStreamFunc func, void *, evStreamID *));
int evTimeRW __P((evContext, evStreamID, evTimerID timer));
int evUntimeRW __P((evContext, evStreamID));
int evCancelRW __P((evContext, evStreamID));

/* ev_timers.c */
#define evConsTime	__evConsTime
#define evAddTime	__evAddTime
#define evSubTime	__evSubTime
#define evCmpTime	__evCmpTime
#define	evTimeSpec	__evTimeSpec
#define	evTimeVal	__evTimeVal

#define evNowTime		__evNowTime
#define evUTCTime		__evUTCTime
#define evLastEventTime		__evLastEventTime
#define evSetTimer		__evSetTimer
#define evClearTimer		__evClearTimer
#define evConfigTimer		__evConfigTimer
#define evResetTimer		__evResetTimer
#define evSetIdleTimer		__evSetIdleTimer
#define evClearIdleTimer	__evClearIdleTimer
#define evResetIdleTimer	__evResetIdleTimer
#define evTouchIdleTimer	__evTouchIdleTimer

struct timespec evConsTime __P((time_t sec, long nsec));
struct timespec evAddTime __P((struct timespec, struct timespec));
struct timespec evSubTime __P((struct timespec, struct timespec));
struct timespec evNowTime __P((void));
struct timespec evUTCTime __P((void));
struct timespec evLastEventTime __P((evContext));
struct timespec evTimeSpec __P((struct timeval));
struct timeval evTimeVal __P((struct timespec));
int evCmpTime __P((struct timespec, struct timespec));
int evSetTimer __P((evContext, evTimerFunc, void *, struct timespec,
		    struct timespec, evTimerID *));
int evClearTimer __P((evContext, evTimerID));
int evConfigTimer __P((evContext, evTimerID, const char *param,
		      int value));
int evResetTimer __P((evContext, evTimerID, evTimerFunc, void *,
		      struct timespec, struct timespec));
int evSetIdleTimer __P((evContext, evTimerFunc, void *, struct timespec,
			evTimerID *));
int evClearIdleTimer __P((evContext, evTimerID));
int evResetIdleTimer __P((evContext, evTimerID, evTimerFunc, void *,
			  struct timespec));
int evTouchIdleTimer __P((evContext, evTimerID));

/* ev_waits.c */
#define evWaitFor	__evWaitFor
#define evDo		__evDo
#define evUnwait	__evUnwait
#define evDefer		__evDefer

int evWaitFor __P((evContext, const void *, evWaitFunc, void *, evWaitID *));
int evDo __P((evContext, const void *));
int evUnwait __P((evContext, evWaitID));
int evDefer __P((evContext, evWaitFunc, void *));

#ifdef __EVENTLIB_P_DEFINED
# undef __P
#endif

#endif /*_EVENTLIB_H*/

/*! \file */

"""

```