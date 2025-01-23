Response:
Let's break down the thought process for analyzing the `ev_streams.c` file.

**1. Initial Understanding of the Context:**

The first crucial step is understanding the provided information:

* **File Location:** `bionic/libc/upstream-netbsd/lib/libc/isc/ev_streams.c`
* **Library:** Part of Bionic, Android's C library.
* **Origin:**  Upstream from NetBSD. This immediately suggests the code might not be entirely Android-specific but rather a general utility that Android has adopted.
* **Purpose (from comments):**  "implement asynch stream file IO for the eventlib". This hints at event-driven, non-blocking I/O operations.

**2. High-Level Functionality Identification (Skimming the Code):**

A quick scan reveals several key functions:

* `evConsIovec`:  Likely for constructing `iovec` structures.
* `evWrite`, `evRead`:  Functions for asynchronous write and read operations.
* `evTimeRW`, `evUntimeRW`: Functions for associating/disassociating timers with read/write operations.
* `evCancelRW`:  For canceling ongoing read/write operations.
* `copyvec`:  Helper function to copy `iovec` data.
* `consume`:  Helper function to track progress in the I/O operation.
* `done`:  Helper function called when an I/O operation is complete.
* `writable`, `readable`:  Callback functions triggered when a file descriptor becomes writable or readable.

**3. Detailed Analysis of Each Function (Focusing on Core Logic):**

Now, go through each function, line by line, understanding its role and how it interacts with other parts of the code.

* **`evConsIovec`:**  Simple structure initialization. Not much complexity here. The `memset` with `0xf5` is a debugging technique to catch uninitialized memory.

* **`evWrite` and `evRead` (Similar Logic):**
    * **Memory Allocation:** `OKNEW(new)` allocates memory for an `evStream` structure.
    * **Initialization:**  Sets up function pointers (`func`), user data (`uap`), file descriptor (`fd`), and flags.
    * **`evSelectFD`:** This is the *key* function for asynchronous I/O. It registers the file descriptor for notification (write or read readiness) and associates it with a callback function (`writable` or `readable`). This strongly points to the use of `epoll` or `poll` under the hood.
    * **`copyvec`:** Copies the provided `iovec` array for internal use.
    * **Linked List Management:** The code manipulates a linked list (`ctx->streams`) to keep track of active stream operations. This is crucial for managing multiple concurrent asynchronous operations.
    * **Error Handling:**  Includes basic error handling (`goto free`).

* **`evTimeRW` and `evUntimeRW`:**  Manage associating a timer with a stream. The `EV_STR_TIMEROK` flag is used to track this.

* **`evCancelRW`:**  Handles canceling an operation. This involves:
    * **Unlinking from Lists:** Removing the `evStream` from both the active streams list (`ctx->streams`) and the done list (`ctx->strDone`).
    * **Deselecting FD:** `evDeselectFD` removes the file descriptor from the monitoring mechanism.
    * **Memory Cleanup:**  Frees allocated memory.

* **`copyvec`:** Allocates memory and copies the `iovec` data.

* **`consume`:**  Updates the `evStream` structure to reflect the progress of the I/O operation by adjusting the `iovCur`, `iovCurCount`, and `ioDone` members.

* **`done`:**  Called when an I/O operation is complete (either successfully or with an error). It:
    * **Moves to Done List:** Adds the `evStream` to a separate linked list of completed operations (`ctx->strDone`).
    * **Deselects FD:** Stops monitoring the file descriptor.

* **`writable` and `readable` (Callback Functions):**
    * **Called by `evDispatch()`:** This indicates an event loop is involved.
    * **Performs I/O:** Uses `writev` or `readv` to perform the actual I/O.
    * **Timer Handling:**  Calls `evTouchIdleTimer` if a timer is associated.
    * **Error Handling:** Checks the return value of `writev`/`readv` and updates the `evStream` state accordingly.
    * **Calls `done`:**  Transitions the stream to the completed state.

**4. Connecting to Android Functionality:**

* **Event Loop:** The core concept of `eventlib` and `ev_streams.c` relies on an event loop. Android's `Looper` and `Handler` mechanism in Java (and the underlying native implementation) serve a similar purpose for handling asynchronous events. While not a direct 1:1 mapping, the *concept* is the same.
* **Network Operations:**  Asynchronous I/O is fundamental for efficient network communication. Android's networking stack likely uses underlying mechanisms similar to what `ev_streams.c` provides.
* **File Operations:** While less common for direct user-level file I/O on Android (compared to network I/O), the underlying OS primitives can be used with asynchronous mechanisms.

**5. Dynamic Linker Aspects (Limited in this File):**

This specific file doesn't have explicit dynamic linker code. However, its presence within `bionic/libc` means it *will* be part of the `libc.so` library. The dynamic linker will handle:

* **Loading `libc.so`:** When an Android process starts, the dynamic linker loads `libc.so`.
* **Resolving Symbols:**  Functions like `evWrite`, `evRead`, etc., will be resolved to their addresses within `libc.so`.

**6. Common User Errors:**

* **Forgetting to Handle Completion:** If the callback function (`evStreamFunc`) isn't properly implemented, the application might not process the results of the I/O operation.
* **Incorrect `iovec` Setup:** Providing invalid pointers or lengths in the `iovec` structure will lead to errors.
* **Not Canceling Operations:**  Failing to call `evCancelRW` when an operation is no longer needed can lead to resource leaks.

**7. Android Framework/NDK Path and Frida Hooking:**

* **Framework:**  The Android Framework often uses higher-level abstractions for I/O (e.g., `Socket`, `FileInputStream`). However, these abstractions ultimately rely on native system calls. It's less likely you'd directly interact with `ev_streams.c` from the Java framework.
* **NDK:**  NDK developers have more direct access to C/C++ libraries. They *could* potentially use the underlying mechanisms of `eventlib` (if exposed) for asynchronous I/O, although it's more common to use standard POSIX functions directly with non-blocking flags and `epoll`/`poll`.

**Frida Hooking Strategy:**

To hook into this, you'd target functions like `evWrite` or `evRead`. You'd need to find the base address of `libc.so` in the target process and then calculate the offset of these functions.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This looks like standard I/O."
* **Correction:**  "Wait, the `evSelectFD` and callback functions indicate it's *asynchronous* I/O."
* **Initial thought:** "This is all Android-specific."
* **Correction:** "The NetBSD copyright and RCS ID indicate it's upstream code. Android is using a pre-existing library."
* **Considering dynamic linking:** "While this file doesn't *contain* dynamic linking code, its presence in `libc` makes it subject to the dynamic linker's processes."

By following this methodical approach, breaking down the code into smaller parts, and relating it back to the given context (Android, Bionic), we can arrive at a comprehensive understanding of the `ev_streams.c` file's functionality and its place within the Android ecosystem.
好的，让我们详细分析一下 `bionic/libc/upstream-netbsd/lib/libc/isc/ev_streams.c` 这个文件。

**功能概述**

`ev_streams.c` 文件实现了用于 `eventlib` 的异步流式文件 I/O 功能。 `eventlib` 是一个事件库，用于管理文件描述符上的事件，例如可读、可写以及超时。  这个文件提供了一种非阻塞的方式来执行读写操作，允许程序在等待 I/O 完成时执行其他任务。

主要功能可以概括为：

1. **异步写入 (evWrite):** 允许程序发起一个非阻塞的写操作，并将数据写入到指定的文件描述符。当文件描述符可写时，会调用用户指定的回调函数。
2. **异步读取 (evRead):** 允许程序发起一个非阻塞的读操作，并从指定的文件描述符读取数据。当文件描述符可读时，会调用用户指定的回调函数。
3. **关联定时器 (evTimeRW):** 允许将一个现有的定时器与一个异步读写操作关联起来。如果在 I/O 操作完成之前定时器到期，可以触发相应的超时处理。
4. **取消关联定时器 (evUntimeRW):**  取消异步读写操作与定时器的关联。
5. **取消读写操作 (evCancelRW):** 允许程序取消正在进行的异步读写操作。

**与 Android 功能的关系**

虽然这个文件来源于 NetBSD，但它作为 Bionic 的一部分，直接服务于 Android 的底层功能。异步 I/O 是构建高性能、响应迅速的应用程序的关键技术。

**举例说明:**

* **网络编程:** Android 的网络栈在底层可能会使用类似的异步 I/O 机制来处理网络连接的读写操作。例如，当一个应用程序通过 socket 发送或接收数据时，底层的实现可能会使用非阻塞 I/O 和事件循环来管理多个连接，而不会阻塞主线程。虽然 Android Framework 提供了 `Socket` 类等更高级的抽象，但这些抽象在 Native 层可能就使用了类似 `ev_streams.c` 提供的功能。

* **文件操作:**  在某些场景下，例如处理大文件或者在后台进行文件读写，异步 I/O 可以提高效率。虽然 Android SDK 通常提供同步的文件操作 API，但在 Native 层，开发者可以使用这些底层的异步 I/O 功能。

**libc 函数功能实现详解**

`ev_streams.c` 中定义了一些自己的数据结构和函数，但它依赖于一些底层的 libc 函数，主要是与 I/O 和事件处理相关的：

* **`writev(int fd, const struct iovec *iov, int iovcnt)` 和 `readv(int fd, const struct iovec *iov, int iovcnt)`:**
    * **功能:** 这两个函数用于执行分散/聚集 I/O。 `writev` 从 `iov` 数组指定的多个缓冲区中读取数据并写入到文件描述符 `fd` 中。 `readv` 从文件描述符 `fd` 中读取数据并分散存储到 `iov` 数组指定的多个缓冲区中。
    * **实现:**  这两个函数是操作系统提供的系统调用的封装。它们直接与内核交互，执行实际的 I/O 操作。内核会管理缓冲、设备驱动等底层细节。
    * **在 `ev_streams.c` 中的使用:** `writable` 函数中调用 `writev` 将数据写入文件描述符；`readable` 函数中调用 `readv` 从文件描述符读取数据。

* **`memset(void *s, int c, size_t n)`:**
    * **功能:** 将 `s` 指向的内存块的前 `n` 个字节设置为值 `c`。
    * **实现:**  这是一个标准的 C 库函数，通常由汇编语言或编译器内建函数高效实现。它会逐字节地填充内存。
    * **在 `ev_streams.c` 中的使用:** `evConsIovec` 函数中使用 `memset` 初始化 `iovec` 结构体。

* **`errno`:**
    * **功能:**  `errno` 是一个全局变量，用于指示最近一次系统调用或库函数调用失败的原因。
    * **实现:**  `errno` 通常是一个线程局部变量，由操作系统维护。当系统调用失败时，内核会设置 `errno` 的值。
    * **在 `ev_streams.c` 中的使用:**  `evWrite` 和 `evRead` 在注册事件失败时会保存当前的 `errno` 值，并在返回错误前恢复它。`writable` 和 `readable` 在 `writev` 或 `readv` 返回错误时会检查 `errno` 以判断错误类型。

* **内存管理函数 (`memget`, `memput`, `FREE`):**
    * **功能:**  这些函数是 `eventlib` 内部使用的内存管理函数，类似于 `malloc` 和 `free`。
    * **实现:**  具体的实现细节没有在这个文件中，但通常会涉及分配和释放内存块，并可能包含一些调试或统计功能。
    * **在 `ev_streams.c` 中的使用:** 用于分配和释放 `evStream` 结构体以及 `iovec` 数组的内存。

* **`evSelectFD(evContext opaqueCtx, int fd, int evmask, void (*handler)(evContext, void *, int, int), void *uap, evFileID *id)` 和 `evDeselectFD(evContext opaqueCtx, evFileID id)`:**
    * **功能:** 这两个函数是 `eventlib` 提供的，用于注册和取消对文件描述符事件的监听。 `evSelectFD` 将文件描述符 `fd` 添加到事件监听中，并指定当 `evmask` 指定的事件发生时（例如 `EV_READ` 或 `EV_WRITE`），调用 `handler` 函数。 `evDeselectFD` 则取消对文件描述符的监听。
    * **实现:**  `eventlib` 的实现细节没有在这个文件中，但它很可能基于操作系统的 I/O 多路复用机制，例如 `select`、`poll` 或 `epoll`。
    * **在 `ev_streams.c` 中的使用:** `evWrite` 和 `evRead` 使用 `evSelectFD` 注册文件描述符的写或读事件，并指定 `writable` 或 `readable` 作为回调函数。 `evCancelRW` 和 `done` 函数使用 `evDeselectFD` 取消事件监听。

* **`evTouchIdleTimer(evContext opaqueCtx, evTimerID timer)`:**
    * **功能:**  `eventlib` 提供的函数，用于重置一个空闲定时器。当与 I/O 操作关联的定时器是空闲定时器时，每次成功进行 I/O 操作都会调用此函数来延长定时器的过期时间。
    * **实现:** 具体实现依赖于 `eventlib` 的定时器管理机制。
    * **在 `ev_streams.c` 中的使用:** `writable` 和 `readable` 函数在成功读写数据后，如果设置了 `EV_STR_TIMEROK` 标志，则会调用 `evTouchIdleTimer`。

**涉及 dynamic linker 的功能**

这个文件本身并没有直接涉及 dynamic linker 的功能。它定义的函数会被编译成静态库或共享库（在 Android 上是 `libc.so`），而 dynamic linker 的工作是在程序运行时加载这些库，并将程序中调用的符号（函数名、变量名等）解析到库中的实际地址。

**so 布局样本和链接处理过程:**

假设 `ev_streams.c` 编译进了 `libc.so`。一个简化的 `libc.so` 布局可能如下：

```
libc.so:
    .text:
        evConsIovec:  <代码地址>
        evWrite:      <代码地址>
        evRead:       <代码地址>
        ...
        writable:     <代码地址>
        readable:     <代码地址>
        ...
    .data:
        ...
    .bss:
        ...
    .dynsym:
        evConsIovec
        evWrite
        evRead
        ...
        writable
        readable
        ...
```

**链接处理过程:**

1. **编译时链接:** 当编译一个使用 `evWrite` 或 `evRead` 等函数的程序时，编译器会在目标文件中生成对这些符号的未解析引用。
2. **加载时链接:** 当 Android 系统启动程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被首先加载。
3. **库加载:** Dynamic linker 会加载程序依赖的共享库，包括 `libc.so`。
4. **符号解析:** Dynamic linker 会遍历程序的未解析符号表，并在加载的共享库的符号表 (`.dynsym`) 中查找匹配的符号。
5. **重定位:** 找到匹配的符号后，dynamic linker 会将程序中对这些符号的引用重定向到 `libc.so` 中对应的函数地址。例如，程序中调用 `evWrite` 的指令会被修改为跳转到 `libc.so` 中 `evWrite` 函数的 `<代码地址>`。

**逻辑推理 (假设输入与输出)**

以 `evWrite` 函数为例，假设我们有以下输入：

* `opaqueCtx`:  一个有效的 `evContext` 指针。
* `fd`:  一个打开的、可写的 socket 文件描述符。
* `iov`:  一个 `iovec` 结构体数组，描述要写入的数据缓冲区。
* `iocnt`:  `iov` 数组的元素个数。
* `func`:  一个回调函数，当写入完成（或出错）时会被调用。
* `uap`:  用户自定义数据，会传递给回调函数。
* `id`:  一个指向 `evStreamID` 的指针，用于接收新创建的流 ID。

**假设输出:**

* **成功:** `evWrite` 返回 0，并且：
    * 创建一个新的 `evStream` 结构体，并将其添加到 `evContext` 的流列表中。
    * 通过 `evSelectFD` 注册了文件描述符 `fd` 的写事件，回调函数设置为 `writable`，用户数据设置为新创建的 `evStream` 结构体指针。
    * 如果 `id` 不为空，则 `id->opaque` 会被设置为新创建的 `evStream` 结构体指针。
    * 当 socket 变得可写时，`writable` 函数会被 `eventlib` 的事件循环调用，该函数会调用 `writev` 尝试写入数据。
    * 写入完成后，`done` 函数会被调用，并将 `evStream` 移动到完成列表，并调用用户提供的回调函数 `func`。
* **失败:** `evWrite` 返回 -1，并且 `errno` 会被设置为相应的错误代码（例如 `ENOMEM` 如果内存分配失败，或者 `其它 evSelectFD` 返回的错误）。

**用户或编程常见的使用错误**

1. **忘记处理回调:** 用户必须提供一个回调函数 (`evStreamFunc`)，并在回调函数中处理 I/O 操作的结果（成功、失败、读取到的数据等）。忘记处理回调会导致程序无法感知 I/O 操作的完成。

2. **`iovec` 设置错误:** `iovec` 结构体中的 `iov_base` 指针必须指向有效的内存区域，`iov_len` 必须是缓冲区的大小。提供无效的指针或长度会导致 `writev` 或 `readv` 出错。

3. **过早释放缓冲区:** 在 `evWrite` 调用返回后，直到回调函数被调用之前，`iovec` 中指向的缓冲区必须保持有效。如果在 I/O 操作完成之前释放了缓冲区，会导致写入的数据不正确。

4. **不匹配的 `evCancelRW` 调用:** 如果异步 I/O 操作不再需要，应该调用 `evCancelRW` 来释放相关的资源并取消事件监听。忘记调用 `evCancelRW` 可能会导致资源泄漏。

5. **在错误的线程/上下文中使用:** `eventlib` 通常有一个事件循环在特定的线程或上下文中运行。在其他线程或上下文中错误地使用 `evWrite` 或 `evRead` 可能会导致竞争条件或未定义的行为。

**Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例**

**Android Framework 到达这里的路径（理论上，不太常见直接调用）：**

Android Framework 通常使用更高级别的抽象，如 `java.net.Socket` 或 `java.nio` 包中的类进行网络编程。这些高级 API 底层会调用 Native 代码，而 Native 代码可能会使用到类似 `ev_streams.c` 提供的异步 I/O 机制。

1. **Java Framework (例如 `SocketOutputStream.write()`):**  用户在 Java 层调用网络或文件写入 API。
2. **JNI 调用:**  Java Framework 的实现会通过 JNI (Java Native Interface) 调用到 Android 系统的 Native 代码。
3. **Native 网络/文件库:** Native 代码中，可能会使用到类似 `libnetd` 或文件系统相关的库。
4. **系统调用:** 这些库最终会调用底层的系统调用，例如 `write` 或 `read`。
5. **Bionic `libc.so`:**  `ev_streams.c` 编译在 `libc.so` 中，虽然 Framework 不会直接调用 `evWrite` 或 `evRead`，但 Bionic 提供的其他异步 I/O 机制的实现可能会借鉴或使用类似的思想。

**NDK 到达这里的路径 (更直接)：**

NDK 开发者可以直接使用 Bionic 提供的 C/C++ 接口。虽然 `eventlib` 的 API 可能不是 NDK 公开的稳定接口，但理论上开发者可以找到并使用这些函数。

1. **NDK 代码:**  NDK 开发者编写 C/C++ 代码。
2. **直接调用:**  如果 `eventlib` 的头文件和库是可用的（通常不是官方 NDK API），开发者可以直接包含头文件并调用 `evWrite` 或 `evRead`。
3. **链接 `libc.so`:**  编译 NDK 代码时，链接器会将代码链接到 `libc.so`，从而可以使用 `ev_streams.c` 中定义的函数。

**Frida Hook 示例调试步骤:**

假设你想 hook `evWrite` 函数：

1. **找到 `libc.so` 的基地址:** 在目标 Android 进程中找到 `libc.so` 加载的基地址。你可以使用 `Process.enumerateModules()` 函数来获取模块信息。

   ```javascript
   function getLibcBase() {
       const modules = Process.enumerateModules();
       for (let i = 0; i < modules.length; i++) {
           if (modules[i].name === 'libc.so') {
               return modules[i].base;
           }
       }
       return null;
   }

   const libcBase = getLibcBase();
   if (!libcBase) {
       console.log("Error: Could not find libc.so");
   } else {
       console.log("libc.so base address:", libcBase);
   }
   ```

2. **计算 `evWrite` 的偏移:**  你需要找到 `evWrite` 函数在 `libc.so` 中的偏移。这可以通过分析 `libc.so` 的符号表来完成（例如使用 `readelf -s libc.so` 或类似工具）。假设偏移是 `0xXXXX`.

3. **Hook `evWrite`:** 使用 Frida 的 `Interceptor.attach` 方法来 hook `evWrite` 函数。

   ```javascript
   if (libcBase) {
       const evWriteOffset = 0x...; // 替换为实际偏移
       const evWriteAddress = libcBase.add(evWriteOffset);

       Interceptor.attach(evWriteAddress, {
           onEnter: function (args) {
               console.log("evWrite called!");
               console.log("  fd:", args[1]); // fd
               // 可以进一步解析和打印其他参数
           },
           onLeave: function (retval) {
               console.log("evWrite returned:", retval);
           }
       });

       console.log("Successfully hooked evWrite");
   }
   ```

**更复杂的 Hook 场景:**

* **Hook 回调函数:**  如果你想观察异步 I/O 完成后的回调，你需要解析 `evWrite` 的参数，获取回调函数指针，然后在合适的时机 hook 这个回调函数。这需要更深入的理解 `eventlib` 的内部机制。
* **跟踪数据流:** 你可以 hook `writev` 和 `readv` 来观察实际写入和读取的数据。

请注意，直接使用 `ev_streams.c` 中的函数可能不是官方支持的 NDK 用法，并且其 API 可能会在 Android 的不同版本之间发生变化。推荐使用更高级别的、稳定的 Android SDK 或 NDK 提供的 API 进行开发。

希望这个详细的分析能够帮助你理解 `ev_streams.c` 的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/upstream-netbsd/lib/libc/isc/ev_streams.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: ev_streams.c,v 1.6 2009/04/12 17:07:17 christos Exp $	*/

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium
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

/* ev_streams.c - implement asynch stream file IO for the eventlib
 * vix 04mar96 [initial]
 */

#include <sys/cdefs.h>
#if !defined(LINT) && !defined(CODECENTER) && !defined(lint)
#ifdef notdef
static const char rcsid[] = "Id: ev_streams.c,v 1.5 2005/04/27 04:56:36 sra Exp";
#else
__RCSID("$NetBSD: ev_streams.c,v 1.6 2009/04/12 17:07:17 christos Exp $");
#endif
#endif

#include "port_before.h"
#include "fd_setsize.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>

#include <isc/eventlib.h>
#include <isc/assertions.h>
#include "eventlib_p.h"

#include "port_after.h"

#ifndef _LIBC
static int	copyvec(evStream *str, const struct iovec *iov, int iocnt);
static void	consume(evStream *str, size_t bytes);
static void	done(evContext opaqueCtx, evStream *str);
static void	writable(evContext opaqueCtx, void *uap, int fd, int evmask);
static void	readable(evContext opaqueCtx, void *uap, int fd, int evmask);
#endif

struct iovec
evConsIovec(void *buf, size_t cnt) {
	struct iovec ret;

	memset(&ret, 0xf5, sizeof ret);
	ret.iov_base = buf;
	ret.iov_len = cnt;
	return (ret);
}

#ifndef _LIBC
int
evWrite(evContext opaqueCtx, int fd, const struct iovec *iov, int iocnt,
	evStreamFunc func, void *uap, evStreamID *id)
{
	evContext_p *ctx = opaqueCtx.opaque;
	evStream *new;
	int save;

	OKNEW(new);
	new->func = func;
	new->uap = uap;
	new->fd = fd;
	new->flags = 0;
	if (evSelectFD(opaqueCtx, fd, EV_WRITE, writable, new, &new->file) < 0)
		goto free;
	if (copyvec(new, iov, iocnt) < 0)
		goto free;
	new->prevDone = NULL;
	new->nextDone = NULL;
	if (ctx->streams != NULL)
		ctx->streams->prev = new;
	new->prev = NULL;
	new->next = ctx->streams;
	ctx->streams = new;
	if (id != NULL)
		id->opaque = new;
	return (0);
 free:
	save = errno;
	FREE(new);
	errno = save;
	return (-1);
}

int
evRead(evContext opaqueCtx, int fd, const struct iovec *iov, int iocnt,
       evStreamFunc func, void *uap, evStreamID *id)
{
	evContext_p *ctx = opaqueCtx.opaque;
	evStream *new;
	int save;

	OKNEW(new);
	new->func = func;
	new->uap = uap;
	new->fd = fd;
	new->flags = 0;
	if (evSelectFD(opaqueCtx, fd, EV_READ, readable, new, &new->file) < 0)
		goto free;
	if (copyvec(new, iov, iocnt) < 0)
		goto free;
	new->prevDone = NULL;
	new->nextDone = NULL;
	if (ctx->streams != NULL)
		ctx->streams->prev = new;
	new->prev = NULL;
	new->next = ctx->streams;
	ctx->streams = new;
	if (id)
		id->opaque = new;
	return (0);
 free:
	save = errno;
	FREE(new);
	errno = save;
	return (-1);
}

int
evTimeRW(evContext opaqueCtx, evStreamID id, evTimerID timer) /*ARGSUSED*/ {
	evStream *str = id.opaque;

	UNUSED(opaqueCtx);

	str->timer = timer;
	str->flags |= EV_STR_TIMEROK;
	return (0);
}

int
evUntimeRW(evContext opaqueCtx, evStreamID id) /*ARGSUSED*/ {
	evStream *str = id.opaque;

	UNUSED(opaqueCtx);

	str->flags &= ~EV_STR_TIMEROK;
	return (0);
}

int
evCancelRW(evContext opaqueCtx, evStreamID id) {
	evContext_p *ctx = opaqueCtx.opaque;
	evStream *old = id.opaque;

	/*
	 * The streams list is doubly threaded.  First, there's ctx->streams
	 * that's used by evDestroy() to find and cancel all streams.  Second,
	 * there's ctx->strDone (head) and ctx->strLast (tail) which thread
	 * through the potentially smaller number of "IO completed" streams,
	 * used in evGetNext() to avoid scanning the entire list.
	 */

	/* Unlink from ctx->streams. */
	if (old->prev != NULL)
		old->prev->next = old->next;
	else
		ctx->streams = old->next;
	if (old->next != NULL)
		old->next->prev = old->prev;

	/*
	 * If 'old' is on the ctx->strDone list, remove it.  Update
	 * ctx->strLast if necessary.
	 */
	if (old->prevDone == NULL && old->nextDone == NULL) {
		/*
		 * Either 'old' is the only item on the done list, or it's
		 * not on the done list.  If the former, then we unlink it
		 * from the list.  If the latter, we leave the list alone.
		 */
		if (ctx->strDone == old) {
			ctx->strDone = NULL;
			ctx->strLast = NULL;
		}
	} else {
		if (old->prevDone != NULL)
			old->prevDone->nextDone = old->nextDone;
		else
			ctx->strDone = old->nextDone;
		if (old->nextDone != NULL)
			old->nextDone->prevDone = old->prevDone;
		else
			ctx->strLast = old->prevDone;
	}

	/* Deallocate the stream. */
	if (old->file.opaque)
		evDeselectFD(opaqueCtx, old->file);
	memput(old->iovOrig, sizeof (struct iovec) * old->iovOrigCount);
	FREE(old);
	return (0);
}

/* Copy a scatter/gather vector and initialize a stream handler's IO. */
static int
copyvec(evStream *str, const struct iovec *iov, int iocnt) {
	int i;

	str->iovOrig = (struct iovec *)memget(sizeof(struct iovec) * iocnt);
	if (str->iovOrig == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	str->ioTotal = 0;
	for (i = 0; i < iocnt; i++) {
		str->iovOrig[i] = iov[i];
		str->ioTotal += iov[i].iov_len;
	}
	str->iovOrigCount = iocnt;
	str->iovCur = str->iovOrig;
	str->iovCurCount = str->iovOrigCount;
	str->ioDone = 0;
	return (0);
}

/* Pull off or truncate lead iovec(s). */
static void
consume(evStream *str, size_t bytes) {
	while (bytes > 0U) {
		if (bytes < (size_t)str->iovCur->iov_len) {
			str->iovCur->iov_len -= bytes;
			str->iovCur->iov_base = (void *)
				((u_char *)str->iovCur->iov_base + bytes);
			str->ioDone += bytes;
			bytes = 0;
		} else {
			bytes -= str->iovCur->iov_len;
			str->ioDone += str->iovCur->iov_len;
			str->iovCur++;
			str->iovCurCount--;
		}
	}
}

/* Add a stream to Done list and deselect the FD. */
static void
done(evContext opaqueCtx, evStream *str) {
	evContext_p *ctx = opaqueCtx.opaque;

	if (ctx->strLast != NULL) {
		str->prevDone = ctx->strLast;
		ctx->strLast->nextDone = str;
		ctx->strLast = str;
	} else {
		INSIST(ctx->strDone == NULL);
		ctx->strDone = ctx->strLast = str;
	}
	evDeselectFD(opaqueCtx, str->file);
	str->file.opaque = NULL;
	/* evDrop() will call evCancelRW() on us. */
}

/* Dribble out some bytes on the stream.  (Called by evDispatch().) */
static void
writable(evContext opaqueCtx, void *uap, int fd, int evmask) {
	evStream *str = uap;
	int bytes;

	UNUSED(evmask);

	bytes = writev(fd, str->iovCur, str->iovCurCount);
	if (bytes > 0) {
		if ((str->flags & EV_STR_TIMEROK) != 0)
			evTouchIdleTimer(opaqueCtx, str->timer);
		consume(str, bytes);
	} else {
		if (bytes < 0 && errno != EINTR) {
			str->ioDone = -1;
			str->ioErrno = errno;
		}
	}
	if (str->ioDone == -1 || str->ioDone == str->ioTotal)
		done(opaqueCtx, str);
}

/* Scoop up some bytes from the stream.  (Called by evDispatch().) */
static void
readable(evContext opaqueCtx, void *uap, int fd, int evmask) {
	evStream *str = uap;
	int bytes;

	UNUSED(evmask);

	bytes = readv(fd, str->iovCur, str->iovCurCount);
	if (bytes > 0) {
		if ((str->flags & EV_STR_TIMEROK) != 0)
			evTouchIdleTimer(opaqueCtx, str->timer);
		consume(str, bytes);
	} else {
		if (bytes == 0)
			str->ioDone = 0;
		else {
			if (errno != EINTR) {
				str->ioDone = -1;
				str->ioErrno = errno;
			}
		}
	}
	if (str->ioDone <= 0 || str->ioDone == str->ioTotal)
		done(opaqueCtx, str);
}
#endif

/*! \file */
```