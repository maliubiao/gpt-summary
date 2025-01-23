Response:
Let's break down the thought process to answer the request about `bionic/libc/bionic/sys_epoll.cpp`.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the provided C++ code. Key aspects requested include:

* **Functionality:** What does the code do?
* **Android Relevance:** How does it relate to Android's operation?
* **libc Function Implementation:**  Detailed explanation of each function's inner workings.
* **Dynamic Linker Involvement:** If applicable, how does it interact with the dynamic linker (and examples).
* **Logic/Assumptions:**  Any internal logic or assumptions made (with examples).
* **Common Errors:**  Typical mistakes developers make when using these functions.
* **Android Framework/NDK Path:**  How does a high-level Android operation eventually lead to this code?
* **Frida Hooking:**  Examples of using Frida to intercept and observe these functions.

**2. Initial Code Analysis (Scanning and Identifying Key Elements):**

First, I'd quickly scan the code to identify the major components:

* **Headers:** `<errno.h>`, `<sys/epoll.h>`, `"private/SigSetConverter.h"`, `"private/bionic_fdtrack.h"`. These suggest standard error handling, epoll related types, and internal bionic utilities for signal sets and file descriptor tracking.
* **External "C" Functions:** `__epoll_create1`, `__epoll_pwait`, `__epoll_pwait2`. The double underscore prefix usually indicates system calls or very low-level internal functions. This immediately tells me the provided code is a *wrapper* around these core system functionalities.
* **Public Functions:** `epoll_create`, `epoll_create1`, `epoll_pwait`, `epoll_pwait64`, `epoll_pwait2`, `epoll_pwait2_64`, `epoll_wait`. These are the standard POSIX epoll API functions that applications will use.
* **`SigSetConverter`:** This class is likely used for converting between different signal set representations.
* **`FDTRACK_CREATE`:** This macro is related to tracking file descriptor creation, presumably for debugging or resource management.
* **Conditional Compilation (`#if __LP64__`)**: This indicates platform-specific handling, specifically for 32-bit (ILP32) vs. 64-bit architectures.

**3. Deeper Dive into Each Function:**

Now, I'd go through each public function, understanding its purpose and how it uses the underlying system calls:

* **`epoll_create(int size)`:**  Checks if `size` is valid, then calls `__epoll_create1(0)` and wraps the result in `FDTRACK_CREATE`. The `size` parameter is historical and ignored by modern kernels.
* **`epoll_create1(int flags)`:** Directly calls `__epoll_create1(flags)` and wraps the result. This allows specifying flags like `EPOLL_CLOEXEC`.
* **`epoll_pwait(...)` variations:**  These functions are all about waiting for events on the epoll file descriptor. They differ in how they handle timeouts and signal masks. The key is that they all eventually call `__epoll_pwait` or `__epoll_pwait2`. The `SigSetConverter` is used to adapt the application's `sigset_t` to the kernel's `sigset64_t`. The `_64` variants likely existed for historical reasons when 64-bit signal masks were explicitly used in some contexts.
* **`epoll_pwait2_64(...)`:** This is where the 32-bit vs. 64-bit handling comes in. On 32-bit systems, it converts the `timespec` to a `__kernel_timespec`. This is a crucial detail for understanding ABI compatibility.
* **`epoll_wait(...)`:** This is a simpler version of `epoll_pwait` that doesn't allow specifying a signal mask (it passes `nullptr`).

**4. Connecting to Android:**

* **Core System Functionality:** Epoll is fundamental for building efficient I/O event notification mechanisms. Android's event loop (like Looper in Java) relies heavily on epoll or similar mechanisms.
* **Android Framework:**  The Java framework uses native code, and that native code will eventually call into these bionic libc functions.
* **NDK:** NDK developers can directly use these functions in their C/C++ code.

**5. Dynamic Linker (Less Relevant Here, But Still Considered):**

While this specific file doesn't *directly* involve dynamic linking in its core logic, it's part of `libc.so`, which *is* dynamically linked. Therefore, I'd consider:

* **`libc.so` as a Shared Object:**  It's loaded into process memory by the dynamic linker.
* **Dependencies:** `libc.so` might depend on other libraries, but for these core system calls, the dependency is mostly on the kernel itself.
* **Symbol Resolution:** When an application calls `epoll_create`, the dynamic linker resolves this symbol to the implementation within `libc.so`.

**6. Logic and Assumptions:**

* **Error Handling:** The `epoll_create` function checks for an invalid size.
* **Signal Mask Conversion:** The `SigSetConverter` assumes a specific mapping between `sigset_t` and `sigset64_t`.
* **Kernel Interface:** The code assumes the existence and behavior of the underlying `__epoll_create1`, `__epoll_pwait`, and `__epoll_pwait2` system calls.
* **32-bit Time Conversion:** The `epoll_pwait2_64` function makes the assumption that converting `timespec` to `__kernel_timespec` is necessary and correct on 32-bit systems.

**7. Common Errors:**

* **Incorrect Size in `epoll_create` (Historically):** While now mostly ignored, older kernels cared.
* **Incorrect `max_events`:**  Allocating too few or too many events can lead to issues.
* **Forgetting to Handle `EINTR`:** System calls can be interrupted by signals.
* **Using `epoll_wait` with Signals:**  If precise signal handling during the wait is needed, `epoll_pwait` is the correct choice.

**8. Android Framework/NDK Path:**

I'd trace a common scenario, like a network operation, to illustrate the call flow.

**9. Frida Hooking:**

I'd construct simple Frida snippets to demonstrate how to intercept calls to these functions, logging arguments and return values.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the dynamic linker is heavily involved in this *specific* file.
* **Correction:**  Realized the file itself *uses* system calls, so the dynamic linker's main role is loading `libc.so`, not directly influencing the logic within these epoll functions.
* **Focus Shift:**  Emphasized the wrapper nature of the code and the importance of the underlying system calls.
* **Clarity on `_64` variants:**  Initially might have been confused by the `_64` suffixes. Realized they are likely historical and related to explicit 64-bit signal mask handling in some older contexts.

By following this structured approach, considering the different facets of the request, and refining the understanding along the way, I can generate a comprehensive and accurate answer.
好的，让我们详细分析 `bionic/libc/bionic/sys_epoll.cpp` 这个文件。

**文件功能概述**

`sys_epoll.cpp` 文件是 Android Bionic C 库 (libc) 中关于 `epoll` 系统调用的封装实现。它提供了用户空间可以调用的 `epoll` 相关函数，例如 `epoll_create`, `epoll_ctl`, `epoll_wait` 等。`epoll` 是一种 I/O 多路复用技术，允许一个进程同时监视多个文件描述符（例如 socket, pipe, file）的状态，并在其中一个或多个文件描述符准备好进行 I/O 操作时得到通知，从而提高 I/O 效率。

**与 Android 功能的关系及举例**

`epoll` 在 Android 系统中扮演着至关重要的角色，它被广泛应用于各种需要高效处理并发连接和事件的场景：

* **网络服务:**  Android 系统中的网络服务，例如 `system_server` 中的网络管理模块、`netd` 守护进程，以及应用程序使用的网络库（例如 OkHttp 的底层实现），都大量使用 `epoll` 来监听和处理网络连接的事件（例如新连接到达、数据可读、数据可写等）。
    * **例子:** 当一个 Android 应用通过 HTTP 请求访问一个服务器时，底层的 socket 连接可能由 `epoll` 监听。当服务器返回数据时，内核会通知 `epoll` 监听的描述符变为可读状态，应用程序的网络库才能接收数据。
* **Binder IPC:** Android 的进程间通信机制 Binder 的底层实现也依赖于 `epoll` 来监听 Binder 驱动的文件描述符，从而接收和处理来自其他进程的请求。
    * **例子:** 当一个 Activity 调用一个 Service 的方法时，这个调用会通过 Binder 传递。`system_server` 中的 `SurfaceFlinger` 服务会使用 `epoll` 监听 Binder 驱动的文件描述符，以便接收来自应用程序的绘制请求。
* **事件循环:** Android 的消息队列和事件循环机制，例如 `Looper`，也可能在底层使用 `epoll` 来监听事件源（例如 pipe, timerfd）的事件。
    * **例子:** Android 的 UI 线程的 `Looper` 会使用 `epoll` 监听消息队列的读取端。当有新的消息到达时，`epoll_wait` 会返回，`Looper` 才能处理该消息。

**libc 函数的实现细节**

让我们逐个分析 `sys_epoll.cpp` 中实现的 libc 函数：

1. **`epoll_create(int size)`:**
   - **功能:** 创建一个 `epoll` 实例。该函数返回一个指向 `epoll` 实例的文件描述符。`size` 参数在现代 Linux 内核中已经被忽略，但为了兼容性仍然保留。
   - **实现:**
     - 首先检查 `size` 是否小于等于 0。如果是，则设置 `errno` 为 `EINVAL` 并返回 -1，表示参数无效。
     - 调用底层的系统调用 `__epoll_create1(0)`。`__epoll_create1` 是一个实际执行 `epoll` 实例创建的系统调用，参数 `0` 表示不设置任何标志。
     - 使用 `FDTRACK_CREATE` 宏包装 `__epoll_create1` 的返回值。`FDTRACK_CREATE` 是 Bionic 内部用于跟踪文件描述符创建的机制，可能用于调试和资源管理。

2. **`epoll_create1(int flags)`:**
   - **功能:** 创建一个 `epoll` 实例，并可以指定一些标志，例如 `EPOLL_CLOEXEC`（在 `exec` 时关闭文件描述符）。
   - **实现:**
     - 直接调用底层的系统调用 `__epoll_create1(flags)`，将用户传入的 `flags` 传递给内核。
     - 同样使用 `FDTRACK_CREATE` 宏包装返回值。

3. **`epoll_pwait(int fd, epoll_event* events, int max_events, int timeout, const sigset_t* ss)`:**
   - **功能:** 等待 `epoll` 实例上的事件发生，可以设置超时时间和阻塞期间屏蔽的信号集。
   - **实现:**
     - 创建一个 `SigSetConverter` 对象 `set`，将用户提供的 `sigset_t` 转换为内核使用的 `sigset64_t` 格式。`SigSetConverter` 是 Bionic 内部用于处理不同信号集表示的工具类。
     - 调用 `epoll_pwait64` 函数，并将转换后的信号集指针 `set.ptr` 传递给它。

4. **`epoll_pwait64(int fd, epoll_event* events, int max_events, int timeout, const sigset64_t* ss)`:**
   - **功能:** `epoll_pwait` 的 64 位版本，直接使用 `sigset64_t`。
   - **实现:**
     - 调用底层的系统调用 `__epoll_pwait(fd, events, max_events, timeout, ss, sizeof(*ss))`。
     - `fd`: `epoll` 实例的文件描述符。
     - `events`: 用户提供的 `epoll_event` 数组，用于接收就绪的事件。
     - `max_events`: `events` 数组的最大容量。
     - `timeout`: 超时时间，单位为毫秒。-1 表示无限等待。
     - `ss`: 指向要屏蔽的信号集的指针。
     - `sizeof(*ss)`: 信号集的大小。

5. **`epoll_pwait2(int fd, epoll_event* events, int max_events, const timespec* timeout, const sigset_t* ss)`:**
   - **功能:**  `epoll_pwait` 的变体，使用 `timespec` 结构体来指定超时时间，精度更高（纳秒级）。
   - **实现:**
     - 同样使用 `SigSetConverter` 转换信号集。
     - 调用 `epoll_pwait2_64` 函数。

6. **`epoll_pwait2_64(int fd, epoll_event* events, int max_events, const timespec* timeout, const sigset64_t* ss)`:**
   - **功能:** `epoll_pwait2` 的 64 位版本。
   - **实现:**
     - **针对 32 位系统 (ILP32) 的特殊处理:**
       - 因为 `epoll_pwait2` 是 Bionic 中第一个假设 `time_t` 为 64 位的系统调用，即使对于 32 位进程也是如此。这意味着内核期望接收 `__kernel_timespec` 结构体。
       - 如果是 32 位系统 (`#ifndef __LP64__`)，并且 `timeout` 不为空，则需要将用户提供的 `timespec` 转换为内核期望的 `__kernel_timespec` 结构体。
       - 创建一个本地的 `__kernel_timespec` 变量 `kts`，并将 `timeout` 中的 `tv_sec` 和 `tv_nsec` 复制到 `kts` 中。
       - 将 `kts` 的地址赋值给 `kts_ptr`。
     - **针对 64 位系统:**
       - 如果是 64 位系统 (`#ifdef __LP64__`)，则直接将用户提供的 `timeout` 指针 `reinterpret_cast` 为 `__kernel_timespec*`。
     - 调用底层的系统调用 `__epoll_pwait2(fd, events, max_events, kts_ptr, ss, sizeof(*ss))`。

7. **`epoll_wait(int fd, struct epoll_event* events, int max_events, int timeout)`:**
   - **功能:**  等待 `epoll` 实例上的事件发生，相当于 `epoll_pwait`，但不允许指定信号屏蔽集。
   - **实现:**
     - 直接调用 `epoll_pwait64`，并将信号集指针设置为 `nullptr`，表示不屏蔽任何信号。

**涉及 dynamic linker 的功能**

虽然 `sys_epoll.cpp` 本身主要关注 `epoll` 系统调用的封装，但它属于 `libc.so` 这个共享库。因此，动态链接器在加载和使用这个库的过程中发挥着关键作用。

**`libc.so` 布局样本 (简化)**

```
libc.so:
    .text         # 代码段
        epoll_create: ...
        epoll_create1: ...
        epoll_pwait: ...
        ...
        __epoll_create1:  <地址 A>  # 指向内核系统调用入口
        __epoll_pwait:    <地址 B>  # 指向内核系统调用入口
        __epoll_pwait2:   <地址 C>  # 指向内核系统调用入口
    .data         # 数据段
        ...
    .bss          # 未初始化数据段
        ...
    .dynamic      # 动态链接信息
        NEEDED   libm.so  # 可能依赖其他库
        SONAME   libc.so
        SYMBOL   epoll_create
        SYMBOL   epoll_pwait
        ...
        SYMBOL   __epoll_create1
        SYMBOL   __epoll_pwait
        SYMBOL   __epoll_pwait2
```

**链接的处理过程**

1. **加载 `libc.so`:** 当一个 Android 进程启动时，动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会根据程序头部的信息，将 `libc.so` 加载到进程的地址空间。

2. **符号解析 (Symbol Resolution):**
   - 当应用程序调用 `epoll_create` 等函数时，编译器会在生成目标文件时生成对这些符号的未定义引用。
   - 在链接阶段，静态链接器会将这些未定义引用标记出来。
   - 在运行时，动态链接器会扫描已加载的共享库，查找与这些未定义引用匹配的符号。
   - 对于 `epoll_create`，动态链接器会在 `libc.so` 的 `.dynsym` 或 `.gnu.hash` 段中找到对应的符号，并将其地址填入应用程序的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table)。

3. **系统调用处理 (对于 `__epoll_create1` 等):**
   - 注意 `__epoll_create1`, `__epoll_pwait`, `__epoll_pwait2` 这些以双下划线开头的函数，它们通常是 Bionic 内部使用的，直接对应内核的系统调用。
   - 动态链接器**不会**将这些符号链接到 `libc.so` 内部的某个函数。相反，这些函数通常是通过汇编指令直接发出系统调用 (`syscall`) 来与内核交互的。
   - 在 `libc.so` 的实现中，这些 `__epoll_*` 函数会包含类似以下的汇编代码（架构相关，这里仅为示意）：
     ```assembly
     mov  $SYS_epoll_create1, %eax  ; 将系统调用号放入 eax 寄存器
     syscall                         ; 执行系统调用
     ret                             ; 返回
     ```
   - 动态链接器不需要解析这些符号到 `libc.so` 内部，因为它们本身就代表了与内核交互的入口点。

**逻辑推理、假设输入与输出**

**假设输入：** 调用 `epoll_create(10)`

**逻辑推理：**

1. `epoll_create(10)` 被调用。
2. 函数检查 `size` (10) 是否小于等于 0，结果为否。
3. 调用 `__epoll_create1(0)`。
4. `__epoll_create1` 系统调用被执行，内核创建一个新的 `epoll` 实例，并返回一个文件描述符（假设为 3）。
5. `FDTRACK_CREATE(3)` 被执行，Bionic 可能会记录这个文件描述符的创建。
6. `epoll_create` 函数返回文件描述符 3。

**输出：** 返回值是新创建的 `epoll` 实例的文件描述符，例如 `3`。如果创建失败，则返回 `-1` 并设置 `errno`。

**用户或编程常见的使用错误**

1. **`epoll_create` 的 `size` 参数的误解:**  在旧版本的 Linux 中，`size` 参数曾用于提示内核 `epoll` 实例将要监听的文件描述符数量。但在现代内核中，该参数已被忽略。一些开发者可能会错误地认为设置一个过小的 `size` 会限制 `epoll` 实例可以监听的文件描述符数量。

   ```c++
   // 错误示例：认为 size 限制了监听数量
   int epfd = epoll_create(1);
   epoll_event ev;
   // ... 添加多个文件描述符到 epfd ...
   ```

2. **`epoll_wait` 的超时时间设置不当:**  开发者可能会错误地设置超时时间，导致程序行为异常。例如，将超时时间设置为 0 会导致 `epoll_wait` 立即返回，而不管是否有事件发生，这可以用于非阻塞的事件检查。将超时时间设置为负数（例如 -1）表示无限等待，直到有事件发生。

   ```c++
   // 错误示例：希望立即检查事件，但误用了负超时
   int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1); // 实际上会阻塞等待
   ```

3. **忘记处理 `epoll_wait` 返回的错误:** `epoll_wait` 可能因为信号中断等原因返回 -1，并设置 `errno`。开发者需要检查返回值和 `errno` 来处理这些错误情况，例如 `EINTR`。

   ```c++
   int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
   if (nfds == -1) {
       perror("epoll_wait"); // 应该处理 errno
       if (errno == EINTR) {
           // 被信号中断，通常可以继续等待
       } else {
           // 其他错误，需要处理
       }
   }
   ```

4. **`epoll_event` 结构体的使用错误:**  开发者可能会错误地设置或读取 `epoll_event` 结构体中的成员，例如 `data.fd` 或 `events`。

   ```c++
   // 错误示例：假设 data.fd 是事件发生的文件描述符，但实际需要检查返回的事件
   int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
   if (nfds > 0) {
       // 错误地认为 events[0].data.fd 是就绪的文件描述符
       process_fd(events[0].data.fd);
   }
   ```

**Android Framework 或 NDK 如何到达这里**

让我们以一个使用 NDK 开发的 Android 应用的网络请求为例，说明如何一步步到达 `sys_epoll.cpp`：

1. **NDK 应用发起网络请求:**  NDK 应用通常会使用 C/C++ 的网络库，例如使用 socket API。

   ```c++
   // NDK 代码
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <unistd.h>
   #include <errno.h>
   #include <sys/epoll.h>

   int main() {
       int sockfd = socket(AF_INET, SOCK_STREAM, 0);
       // ... 连接服务器 ...

       int epfd = epoll_create1(0);
       epoll_event event;
       event.data.fd = sockfd;
       event.events = EPOLLIN;
       epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &event);

       epoll_event events[1];
       int nfds = epoll_wait(epfd, events, 1, -1); // 这里会调用到 bionic 的 epoll_wait
       if (nfds > 0) {
           // 处理接收到的数据
           char buffer[1024];
           recv(sockfd, buffer, sizeof(buffer), 0);
       }
       close(sockfd);
       close(epfd);
       return 0;
   }
   ```

2. **调用 `epoll_wait`:**  在 NDK 代码中，直接调用了 `epoll_wait` 函数。由于 NDK 应用链接到 Bionic libc，这个调用实际上会跳转到 `bionic/libc/bionic/sys_epoll.cpp` 中实现的 `epoll_wait` 函数。

3. **Bionic libc 的 `epoll_wait`:** `bionic/libc/bionic/sys_epoll.cpp` 中的 `epoll_wait` 函数会进一步调用底层的系统调用 `__epoll_pwait64`。

4. **系统调用:**  `__epoll_pwait64` 函数内部会使用汇编指令触发 `epoll_pwait` 系统调用，将请求传递给 Linux 内核。

5. **内核处理:** Linux 内核接收到 `epoll_pwait` 系统调用后，会将进程置于休眠状态，直到被监听的文件描述符上有事件发生。当事件发生时，内核会唤醒进程，并将就绪的事件信息返回给用户空间。

**Frida Hook 示例**

可以使用 Frida Hook 来观察 `epoll_wait` 函数的调用过程，例如打印其参数和返回值：

```python
import frida
import sys

package_name = "your.ndk.app.package" # 替换为你的 NDK 应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "epoll_wait"), {
    onEnter: function(args) {
        console.log("[*] epoll_wait called");
        console.log("    fd:", args[0]);
        console.log("    events:", args[1]);
        console.log("    max_events:", args[2]);
        console.log("    timeout:", args[3]);
    },
    onLeave: function(retval) {
        console.log("[*] epoll_wait returned:", retval);
        if (retval > 0) {
            // 可以进一步解析 events 指针指向的数据
            console.log("    Number of events:", retval);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. 确保你的 Android 设备已连接并通过 ADB 可访问。
2. 安装 Frida 和 Frida-server 到你的设备上。
3. 将 `your.ndk.app.package` 替换为你的 NDK 应用的实际包名。
4. 运行 Python 脚本。
5. 启动你的 NDK 应用并执行触发 `epoll_wait` 的操作。
6. Frida 会拦截 `epoll_wait` 的调用，并打印出其参数和返回值。

这个 Frida 脚本会 hook `libc.so` 中的 `epoll_wait` 函数，当你的应用调用这个函数时，`onEnter` 和 `onLeave` 函数会被执行，从而你可以观察到函数的调用信息。

希望这个详细的分析能够帮助你理解 `bionic/libc/bionic/sys_epoll.cpp` 的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/sys_epoll.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <sys/epoll.h>

#include "private/SigSetConverter.h"
#include "private/bionic_fdtrack.h"

extern "C" int __epoll_create1(int flags);
extern "C" int __epoll_pwait(int, epoll_event*, int, int, const sigset64_t*, size_t);
extern "C" int __epoll_pwait2(int, epoll_event*, int, const __kernel_timespec*, const sigset64_t*,
                              size_t);

int epoll_create(int size) {
  if (size <= 0) {
    errno = EINVAL;
    return -1;
  }
  return FDTRACK_CREATE(__epoll_create1(0));
}

int epoll_create1(int flags) {
  return FDTRACK_CREATE(__epoll_create1(flags));
}

int epoll_pwait(int fd, epoll_event* events, int max_events, int timeout, const sigset_t* ss) {
  SigSetConverter set{ss};
  return epoll_pwait64(fd, events, max_events, timeout, set.ptr);
}

int epoll_pwait64(int fd, epoll_event* events, int max_events, int timeout, const sigset64_t* ss) {
  return __epoll_pwait(fd, events, max_events, timeout, ss, sizeof(*ss));
}

int epoll_pwait2(int fd, epoll_event* events, int max_events, const timespec* timeout,
                 const sigset_t* ss) {
  SigSetConverter set{ss};
  return epoll_pwait2_64(fd, events, max_events, timeout, set.ptr);
}

int epoll_pwait2_64(int fd, epoll_event* events, int max_events, const timespec* timeout,
                    const sigset64_t* ss) {
  // epoll_pwait2() is our first syscall that assumes a 64-bit time_t even for
  // 32-bit processes, so for ILP32 we need to convert.
  // TODO: factor this out into a TimeSpecConverter as/when we get more syscalls like this.
#if __LP64__
  const __kernel_timespec* kts_ptr = reinterpret_cast<const __kernel_timespec*>(timeout);
#else
  __kernel_timespec kts;
  const __kernel_timespec* kts_ptr = nullptr;
  if (timeout) {
    kts.tv_sec = timeout->tv_sec;
    kts.tv_nsec = timeout->tv_nsec;
    kts_ptr = &kts;
  }
#endif
  return __epoll_pwait2(fd, events, max_events, kts_ptr, ss, sizeof(*ss));
}

int epoll_wait(int fd, struct epoll_event* events, int max_events, int timeout) {
  return epoll_pwait64(fd, events, max_events, timeout, nullptr);
}
```