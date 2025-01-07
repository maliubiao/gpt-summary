Response:
我的目标是对给定的 C++ 源代码文件 `bionic/tests/sys_epoll_test.cpp` 进行分析，并按照要求给出详细的中文回复。

**分析步骤：**

1. **理解文件用途：**  首先识别这是一个测试文件，隶属于 Android Bionic 库的 `sys_epoll` 部分。这意味着它主要用来测试 `epoll` 相关的系统调用。

2. **识别测试用例：**  浏览代码，可以清晰地看到多个以 `TEST` 宏定义的测试用例。每个测试用例针对 `epoll` 的一个或多个特定功能点。

3. **提取测试功能点：**  逐个分析每个测试用例，明确其测试的目标。例如，`epoll_wait` 测试基本的 `epoll_wait` 调用，`epoll_pwait_no_sigset` 测试 `epoll_pwait` 在不使用信号掩码时的行为，以此类推。

4. **关联 Android 功能：** 思考 `epoll` 在 Android 系统中的作用。`epoll` 是一种高效的 I/O 多路复用机制，Android 框架的许多部分都依赖它来处理并发事件，例如网络连接、文件描述符的就绪状态等。

5. **深入 libc 函数实现：**  由于这是 Bionic 的测试文件，需要了解被测试的 libc 函数的实现原理。对于 `epoll_create`、`epoll_ctl`、`epoll_wait`、`epoll_pwait` 等，需要从系统调用的角度进行解释，说明内核如何管理 `epoll` 实例和事件。

6. **涉及 dynamic linker 的部分：**  虽然这个特定的测试文件没有直接涉及到动态链接器，但 `epoll` 是 libc 的一部分，而 libc 本身是通过动态链接器加载的。  因此，可以描述一下动态链接器加载 libc 的过程，以及 `epoll` 函数如何在 libc 中被找到和调用。  可以提供一个简单的 so 布局示例，并解释链接过程。

7. **逻辑推理和假设输入输出：** 对于每个测试用例，可以分析其逻辑，并给出假设的输入和预期的输出。例如，对于 `epoll_wait`，输入是创建的 epoll 实例和超时时间，预期输出是 0，表示没有事件发生。

8. **用户或编程常见错误：**  思考在使用 `epoll` 时常见的错误，例如忘记添加文件描述符到 epoll 实例，或者错误地设置事件掩码等。

9. **Android Framework/NDK 到达测试点的路径：** 描述一个典型的场景，例如一个 Native Activity 使用 `epoll` 监听网络事件，来说明 Android Framework 或 NDK 如何最终调用到 Bionic 的 `epoll` 函数。

10. **Frida Hook 示例：**  提供 Frida Hook 代码示例，用于拦截和观察 `epoll_wait` 等函数的调用，以便进行调试和分析。

**具体思考过程的细节：**

* **功能列表：**  简单列举每个测试用例覆盖的功能。
* **Android 关联：**  强调 `epoll` 在事件循环、网络编程、Binder 通信中的重要性。
* **libc 函数解释：**  以系统调用为核心，解释 `epoll_create` 创建内核对象，`epoll_ctl` 操作事件集合，`epoll_wait` 进行阻塞等待。  对于 `epoll_pwait`，强调信号掩码的作用。
* **dynamic linker：**  构建一个简化的 so 布局，说明 `DT_NEEDED`、`.dynsym`、`.rel.plt` 等部分，并描述链接器如何解析符号和重定位。
* **假设输入输出：**  选择一些简单的测试用例，给出明确的输入和预期输出。例如，`epoll_create(1)` 应该成功返回非负的文件描述符。
* **常见错误：**  列举例如忘记 `EPOLLIN`/`EPOLLOUT`，使用已关闭的 fd，泄露 epoll fd 等。
* **Android 路径：**  从 Java 层事件处理到 Native 代码，再到 Bionic 的系统调用。  或者从 NDK 网络编程直接调用 socket 和 epoll。
* **Frida Hook：**  针对 `epoll_wait`，hook 其入口和出口，打印参数和返回值。

**自我纠正/优化：**

* **最初想法：**  仅仅列举功能和简单解释 libc 函数。
* **优化：**  增加了 Android 关联的深度，更详细地解释了 libc 函数的系统调用实现，补充了 dynamic linker 的相关内容，以及更实际的 Frida Hook 示例。 强调了用户常见错误和 Android 框架的调用链。 确保了语言的准确性和描述的清晰度。

通过以上分析和思考过程，我最终形成了现在这个较为完善的回复。
好的，让我们来详细分析一下 `bionic/tests/sys_epoll_test.cpp` 这个文件。

**文件功能总览**

这个 C++ 文件是 Android Bionic 库的测试文件，专门用于测试与 `epoll` 相关的系统调用。`epoll` 是一种 Linux 特有的 I/O 多路复用机制，它允许一个进程监视多个文件描述符，等待其中一个或多个变为就绪状态（例如可读、可写或发生错误）。

该文件的主要功能是：

1. **测试 `epoll_create` 和 `epoll_create1`:** 验证创建 `epoll` 实例的功能，包括指定大小和 `close-on-exec` 标志。
2. **测试 `epoll_wait`:** 验证基本的 `epoll_wait` 系统调用，它会阻塞等待 `epoll` 实例上的事件。
3. **测试 `epoll_pwait` 和其变种 (`epoll_pwait64`, `epoll_pwait2`, `epoll_pwait2_64`):** 验证带信号屏蔽的 `epoll_wait` 系统调用，它允许在等待事件时临时阻塞某些信号。
4. **测试 `epoll_ctl`:** 通过添加文件描述符到 `epoll` 实例并等待事件，间接测试 `epoll_ctl` 的 `EPOLL_CTL_ADD` 功能。
5. **测试 `epoll_event` 结构体中的 `data` 联合体:** 验证通过 `epoll_event` 结构体传递用户数据的能力。
6. **处理平台差异:** 使用条件编译 (`#if defined(__BIONIC__)`) 和 `GTEST_SKIP()` 来处理不同平台或内核版本对某些 `epoll` 变种的支持情况。

**与 Android 功能的关系及举例**

`epoll` 在 Android 系统中扮演着至关重要的角色，它是构建高性能、事件驱动的应用程序的基础。以下是一些例子：

* **网络编程:**  Android 应用（包括 Framework 和 Native 代码）经常使用 `epoll` 来监听多个套接字上的事件，例如新的连接请求、接收到数据等。例如，一个网络服务器可以使用 `epoll` 来同时处理多个客户端连接，而无需为每个连接创建一个单独的线程或进程。
* **Binder 通信:** Android 的进程间通信 (IPC) 机制 Binder 底层就使用了 `epoll` 来管理和监听不同进程之间的通信事件。Binder 驱动会通知注册了 Binder 节点的进程是否有新的事务需要处理。
* **事件循环 (Event Loop):**  Android 的各种事件循环机制，例如 Looper (Java) 和 libevent/libuv (Native)，通常会使用 `epoll` (或其他类似的机制，如 `poll` 或 `select`) 来高效地等待事件的发生。例如，主线程的 Looper 使用 `epoll` 来监听消息队列、输入事件等。
* **文件系统监控:** 某些文件系统监控工具或库可能使用 `epoll` 来监听文件描述符上的事件，例如文件的可读性变化。

**举例说明:**

假设一个 Android 应用需要从多个网络连接接收数据。它可以创建一个 `epoll` 实例，并将所有连接的 socket 文件描述符添加到这个实例中。然后，调用 `epoll_wait` 来等待任何一个连接上有数据到达。当 `epoll_wait` 返回时，它会指示哪些连接是可读的，应用程序就可以针对这些连接进行处理。

**libc 函数的功能及其实现**

接下来，我们详细解释一下代码中涉及的 libc 函数：

1. **`epoll_create(int size)`:**
   - **功能:** 创建一个 `epoll` 实例。`size` 参数是内核为内部数据结构分配初始大小的提示，在现代内核中该参数已被忽略。
   - **实现:**  这是一个系统调用。当调用 `epoll_create` 时，内核会执行以下操作：
     - 分配一个 `epoll` 文件描述符。
     - 初始化与该文件描述符关联的内核数据结构，例如红黑树（用于高效地存储被监视的文件描述符）和一个双向链表（用于存储就绪的文件描述符）。
     - 返回新的 `epoll` 文件描述符。如果出错，返回 -1 并设置 `errno`。

2. **`epoll_create1(int flags)`:**
   - **功能:**  类似于 `epoll_create`，但允许设置额外的标志。目前常用的标志是 `EPOLL_CLOEXEC`，表示创建的文件描述符在执行 `exec` 系统调用后会自动关闭。
   - **实现:**  这也是一个系统调用，其实现与 `epoll_create` 类似，但会根据 `flags` 参数进行额外的处理，例如设置文件描述符的 `close-on-exec` 标志。

3. **`epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)`:**
   - **功能:**  用于控制 `epoll` 实例所监视的文件描述符。
   - **参数:**
     - `epfd`: `epoll` 实例的文件描述符。
     - `op`: 操作类型，例如 `EPOLL_CTL_ADD` (添加文件描述符)，`EPOLL_CTL_MOD` (修改文件描述符的监视事件)，`EPOLL_CTL_DEL` (删除文件描述符)。
     - `fd`: 要操作的文件描述符。
     - `event`: 一个指向 `epoll_event` 结构体的指针，用于指定要监视的事件类型（例如 `EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`）以及用户数据。
   - **实现:**  这是一个系统调用。内核会根据 `op` 参数执行相应的操作：
     - **`EPOLL_CTL_ADD`:** 将 `fd` 添加到 `epoll` 实例的红黑树中，并关联指定的事件。
     - **`EPOLL_CTL_MOD`:** 更新 `fd` 在红黑树中关联的事件。
     - **`EPOLL_CTL_DEL`:** 从红黑树中移除 `fd`。
     - 当监视的文件描述符上的事件发生时，内核会将该文件描述符添加到 `epoll` 实例的就绪链表中。

4. **`epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)`:**
   - **功能:**  等待 `epoll` 实例上的事件发生。
   - **参数:**
     - `epfd`: `epoll` 实例的文件描述符。
     - `events`: 一个指向 `epoll_event` 数组的指针，用于存储就绪事件的信息。
     - `maxevents`: `events` 数组的最大容量。
     - `timeout`: 等待超时时间，单位是毫秒。如果为 -1，则无限期等待；如果为 0，则立即返回。
   - **实现:**  这是一个系统调用。
     - 内核会检查 `epoll` 实例的就绪链表。
     - 如果链表为空且 `timeout` 大于 0，则进程会进入睡眠状态，直到以下情况发生：
       - 至少有一个文件描述符变为就绪状态。
       - 超时时间到达。
       - 接收到未被屏蔽的信号。
     - 当事件发生或超时后，内核会将就绪链表中的事件信息复制到 `events` 数组中。
     - 返回就绪事件的数量。如果超时，返回 0。如果出错，返回 -1 并设置 `errno`。

5. **`epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask)`:**
   - **功能:** 类似于 `epoll_wait`，但允许在等待事件时临时替换进程的信号屏蔽字。
   - **参数:** 比 `epoll_wait` 多了一个 `sigmask` 参数，它指向一个信号集。
   - **实现:**  这是一个系统调用。在进入等待状态之前，内核会将进程的信号屏蔽字替换为 `sigmask` 指向的信号集。当 `epoll_pwait` 返回时，原始的信号屏蔽字会被恢复。这允许应用程序在等待 I/O 事件的同时，原子地阻塞或取消阻塞某些信号。

6. **`epoll_pwait64`, `epoll_pwait2`, `epoll_pwait2_64`:**
   - 这些是 `epoll_pwait` 的变种，主要是为了处理不同平台或内核版本的差异，例如：
     - `epoll_pwait64`：在某些架构上使用 64 位的时间值。
     - `epoll_pwait2`：使用 `timespec` 结构体来指定超时时间，精度更高。
     - `epoll_pwait2_64`：结合了 `epoll_pwait2` 和 64 位时间值的特性。
   - **实现:**  它们的实现与 `epoll_pwait` 类似，但可能在时间精度或数据类型上有所不同。

7. **`sigemptyset`, `sigaddset`:**
   - 这些是 POSIX 标准的信号处理函数。
   - **`sigemptyset(sigset_t *set)`:** 初始化信号集 `set`，使其不包含任何信号。
   - **`sigaddset(sigset_t *set, int signum)`:** 将信号 `signum` 添加到信号集 `set` 中。

**涉及 dynamic linker 的功能**

虽然这个测试文件本身没有直接测试动态链接器的功能，但 `epoll` 相关的函数是 libc 的一部分，而 libc 是通过 dynamic linker 加载到进程中的。

**so 布局样本 (libc.so)：**

```
libc.so:
  .dynsym:  // 动态符号表，包含导出的符号信息（如 epoll_create, epoll_wait 等）
    STT_FUNC epoll_create
    STT_FUNC epoll_wait
    ...
  .plt:     // 程序链接表，用于延迟绑定动态符号
    epoll_create@plt:
      jmp *GOT entry for epoll_create
    epoll_wait@plt:
      jmp *GOT entry for epoll_wait
    ...
  .got.plt: // 全局偏移表 (GOT) 的 PLT 部分，存储动态符号的地址
    Address of epoll_create
    Address of epoll_wait
    ...
  .text:    // 代码段，包含 epoll_create 和 epoll_wait 等函数的实现
    Implementation of epoll_create
    Implementation of epoll_wait
    ...
  ...其他段...
```

**链接的处理过程：**

1. **编译时链接:** 当编译 `sys_epoll_test.cpp` 时，编译器会找到 `epoll_create` 和 `epoll_wait` 等函数的声明，并生成对这些函数的调用指令。由于这些函数位于 libc.so 中，链接器会在可执行文件的 `.dynamic` 段中添加一个 `DT_NEEDED` 条目，指示需要链接 libc.so。同时，会在 `.plt` 和 `.got.plt` 中创建相应的条目。

2. **加载时链接 (dynamic linker 的工作):** 当运行测试程序时，操作系统会首先加载 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。

3. **加载依赖库:** dynamic linker 会解析可执行文件的 `.dynamic` 段，找到 `DT_NEEDED` 条目，并加载 libc.so 到内存中。

4. **符号解析和重定位:**
   - 当程序第一次调用 `epoll_create` 时，会跳转到 `epoll_create@plt`。
   - `epoll_create@plt` 中的指令会跳转到 GOT 中对应的条目，该条目最初包含的是一个跳转回 PLT 的地址。
   - dynamic linker 捕获到这个跳转，然后查找 libc.so 的 `.dynsym` 表，找到 `epoll_create` 的实际地址。
   - dynamic linker 将 `epoll_create` 的实际地址写入到 GOT 中 `epoll_create` 对应的条目。
   - 再次调用 `epoll_create` 时，会直接跳转到 GOT 中存储的实际地址，从而避免了重复的符号解析。
   - `epoll_wait` 等其他动态链接的函数也遵循类似的过程。

**假设输入与输出**

* **`TEST(sys_epoll, epoll_wait)`:**
    - **假设输入:**  创建一个 `epoll` 实例。
    - **预期输出:** `epoll_wait` 调用返回 0，表示超时时间内没有事件发生。

* **`TEST(sys_epoll, epoll_create_invalid_size)`:**
    - **假设输入:** 调用 `epoll_create(0)`。
    - **预期输出:** `epoll_create` 返回 -1，`errno` 被设置为 `EINVAL` (无效参数)。

* **`TEST(sys_epoll, epoll_event_data)`:**
    - **假设输入:**  创建一个 `epoll` 实例，创建一个管道，将管道的读端添加到 `epoll` 实例并关联用户数据 `0x123456789abcdef0`，向管道的写端写入数据。
    - **预期输出:** `epoll_wait` 返回 1，表示有一个事件发生。`events[0].data.u64` 的值为 `0x123456789abcdef0`。

**用户或编程常见的使用错误**

1. **忘记使用 `epoll_ctl` 添加文件描述符:**  创建了 `epoll` 实例后，必须使用 `epoll_ctl` 将要监视的文件描述符添加到该实例中，否则 `epoll_wait` 永远不会返回有意义的事件。

   ```c++
   int epoll_fd = epoll_create(1);
   int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
   // 错误：忘记将 socket_fd 添加到 epoll_fd
   epoll_event events[1];
   epoll_wait(epoll_fd, events, 1, -1); // 会一直阻塞，除非发生信号
   ```

2. **事件掩码设置不正确:**  在 `epoll_ctl` 中设置事件掩码时，需要根据实际需求设置 `event.events`。例如，如果只关心可读事件，应设置 `EPOLLIN`。如果设置错误，可能无法正确接收到期望的事件。

   ```c++
   int epoll_fd = epoll_create(1);
   int pipe_fds[2];
   pipe(pipe_fds);
   epoll_event ev;
   ev.events = EPOLLOUT; // 错误：期望读取数据，却监听了可写事件
   ev.data.fd = pipe_fds[0];
   epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_fds[0], &ev);
   // 即使 pipe_fds[0] 可读，epoll_wait 也不会返回，因为监听的是 EPOLLOUT
   epoll_event events[1];
   epoll_wait(epoll_fd, events, 1, -1);
   ```

3. **处理 `epoll_wait` 的返回值和 `errno`:**  `epoll_wait` 返回 -1 时表示出错，需要检查 `errno` 来确定错误原因。返回 0 表示超时，返回正数表示就绪事件的数量。忽略返回值和 `errno` 可能导致程序行为异常。

   ```c++
   int epoll_fd = epoll_create(1);
   // ... 添加文件描述符 ...
   epoll_event events[1];
   int nfds = epoll_wait(epoll_fd, events, 1, 100);
   if (nfds == -1) {
       perror("epoll_wait"); // 正确处理错误
   } else if (nfds == 0) {
       // 超时处理
   } else {
       // 处理事件
   }
   ```

4. **使用已关闭的文件描述符:**  如果添加到 `epoll` 实例的文件描述符被关闭，`epoll_wait` 仍然会返回事件（通常是 `EPOLLHUP` 或 `EPOLLERR`），但尝试对该文件描述符进行操作可能会失败。

   ```c++
   int epoll_fd = epoll_create(1);
   int fd = open("some_file.txt", O_RDONLY);
   epoll_event ev;
   ev.events = EPOLLIN;
   ev.data.fd = fd;
   epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
   close(fd); // 关闭了文件描述符
   epoll_event events[1];
   epoll_wait(epoll_fd, events, 1, -1); // 可能会返回 EPOLLHUP 或 EPOLLERR
   ```

5. **泄露 `epoll` 文件描述符:**  `epoll_create` 返回的文件描述符需要在使用完毕后使用 `close()` 关闭，否则可能导致资源泄露。

**Android Framework 或 NDK 如何到达这里**

以下是一个简化的路径，说明 Android Framework 或 NDK 如何最终调用到 Bionic 的 `epoll` 函数：

1. **Java Framework (e.g., Network Management Service):**
   - Android Framework 中的某些服务，例如负责网络连接管理的 `NetworkManagementService`，可能需要监听网络套接字事件。
   - 在 Java 代码中，可以使用 `java.nio.channels.Selector` 类来进行 I/O 多路复用。
   - `Selector` 的底层实现会调用 Native 代码。

2. **Native Framework (e.g., libbinder, libnetd):**
   - `Selector` 的 Native 实现通常位于 Bionic 或其他 Native 库中。
   - 例如，Binder 通信库 `libbinder` 内部会使用 `epoll` 来监听 Binder 驱动上的事件。
   - `libnetd` (网络守护进程) 也广泛使用 `epoll` 来管理网络连接。

3. **NDK (Native Development Kit):**
   - NDK 开发者可以直接使用 POSIX 标准的 `epoll` 函数。
   - 例如，一个使用 NDK 开发的网络应用程序可以直接调用 `epoll_create`, `epoll_ctl`, 和 `epoll_wait`。

4. **Bionic (Android's C library):**
   - 无论是 Framework 还是 NDK 代码调用 `epoll` 相关函数，最终都会调用到 Bionic 提供的系统调用封装。
   - Bionic 的 `epoll_create`, `epoll_wait` 等函数是对 Linux 内核 `epoll` 系统调用的封装。

5. **Linux Kernel:**
   - Bionic 的函数最终会通过系统调用接口 (`syscall`) 进入 Linux 内核，内核负责实际的 `epoll` 功能实现。

**Frida Hook 示例调试步骤**

以下是一个使用 Frida Hook 拦截 `epoll_wait` 调用的示例：

```javascript
// frida hook 脚本

// 目标进程的名称或 PID
const targetProcess = "your_app_process_name"; // 替换为你的应用进程名

// 附加到目标进程
Frida.attach(targetProcess, function(session) {
  console.log("[*] Attached to process: " + targetProcess);

  // 查找 epoll_wait 的地址
  const epoll_wait_addr = Module.findExportByName("libc.so", "epoll_wait");

  if (epoll_wait_addr) {
    console.log("[*] Found epoll_wait at: " + epoll_wait_addr);

    // 拦截 epoll_wait 函数
    Interceptor.attach(epoll_wait_addr, {
      onEnter: function(args) {
        console.log("\n[*] epoll_wait called");
        console.log("    epfd: " + args[0]);
        console.log("    events: " + args[1]);
        console.log("    maxevents: " + args[2]);
        console.log("    timeout: " + args[3]);
      },
      onLeave: function(retval) {
        console.log("[*] epoll_wait returned: " + retval);
        if (retval > 0) {
          // 可以进一步解析 events 参数
          const epoll_event_ptr = this.context.rdi.add(8); // events 参数的地址
          const num_events = retval.toInt();
          for (let i = 0; i < num_events; i++) {
            const event_data = Memory.readU64(epoll_event_ptr.add(i * 12)); // 假设 epoll_event 大小为 12 字节
            const event_type = Memory.readU32(epoll_event_ptr.add(i * 12 + 8));
            console.log(`    Event ${i + 1}: data=${event_data.toString(16)}, events=${event_type}`);
          }
        }
      }
    });
  } else {
    console.error("[!] Could not find epoll_wait in libc.so");
  }
});
```

**调试步骤：**

1. **保存脚本:** 将上述 JavaScript 代码保存到一个文件中，例如 `hook_epoll_wait.js`。
2. **运行 Frida:** 使用 Frida 命令行工具运行该脚本，并指定目标进程：
   ```bash
   frida -U -f your_app_package_name -l hook_epoll_wait.js --no-pause
   ```
   或者，如果已经知道进程的 PID：
   ```bash
   frida -p <pid> -l hook_epoll_wait.js
   ```
3. **触发 `epoll_wait` 调用:** 在目标 Android 应用程序中执行操作，使其调用到 `epoll_wait` 函数。例如，如果应用程序正在监听网络连接，可以尝试建立一个新的连接。
4. **查看 Frida 输出:** Frida 会在控制台上打印出 `epoll_wait` 函数被调用时的参数值和返回值，以及相关的事件信息。

这个 Frida Hook 示例可以帮助你理解应用程序何时调用了 `epoll_wait`，以及传递了哪些参数，这对于调试网络相关的或者其他使用 `epoll` 的功能非常有用。你可以根据需要修改脚本来 hook 其他 `epoll` 相关函数或分析更详细的数据。

Prompt: 
```
这是目录为bionic/tests/sys_epoll_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "utils.h"

TEST(sys_epoll, epoll_wait) {
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd);

  // Regular epoll_wait.
  epoll_event events[1] = {};
  ASSERT_EQ(0, epoll_wait(epoll_fd, events, 1, 1));
}

TEST(sys_epoll, epoll_pwait_no_sigset) {
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd);

  // epoll_pwait without a sigset (which is equivalent to epoll_wait).
  epoll_event events[1] = {};
  ASSERT_EQ(0, epoll_pwait(epoll_fd, events, 1, 1, nullptr));
}

TEST(sys_epoll, epoll_pwait64_no_sigset) {
#if defined(__BIONIC__)
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd);

  // epoll_pwait64 without a sigset (which is equivalent to epoll_wait).
  epoll_event events[1] = {};
  ASSERT_EQ(0, epoll_pwait64(epoll_fd, events, 1, 1, nullptr));
#else
  GTEST_SKIP() << "epoll_pwait64 is bionic-only";
#endif
}

TEST(sys_epoll, epoll_pwait2_no_sigset) {
#if defined(__BIONIC__)
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd);

  // epoll_pwait2 without a sigset (which is equivalent to epoll_wait).
  epoll_event events[1] = {};
  timespec ts = {.tv_nsec = 500};
  int rc = epoll_pwait2(epoll_fd, events, 1, &ts, nullptr);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no epoll_pwait2() in this kernel";
  ASSERT_EQ(0, rc) << strerror(errno);
#else
  GTEST_SKIP() << "epoll_pwait2 is only in glibc 2.35+";
#endif
}

TEST(sys_epoll, epoll_pwait_with_sigset) {
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd);

  // epoll_pwait with a sigset.
  epoll_event events[1] = {};
  sigset_t ss;
  sigemptyset(&ss);
  sigaddset(&ss, SIGPIPE);
  ASSERT_EQ(0, epoll_pwait(epoll_fd, events, 1, 1, &ss));
}

TEST(sys_epoll, epoll_pwait2_with_sigset) {
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd);

#if defined(__BIONIC__)
  epoll_event events[1] = {};
  timespec ts = {.tv_nsec = 500};
  sigset_t ss2;
  sigemptyset(&ss2);
  sigaddset(&ss2, SIGPIPE);
  int rc = epoll_pwait2(epoll_fd, events, 1, &ts, &ss2);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no epoll_pwait2() in this kernel";
  ASSERT_EQ(0, rc) << strerror(errno);
#else
  GTEST_SKIP() << "epoll_pwait2 is only in glibc 2.35+";
#endif
}

TEST(sys_epoll, epoll_pwait2_64_with_sigset) {
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd);

#if defined(__BIONIC__)
  epoll_event events[1] = {};
  timespec ts = {.tv_nsec = 500};
  sigset64_t ss2;
  sigemptyset64(&ss2);
  sigaddset64(&ss2, SIGPIPE);
  int rc = epoll_pwait2_64(epoll_fd, events, 1, &ts, &ss2);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no epoll_pwait2() in this kernel";
  ASSERT_EQ(0, rc) << strerror(errno);
#else
  GTEST_SKIP() << "epoll_pwait2_64 is bionic-only";
#endif
}

TEST(sys_epoll, epoll_create_invalid_size) {
  errno = 0;
  ASSERT_EQ(-1, epoll_create(0));
  ASSERT_ERRNO(EINVAL);
}

TEST(sys_epoll, epoll_event_data) {
  int epoll_fd = epoll_create(1);
  ASSERT_NE(-1, epoll_fd) << strerror(errno);

  int fds[2];
  ASSERT_NE(-1, pipe(fds));

  const uint64_t expected = 0x123456789abcdef0;

  // Get ready to poll on read end of pipe.
  epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.u64 = expected;
  ASSERT_NE(-1, epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fds[0], &ev));

  // Ensure there's something in the pipe.
  ASSERT_EQ(1, write(fds[1], "\n", 1));

  // Poll.
  epoll_event events[1];
  ASSERT_EQ(1, epoll_wait(epoll_fd, events, 1, 1));
  ASSERT_EQ(expected, events[0].data.u64);

  close(fds[0]);
  close(fds[1]);
}

TEST(sys_epoll, epoll_create1) {
  int fd;
  fd = epoll_create(1);
  ASSERT_FALSE(CloseOnExec(fd));
  close(fd);

  fd = epoll_create1(0);
  ASSERT_FALSE(CloseOnExec(fd));
  close(fd);

  fd = epoll_create1(EPOLL_CLOEXEC);
  ASSERT_TRUE(CloseOnExec(fd));
  close(fd);
}

"""

```