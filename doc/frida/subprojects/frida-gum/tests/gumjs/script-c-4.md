Response:
My thinking process for analyzing the provided code snippet went something like this:

1. **Understand the Context:** The prompt clearly states this is part of the Frida dynamic instrumentation tool, specifically a test file (`script.c`) within the `frida-gum` subproject. This immediately tells me the code is about testing Frida's functionality. The location within the `tests/gumjs` directory suggests these tests are focused on the JavaScript API (`gumjs`) interacting with the underlying Frida Gum engine.

2. **Initial Scan for Keywords and Patterns:** I quickly scanned the code for recurring keywords and patterns. I noticed:
    * `TESTCASE`: This clearly indicates the structure of the file – a collection of individual test cases.
    * `COMPILE_AND_LOAD_SCRIPT`:  This is a strong indicator that the tests involve compiling and executing JavaScript code within the Frida environment.
    * `EXPECT_SEND_MESSAGE_WITH`: This suggests the tests are verifying the output of the JavaScript code by checking for specific messages sent back from the script.
    * `Socket.type`, `Socket.localAddress`, `Socket.peerAddress`:  These point to testing Frida's API for interacting with sockets.
    * `Stalker.follow`, `Stalker.unfollow`, `Stalker.flush`, `Stalker.queueDrainInterval`, `Stalker.exclude`, `Stalker.addCallProbe`, `Stalker.invalidate`, `Stalker.parse`: These are all related to Frida's Stalker API, which is used for code tracing and instrumentation.
    * `Process.getModuleByName`, `Process.enumerateThreads`, `Process.enumerateModules`, `Process.enumerateRanges`, `Process.findModuleByAddress`, `Process.getModuleByAddress`, `Process.findModuleByName`, `Process.getRangeByAddress`, `Process.pageSize`, `Process.platform`, `Process.arch`, `Process.pointerSize`, `Process.isDebuggerAttached`, `Process.id`, `Process.getCurrentThreadId`, `Process.getCurrentDir`, `Process.getHomeDir`, `Process.getTmpDir`, `Process.setExceptionHandler`: These are all part of Frida's `Process` API, providing information about and control over the target process.
    * `NativeFunction`: This indicates testing Frida's ability to call native functions.
    * `Interceptor.attach`: This points to testing Frida's interception capabilities.
    * `Memory.protect`: This relates to testing Frida's memory manipulation features.
    * `#ifdef`, `#ifndef`: These preprocessor directives suggest platform-specific code and conditional compilation. Paying attention to the platforms mentioned (Windows, Linux, Darwin/macOS, Android, QNX) is crucial.
    * `g_assert_cmpint`, `g_assert_true`, `g_assert_nonnull`, `g_usleep`: These are GLib assertions and utility functions used for testing.
    *  Socket related system calls like `socket`, `bind`, `connect`, `close`, `send`, `recv`, `unlink`.
    * Threading primitives like `g_thread_new`, `g_thread_join`.

3. **Group Test Cases by Functionality:**  Based on the keywords and patterns, I started grouping the test cases by the Frida API they were testing. This helps in understanding the overall purpose of the file. The groupings I identified were:
    * Socket API testing (`socket_types_can_be_inspected`, `socket_endpoints_can_be_inspected`)
    * Stalker API testing (multiple test cases starting with `execution_can_be_traced`, `basic_block_can_be_invalidated`, `call_can_be_probed`, `stalker_events_can_be_parsed`)
    * Process API testing (multiple test cases starting with `frida_version_is_available`, `process_arch_is_available`, etc.)
    * Native function interaction (`execution_can_be_traced_during_immediate_native_function_call`, `execution_can_be_traced_during_scheduled_native_function_call`, `execution_can_be_traced_after_native_function_call_from_hook`)
    * Interceptor API testing (`execution_can_be_traced_after_native_function_call_from_hook`)
    * Memory API testing (`process_should_support_nested_signal_handling`)

4. **Analyze Individual Test Cases (Example):**  Let's take the `socket_types_can_be_inspected` test case as an example of how I'd break down a single test:
    * **Goal:** The name suggests it tests the ability to determine the type of a socket using Frida's API.
    * **Mechanism:**
        * It creates different types of sockets (TCP/IPv4, UDP/IPv4, TCP/IPv6, UDP/IPv6, Unix stream/dgram).
        * For each socket, it compiles and loads a JavaScript snippet: `COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);`  This calls the `Socket.type()` function in the Frida API, passing in the file descriptor of the socket.
        * It then uses `EXPECT_SEND_MESSAGE_WITH` to verify that the JavaScript code returns the correct socket type string (e.g., `"tcp4"`, `"udp6"`, `"unix:stream"`).
        * It also tests the case of an invalid file descriptor (`-1`) and a regular file to ensure `Socket.type()` handles these cases gracefully (returning `null`).
    * **Relevance to Reverse Engineering:** Knowing the type of a socket is crucial for understanding network communication in a target application. This Frida API allows reverse engineers to dynamically inspect socket types.
    * **Binary/Kernel/Framework Relation:** Creating sockets involves system calls that interact directly with the operating system kernel. The `AF_INET`, `SOCK_STREAM`, `AF_UNIX`, etc., constants are defined at the operating system level.
    * **Logic/Input/Output:** The input is a file descriptor. The expected output is a string representing the socket type or `null`.

5. **Synthesize and Summarize:** After analyzing several test cases, I began to synthesize the information and formulate a summary of the file's functionality, keeping in mind the different aspects requested in the prompt (relation to reverse engineering, binary/kernel knowledge, logic, user errors, debugging).

6. **Address Specific Prompt Questions:**  I then systematically went through each of the specific questions in the prompt:
    * **List the functions:** This involves listing the core functionalities revealed by the test cases (socket inspection, code tracing, process information, etc.).
    * **Relation to reverse engineering:** I considered how each tested Frida feature could be used in a reverse engineering context.
    * **Binary/kernel/framework knowledge:** I identified the underlying OS concepts and APIs that the tests implicitly cover.
    * **Logical reasoning (input/output):** For relevant test cases, I described the input to the JavaScript code and the expected output, highlighting the logical flow.
    * **User/programming errors:** I considered potential misuse of the Frida APIs being tested and how the tests might expose such errors (e.g., passing an invalid file descriptor).
    * **User operation leading to this code:** I described the general steps a user would take to use Frida and potentially trigger the execution of the tested code.
    * **Summarize the functionality:**  Finally, I provided a concise overview of the file's purpose.

By following these steps, I could systematically analyze the code snippet and provide a comprehensive answer to the prompt. The key was to understand the context, identify patterns, analyze individual components, and then synthesize the information to address the specific questions.
这是 `frida/subprojects/frida-gum/tests/gumjs/script.c` 文件的第 5 部分，共 11 部分。从这部分的代码来看，它主要关注 **Frida 的 JavaScript API 如何与操作系统底层资源（如套接字）进行交互**，以及 **Frida 的代码追踪功能 (Stalker)** 的各种测试。

**本部分主要功能归纳：**

1. **套接字类型检查 (Socket Type Inspection):**
   - 测试 `Socket.type()` API，用于获取给定文件描述符对应的套接字类型。
   - 支持检查 IPv4 TCP/UDP, IPv6 TCP/UDP, Unix 域套接字 (stream/dgram) 的类型。
   - 能够处理无效的文件描述符或非套接字文件。

2. **套接字端点信息检查 (Socket Endpoint Inspection):**
   - 测试 `Socket.localAddress()` 和 `Socket.peerAddress()` API，用于获取套接字的本地和远端地址信息。
   - 支持 IPv4 和 IPv6 套接字。
   - 对于 Unix 域套接字，可以获取本地路径信息。
   - 测试了在连接建立前/后的端点信息获取。

3. **代码执行追踪 (Execution Tracing with Stalker):**
   - 测试 Frida 的 `Stalker` API，用于动态追踪代码的执行流程。
   - 涵盖基本的代码追踪功能，包括追踪调用 (call)。
   - 测试了自定义转换器 (Transformer) 的使用，允许用户在代码执行过程中修改指令流或插入自定义逻辑 (Callout)。
   - 测试了转换器中抛出异常的处理。
   - 测试了在直接调用的原生函数和通过 `setImmediate` 调度的原生函数中进行代码追踪。
   - 测试了在 `Interceptor.attach` 的钩子函数中调用原生函数后进行代码追踪。
   - 测试了在 Stalker 的 Callout 中使基本块失效 (`Stalker.invalidate`)，可以针对当前线程或指定线程。
   - 测试了 `Stalker.addCallProbe()`，用于在函数调用时插入探针，获取函数参数。
   - 测试了 `Stalker.parse()`，用于解析 Stalker 捕获的事件数据。

4. **Frida 全局属性和 Process API 测试:**
   - 测试 `Frida.version` (Frida 版本信息)。
   - 测试 `Frida.heapSize` (Frida 堆大小)。
   - 测试 `Process.arch` (进程架构)。
   - 测试 `Process.platform` (操作系统平台)。
   - 测试 `Process.pageSize` (内存页大小)。
   - 测试 `Process.pointerSize` (指针大小)。
   - 测试 `Process.should_support_nested_signal_handling` (嵌套信号处理能力，Linux 特有)。
   - 测试 `Process.getCurrentDir()` (当前工作目录)。
   - 测试 `Process.getHomeDir()` (用户主目录)。
   - 测试 `Process.getTmpDir()` (临时目录)。
   - 测试 `Process.isDebuggerAttached()` (是否连接了调试器)。
   - 测试 `Process.id` (进程 ID)。
   - 测试 `Process.getCurrentThreadId()` (当前线程 ID)。
   - 测试 `Process.enumerateThreads()` (枚举进程线程)。
   - 测试 `Process.enumerateModules()` (枚举进程模块)。
   - 测试 `Process.findModuleByAddress()` 和 `Process.getModuleByAddress()` (根据地址查找模块)。
   - 测试 `Process.findModuleByName()` 和 `Process.getModuleByName()` (根据名称查找模块)。
   - 测试 `Process.enumerateRanges()` (枚举内存区域)。
   - 测试 `Process.findRangeByAddress()` 和 `Process.getRangeByAddress()` (根据地址查找内存区域)。

**与逆向方法的关系及举例说明：**

* **动态分析和监控:** Frida 本身就是一个动态分析工具。本部分测试的 `Stalker` API 直接关联代码追踪和动态行为分析。逆向工程师可以使用 `Stalker` 观察函数调用序列、代码执行路径，甚至在执行过程中修改代码行为。
    * **举例:** 使用 `Stalker.follow()` 可以追踪目标函数的调用，了解其参数和返回值，或者观察其内部执行流程，这对于理解不熟悉的代码很有帮助。
* **运行时信息获取:**  `Socket` 和 `Process` API 提供了运行时环境的关键信息，这对于理解目标进程的运行状态至关重要。
    * **举例:** 使用 `Socket.peerAddress()` 可以动态获取进程正在连接的远程服务器地址和端口，这对于分析网络协议或恶意软件的网络行为很有用。
    * **举例:** 使用 `Process.enumerateModules()` 可以获取进程加载的所有动态链接库，这有助于识别目标进程使用了哪些第三方库，为进一步的逆向分析提供线索。
* **代码插桩和修改:** `Stalker` 的转换器和 Callout 功能允许在运行时修改代码行为，这可以用于绕过安全检查、修改函数返回值或插入自定义逻辑。
    * **举例:** 在 `Stalker` 的转换器中，可以判断当前执行的指令是否为某个关键函数的入口，然后插入一个 Callout 来记录函数参数，而无需修改原始代码。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

* **文件描述符 (File Descriptor):**  `Socket.type()` 等 API 直接操作文件描述符，这是操作系统用来标识打开文件或套接字的整数。理解文件描述符是理解 Unix-like 系统 I/O 的基础。
    * **举例:** 测试代码中 `socket(AF_INET, SOCK_STREAM, 0)` 创建了一个 TCP 套接字，返回的文件描述符被传递给 `Socket.type()`。这涉及到 Linux 内核提供的套接字系统调用。
* **套接字类型和协议:** 测试代码中使用了 `AF_INET`, `AF_INET6`, `AF_UNIX`, `SOCK_STREAM`, `SOCK_DGRAM` 等常量，这些常量定义了不同类型的套接字和网络协议，是操作系统网络编程的基础知识。
    * **举例:**  `AF_INET` 表示 IPv4 地址族，`SOCK_STREAM` 表示面向连接的 TCP 协议。
* **内存管理:** `Process.pageSize` 涉及操作系统内存分页机制。`Process.enumerateRanges()` 涉及到进程的虚拟内存空间布局。
    * **举例:**  测试代码中查询的 `Process.pageSize` 与 Linux 内核的页大小设置有关。
* **进程和线程:** `Process.enumerateThreads()` 和相关的测试直接操作进程和线程的概念，这涉及操作系统进程管理和线程调度的知识。
    * **举例:** 测试代码创建了新的线程并使用 Frida API 枚举它们，这依赖于操作系统提供的线程创建和管理机制。
* **动态链接库 (Modules):** `Process.enumerateModules()` 涉及到操作系统加载和管理动态链接库的方式。
    * **举例:** 测试代码枚举进程加载的模块，这与 Linux 的 `ld-linux.so` 或 Windows 的加载器的工作方式相关。
* **信号处理:** `Process.should_support_nested_signal_handling` 测试了 Linux 特有的信号处理机制。
* **代码追踪 (Stalker):**  `Stalker` 的实现涉及到对目标进程指令流的解析、修改和回调，这需要深入理解目标平台的指令集架构 (如 ARM, x86) 和操作系统提供的调试接口或代码注入机制。

**逻辑推理、假设输入与输出：**

* **套接字类型检查:**
    * **假设输入:** 一个文件描述符 `fd`，例如通过 `socket(AF_INET, SOCK_STREAM, 0)` 创建。
    * **预期输出:**  `Socket.type(fd)` 返回字符串 `"tcp4"`。
    * **假设输入:** 文件描述符 `-1` (无效)。
    * **预期输出:** `Socket.type(-1)` 返回 `null`。
* **套接字端点信息检查:**
    * **假设输入:** 一个已连接的 TCP 套接字的文件描述符 `fd`。
    * **预期输出:** `Socket.localAddress(fd)` 返回一个包含本地 IP 地址和端口的对象，例如 `{"ip":"127.0.0.1", "port":12345}`。
    * **预期输出:** `Socket.peerAddress(fd)` 返回一个包含远端 IP 地址和端口的对象。
* **Stalker 代码追踪:**
    * **假设输入:** 使用 `Stalker.follow()` 追踪某个线程。
    * **预期输出:**  `onCallSummary` 回调会收到一个对象，其中包含了被追踪到的函数调用信息，例如函数地址和调用次数。
    * **假设输入:**  在 `Stalker` 的转换器中，`iterator.next()` 返回一个指令对象。
    * **预期输出:**  可以通过 `instruction.address` 获取指令地址，`instruction.mnemonic` 获取指令助记符等。

**用户或编程常见的使用错误及举例说明：**

* **向 `Socket.type()` 传递无效的文件描述符:**
    * **错误:** 用户传递了一个未打开的文件描述符或者一个指向非套接字的文件描述符。
    * **测试体现:** 测试代码使用了 `COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(-1));");` 和针对普通文件的测试，预期返回 `null`，这模拟了用户可能犯的错误。
* **在套接字连接建立前尝试获取远端地址:**
    * **错误:** 用户在调用 `connect()` 之前就尝试调用 `Socket.peerAddress()`。
    * **测试体现:**  `COMPILE_AND_LOAD_SCRIPT ("send(Socket.peerAddress(%d));", fd); EXPECT_SEND_MESSAGE_WITH ("null");` 这段代码测试了在连接建立前获取远端地址的情况，预期返回 `null`。
* **`Stalker` 的转换器中出现错误:**
    * **错误:** 用户在 `Stalker` 的 `transform` 函数中编写了有 bug 的代码，导致异常抛出。
    * **测试体现:** `TESTCASE (execution_can_be_traced_with_faulty_transformer)` 测试了这种情况，预期会收到错误消息。
* **不正确地使用 `Stalker.invalidate()`:**
    * **错误:**  用户可能传入错误的线程 ID 或内存地址，导致失效操作不生效。
    * **测试体现:** 虽然代码没有直接测试错误使用，但测试了针对特定线程的失效，暗示了用户需要正确指定目标。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户编写 Frida 脚本:** 用户编写一个 JavaScript 脚本，使用 Frida 的 `Socket` API 来检查目标进程打开的套接字类型，例如：
   ```javascript
   Process.enumerateThreads().forEach(thread => {
       Thread.attach(thread.id, () => {
           const fds = Process.enumerateFds();
           fds.forEach(fdInfo => {
               if (fdInfo.type === 'socket') {
                   console.log(`Socket type for fd ${fdInfo.fd}: ${Socket.type(fdInfo.fd)}`);
               }
           });
       });
   });
   ```
2. **用户运行 Frida 脚本:** 用户使用 Frida 命令行工具 (如 `frida`) 或通过编程方式将该脚本注入到目标进程。
3. **Frida 加载 GumJS 环境:** Frida 会在目标进程中加载 GumJS 引擎，用于执行用户提供的 JavaScript 代码。
4. **JavaScript 代码调用 Frida API:** 用户脚本中调用了 `Socket.type()` 等 Frida 提供的 JavaScript API。
5. **GumJS 调用 Gum 接口:** GumJS 引擎会将这些 JavaScript API 调用转换为对 Frida Gum 核心库的 C/C++ 接口调用。
6. **`script.c` 中的测试覆盖 Gum 的实现:**  `frida/subprojects/frida-gum/tests/gumjs/script.c` 中的测试用例，如 `TESTCASE (socket_types_can_be_inspected)`，实际上测试了 Gum 库中实现 `Socket.type()` 功能的代码逻辑。如果用户在使用 Frida 脚本时遇到关于 `Socket.type()` 的问题，那么很可能是 Gum 库的实现存在 bug，而 `script.c` 中的相关测试可以帮助开发者发现和修复这些 bug。

**总结：**

这部分 `script.c` 文件主要测试了 Frida 的 JavaScript API 与操作系统底层资源的交互能力，特别是套接字相关的操作，以及 Frida 的代码追踪功能 `Stalker` 的各种使用场景。它还涵盖了 Frida 提供的全局属性和 `Process` API 的基本功能。这些测试确保了 Frida 能够正确地获取和操作目标进程的运行时信息，并提供强大的动态代码分析和插桩能力。理解这些测试用例可以帮助开发者了解 Frida 的工作原理，并为用户提供调试 Frida 脚本的线索。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
ESSAGE_WITH ("\"tcp6\"");
    GUM_CLOSE_SOCKET (fd);
  }

  fd = socket (AF_INET6, SOCK_DGRAM, 0);
  if (fd != -1)
  {
    COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
    EXPECT_SEND_MESSAGE_WITH ("\"udp6\"");
    GUM_CLOSE_SOCKET (fd);
  }

  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(-1));");
  EXPECT_SEND_MESSAGE_WITH ("null");

#ifndef HAVE_WINDOWS
  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"unix:stream\"");
  close (fd);

  fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("\"unix:dgram\"");
  close (fd);

  fd = open (
# ifdef HAVE_QNX
      "/usr/lib/ldqnx.so.2",
# else
      "/etc/hosts",
# endif
      O_RDONLY);
  g_assert_cmpint (fd, >=, 0);
  COMPILE_AND_LOAD_SCRIPT ("send(Socket.type(%d));", fd);
  EXPECT_SEND_MESSAGE_WITH ("null");
  close (fd);
#endif
}

TESTCASE (socket_endpoints_can_be_inspected)
{
  GSocketFamily family[] = { G_SOCKET_FAMILY_IPV4, G_SOCKET_FAMILY_IPV6 };
  guint i;
  GMainContext * context;
  int fd;

  context = g_main_context_get_thread_default ();

  for (i = 0; i != G_N_ELEMENTS (family); i++)
  {
    GSocket * sock;
    GSocketService * service;
    GInetAddress * loopback;
    GSocketAddress * listen_address, * server_address, * client_address;
    guint16 server_port, client_port;

    sock = g_socket_new (family[i], G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP,
        NULL);
    if (sock == NULL)
      continue;
    fd = g_socket_get_fd (sock);

    service = g_socket_service_new ();
    g_signal_connect (service, "incoming", G_CALLBACK (on_incoming_connection),
        NULL);
    loopback = g_inet_address_new_loopback (family[i]);
    listen_address = g_inet_socket_address_new (loopback, 0);
    if (!g_socket_listener_add_address (G_SOCKET_LISTENER (service),
        listen_address, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL,
        &server_address, NULL))
      goto skip_unsupported_family;
    server_port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (
        server_address));
    g_socket_service_start (service);

    COMPILE_AND_LOAD_SCRIPT ("send(Socket.peerAddress(%d));", fd);
    EXPECT_SEND_MESSAGE_WITH ("null");

    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);

    g_assert_true (g_socket_connect (sock, server_address, NULL, NULL));

    g_object_get (sock, "local-address", &client_address, NULL);
    client_port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (
        client_address));

    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);

    COMPILE_AND_LOAD_SCRIPT (
        "const addr = Socket.localAddress(%d);"
        "send([typeof addr.ip, addr.port]);", fd);
    EXPECT_SEND_MESSAGE_WITH ("[\"string\",%u]", client_port);

    COMPILE_AND_LOAD_SCRIPT (
        "const addr = Socket.peerAddress(%d);"
        "send([typeof addr.ip, addr.port]);", fd);
    EXPECT_SEND_MESSAGE_WITH ("[\"string\",%u]", server_port);

    g_socket_close (sock, NULL);
    g_socket_service_stop (service);
    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);

    g_object_unref (client_address);
    g_object_unref (server_address);

skip_unsupported_family:
    g_object_unref (listen_address);
    g_object_unref (loopback);
    g_object_unref (service);

    g_object_unref (sock);
  }

#ifdef HAVE_DARWIN
  {
    struct sockaddr_un address;
    socklen_t len;

    fd = socket (AF_UNIX, SOCK_STREAM, 0);

    address.sun_family = AF_UNIX;
    strcpy (address.sun_path, "/tmp/gum-script-test");
    unlink (address.sun_path);
    address.sun_len = sizeof (address) - sizeof (address.sun_path) +
        strlen (address.sun_path) + 1;
    len = address.sun_len;
    bind (fd, (struct sockaddr *) &address, len);

    COMPILE_AND_LOAD_SCRIPT ("send(Socket.localAddress(%d));", fd);
    EXPECT_SEND_MESSAGE_WITH ("{\"path\":\"\"}");
    close (fd);

    unlink (address.sun_path);
  }
#endif
}

static gboolean
on_incoming_connection (GSocketService * service,
                        GSocketConnection * connection,
                        GObject * source_object,
                        gpointer user_data)
{
  GInputStream * input;
  void * buf;

  input = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  buf = g_malloc (1);
  g_input_stream_read_async (input, buf, 1, G_PRIORITY_DEFAULT, NULL,
      on_read_ready, g_object_ref (connection));

  return TRUE;
}

static void
on_read_ready (GObject * source_object,
               GAsyncResult * res,
               gpointer user_data)
{
  GSocketConnection * connection = user_data;

  GError * error = NULL;
  g_input_stream_read_finish (G_INPUT_STREAM (source_object), res, &error);
  g_clear_error (&error);

  g_io_stream_close_async (G_IO_STREAM (connection), G_PRIORITY_LOW, NULL,
      NULL, NULL);
  g_object_unref (connection);
}

#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)

#include "stalkerdummychannel.h"

TESTCASE (execution_can_be_traced)
{
  GumThreadId test_thread_id;

#ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "Stalker.queueDrainInterval = 0;"
      "const testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  events: {"
      "    call: true,"
      "    ret: false,"
      "    exec: false"
      "  },"
      "  onReceive(events) {"
      "    send('onReceive: ' + (events.byteLength > 0));"
      "  },"
      "  onCallSummary(summary) {"
      "    send('onCallSummary: ' + (Object.keys(summary).length > 0));"
      "  }"
      "});"

      "recv('stop', message => {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  Stalker.flush();"
      "});",

      GUM_TESTS_MODULE_NAME,
      test_thread_id,
      test_thread_id);
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"onCallSummary: true\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onReceive: true\"");
}

TESTCASE (execution_can_be_traced_with_custom_transformer)
{
  GumThreadId test_thread_id;

#if defined (HAVE_QNX) || defined (__ARM_PCS_VFP)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "const testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "let instructionsSeen = 0;"
      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform(iterator) {"
      "    let instruction;"

      "    while ((instruction = iterator.next()) !== null) {"
      "      if (instructionsSeen === 0) {"
      "        send(typeof iterator.memoryAccess);"
      "        iterator.putCallout(onBeforeFirstInstruction);"
      "      }"

      "      iterator.keep();"

      "      instructionsSeen++;"
      "    }"
      "  }"
      "});"

      "function onBeforeFirstInstruction (context) {"
      "  console.log(JSON.stringify(context, null, 2));"
      "}"

      "recv('stop', message => {"
      "  Stalker.unfollow(%" G_GSIZE_FORMAT ");"
      "  send(instructionsSeen > 0);"
      "});",

      GUM_TESTS_MODULE_NAME,
      test_thread_id,
      test_thread_id);
  g_usleep (1);
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (execution_can_be_traced_with_faulty_transformer)
{
  GumThreadId test_thread_id;

#ifdef HAVE_QNX
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  test_thread_id = gum_process_get_current_thread_id ();

  COMPILE_AND_LOAD_SCRIPT (
      "const testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "Stalker.follow(%" G_GSIZE_FORMAT ", {"
      "  transform(iterator) {"
      "    throw new Error('oh no I am buggy');"
      "  }"
      "});",

      GUM_TESTS_MODULE_NAME,
      test_thread_id);
  g_usleep (1);
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: oh no I am buggy");
  EXPECT_NO_MESSAGES ();

  g_assert (
      !gum_stalker_is_following_me (gum_script_get_stalker (fixture->script)));
}

TESTCASE (execution_can_be_traced_during_immediate_native_function_call)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Stalker.queueDrainInterval = 0;"
      "const testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "const a = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int'], "
          "{ traps: 'all', exceptions: 'propagate' });"

      "Stalker.follow({"
      "  events: {"
      "    call: true,"
      "  },"
      "  onCallSummary(summary) {"
      "    const key = a.strip().toString();"
      "    send(key in summary);"
      "    send(summary[key]);"
      "  }"
      "});"

      "a(42);"
      "a(42);"

      "Stalker.unfollow();"
      "Stalker.flush();",

      GUM_TESTS_MODULE_NAME,
      target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (execution_can_be_traced_during_scheduled_native_function_call)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Stalker.queueDrainInterval = 0;"
      "const testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "const a = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int'], "
          "{ traps: 'all' });"

      "Stalker.follow({"
      "  events: {"
      "    call: true,"
      "  },"
      "  onCallSummary(summary) {"
      "    const key = a.strip().toString();"
      "    send(key in summary);"
      "    send(summary[key]);"
      "  }"
      "});"

      "setImmediate(() => {"
        "a(42);"
        "a(42);"

        "Stalker.unfollow();"
        "Stalker.flush();"
      "});",

      GUM_TESTS_MODULE_NAME,
      target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (execution_can_be_traced_after_native_function_call_from_hook)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

#ifdef __ARM_PCS_VFP
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target",
      run_stalked_through_hooked_function, &channel);
  thread_id = sdc_await_thread_id (&channel);

  COMPILE_AND_LOAD_SCRIPT (
      "Stalker.queueDrainInterval = 0;"
      "const testsRange = Process.getModuleByName('%s');"
      "Stalker.exclude(testsRange);"

      "const targetThreadId = %" G_GSIZE_FORMAT ";"
      "const targetFuncInt = " GUM_PTR_CONST ";"
      "const targetFuncNestedA = new NativeFunction(" GUM_PTR_CONST ", 'int', "
          "['int'], { traps: 'all' });"

      "Interceptor.attach(targetFuncInt, () => {"
      "  targetFuncNestedA(1337);"
      "});"

      "Stalker.follow(targetThreadId, {"
      "  events: {"
      "    call: true,"
      "  },"
      "  onCallSummary(summary) {"
      "    const key = targetFuncNestedA.strip().toString();"
      "    send(key in summary);"
      "    send(summary[key]);"
      "  }"
      "});"

      "recv('stop', message => {"
      "  Stalker.unfollow(targetThreadId);"
      "  Stalker.flush();"
      "});"

      "send('ready');",

      GUM_TESTS_MODULE_NAME,
      thread_id,
      target_function_int,
      target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");

  EXPECT_NO_MESSAGES ();
  sdc_put_follow_confirmation (&channel);

  sdc_await_run_confirmation (&channel);

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();

  sdc_put_finish_confirmation (&channel);

  g_thread_join (thread);

  sdc_finalize (&channel);
}

static gpointer
run_stalked_through_hooked_function (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  target_function_int (42);

  target_function_nested_a (1338);

  sdc_put_run_confirmation (channel);

  sdc_await_finish_confirmation (channel);

  return NULL;
}

TESTCASE (basic_block_can_be_invalidated_for_current_thread)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

#if (defined (HAVE_ANDROID) && defined (HAVE_ARM)) || defined (HAVE_QNX)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target",
      run_stalked_through_block_invalidated_in_callout, &channel);
  thread_id = sdc_await_thread_id (&channel);

  COMPILE_AND_LOAD_SCRIPT (
      "const targetThreadId = %" G_GSIZE_FORMAT ";"
      "const targetFuncInt = " GUM_PTR_CONST ";"

      "let instrumentationVersion = 0;"
      "let calls = 0;"

      "Stalker.follow(targetThreadId, {"
      "  transform(iterator) {"
      "    let i = 0;"
      "    let instruction;"
      "    while ((instruction = iterator.next()) !== null) {"
      "      if (i === 0 && instruction.address.equals(targetFuncInt)) {"
      "        const v = instrumentationVersion++;"
      "        iterator.putCallout(() => {"
      "          send(`f() version=${v}`);"
      "          if (++calls === 3) {"
      "            Stalker.invalidate(targetFuncInt);"
      "          }"
      "        });"
      "      }"

      "      iterator.keep();"

      "      i++;"
      "    }"
      "  }"
      "});"

      "recv('stop', message => {"
      "  Stalker.unfollow(targetThreadId);"
      "  Stalker.flush();"
      "});"

      "send('ready');",

      thread_id,
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");

  EXPECT_NO_MESSAGES ();
  sdc_put_follow_confirmation (&channel);

  EXPECT_SEND_MESSAGE_WITH ("\"f() version=0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"f() version=0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"f() version=0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"f() version=1\"");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_NO_MESSAGES ();

  sdc_put_finish_confirmation (&channel);

  g_thread_join (thread);

  sdc_finalize (&channel);
}

static gpointer
run_stalked_through_block_invalidated_in_callout (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  target_function_int (42);
  target_function_int (42);
  target_function_int (42);

  target_function_int (42);

  sdc_await_finish_confirmation (channel);

  return NULL;
}

TESTCASE (basic_block_can_be_invalidated_for_specific_thread)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

#if (defined (HAVE_ANDROID) && defined (HAVE_ARM)) || defined (HAVE_QNX)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target",
      run_stalked_through_block_invalidated_by_request, &channel);
  thread_id = sdc_await_thread_id (&channel);

  COMPILE_AND_LOAD_SCRIPT (
      "const targetThreadId = %" G_GSIZE_FORMAT ";"
      "const targetFuncInt = " GUM_PTR_CONST ";"

      "let instrumentationVersion = 0;"

      "Stalker.follow(targetThreadId, {"
      "  transform(iterator) {"
      "    let i = 0;"
      "    let instruction;"
      "    while ((instruction = iterator.next()) !== null) {"
      "      if (i === 0 && instruction.address.equals(targetFuncInt)) {"
      "        const v = instrumentationVersion++;"
      "        iterator.putCallout(() => {"
      "          send(`f() version=${v}`);"
      "        });"
      "      }"

      "      iterator.keep();"

      "      i++;"
      "    }"
      "  }"
      "});"

      "recv('invalidate', message => {"
      "  Stalker.invalidate(targetThreadId, targetFuncInt);"
      "  send('invalidated');"
      "});"

      "recv('stop', message => {"
      "  Stalker.unfollow(targetThreadId);"
      "  Stalker.flush();"
      "});"

      "send('ready');",

      thread_id,
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");

  EXPECT_NO_MESSAGES ();
  sdc_put_follow_confirmation (&channel);

  EXPECT_SEND_MESSAGE_WITH ("\"f() version=0\"");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"invalidate\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"invalidated\"");
  EXPECT_NO_MESSAGES ();

  sdc_put_run_confirmation (&channel);
  EXPECT_SEND_MESSAGE_WITH ("\"f() version=1\"");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"stop\"}");
  EXPECT_NO_MESSAGES ();

  sdc_put_finish_confirmation (&channel);

  g_thread_join (thread);

  sdc_finalize (&channel);
}

static gpointer
run_stalked_through_block_invalidated_by_request (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  target_function_int (42);

  sdc_await_run_confirmation (channel);

  target_function_int (42);

  sdc_await_finish_confirmation (channel);

  return NULL;
}

TESTCASE (call_can_be_probed)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target",
      run_stalked_through_target_function, &channel);
  thread_id = sdc_await_thread_id (&channel);

  COMPILE_AND_LOAD_SCRIPT (
      "const targetThreadId = %" G_GSIZE_FORMAT ";"

      "Stalker.addCallProbe(" GUM_PTR_CONST ", args => {"
      "  send(args[0].toInt32());"
      "});"

      "Stalker.follow(targetThreadId);"

      "recv('stop', message => {"
      "  Stalker.unfollow(targetThreadId);"
      "});"

      "send('ready');",

      thread_id,
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");

  EXPECT_NO_MESSAGES ();
  sdc_put_follow_confirmation (&channel);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  POST_MESSAGE ("{\"type\":\"stop\"}");

  g_thread_join (thread);

  sdc_finalize (&channel);
}

static gpointer
run_stalked_through_target_function (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  target_function_int (1337);

  return NULL;
}

#endif

TESTCASE (stalker_events_can_be_parsed)
{
  GumEvent ev;

  ev.type = GUM_CALL;
  ev.call.location = GSIZE_TO_POINTER (7);
  ev.call.target = GSIZE_TO_POINTER (12);
  ev.call.depth = 42;
  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(" GUM_PTR_CONST ".readByteArray("
      "%" G_GSIZE_FORMAT ")));", &ev, sizeof (ev));
  EXPECT_SEND_MESSAGE_WITH ("[[\"call\",\"0x7\",\"0xc\",42]]");

  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(new ArrayBuffer(0)));");
  EXPECT_SEND_MESSAGE_WITH ("[]");

  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(new ArrayBuffer(1)));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid buffer shape");

  COMPILE_AND_LOAD_SCRIPT ("send(Stalker.parse(new ArrayBuffer(%" G_GSIZE_FORMAT
      ")));", sizeof (GumEvent));
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid event type");
}

TESTCASE (frida_version_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Frida.version);");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
}

TESTCASE (frida_heap_size_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Frida.heapSize);");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
}

TESTCASE (process_arch_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.arch);");
#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  EXPECT_SEND_MESSAGE_WITH ("\"ia32\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"x64\"");
# endif
#elif defined (HAVE_ARM)
  EXPECT_SEND_MESSAGE_WITH ("\"arm\"");
#elif defined (HAVE_ARM64)
  EXPECT_SEND_MESSAGE_WITH ("\"arm64\"");
#endif
}

TESTCASE (process_platform_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.platform);");
#if defined (HAVE_LINUX)
  EXPECT_SEND_MESSAGE_WITH ("\"linux\"");
#elif defined (HAVE_DARWIN)
  EXPECT_SEND_MESSAGE_WITH ("\"darwin\"");
#elif defined (HAVE_WINDOWS)
  EXPECT_SEND_MESSAGE_WITH ("\"windows\"");
#endif
}

TESTCASE (process_page_size_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.pageSize);");
  EXPECT_SEND_MESSAGE_WITH ("%d", gum_query_page_size ());
}

TESTCASE (process_pointer_size_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.pointerSize);");
  EXPECT_SEND_MESSAGE_WITH (G_STRINGIFY (GLIB_SIZEOF_VOID_P));
}

TESTCASE (process_should_support_nested_signal_handling)
{
#ifdef HAVE_LINUX
  gpointer page;

  if (!check_exception_handling_testable ())
    return;

  page = gum_alloc_n_pages (1, GUM_PAGE_NO_ACCESS);

  COMPILE_AND_LOAD_SCRIPT ("Process.setExceptionHandler(details => {"
          "Memory.protect(" GUM_PTR_CONST ", Process.pageSize, 'rw-');"
          "try {"
              "ptr(42).readU8();"
          "} catch (e) {"
              "send('error');"
          "};"
          "return true;"
      "});", page);

  *((guint8 *) page) = 1;
  EXPECT_SEND_MESSAGE_WITH ("\"error\"");

  gum_free_pages ((gpointer) page);
#else
  g_print ("<skipping, only supported on Linux for now> ");
#endif
}

TESTCASE (process_current_dir_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Process.getCurrentDir());");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
}

TESTCASE (process_home_dir_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Process.getHomeDir());");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
}

TESTCASE (process_tmp_dir_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Process.getTmpDir());");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
}

TESTCASE (process_debugger_status_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(Process.isDebuggerAttached());");
  if (gum_process_is_debugger_attached ())
    EXPECT_SEND_MESSAGE_WITH ("true");
  else
    EXPECT_SEND_MESSAGE_WITH ("false");
}

TESTCASE (process_id_is_available)
{
  TestScriptMessageItem * item;
  gint pid;

  COMPILE_AND_LOAD_SCRIPT ("send(Process.id);");

  item = test_script_fixture_pop_message (fixture);
  pid = 0;
  sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &pid);
  g_assert_cmpint (pid, ==, gum_process_get_id ());
  test_script_message_item_free (item);
}

TESTCASE (process_current_thread_id_is_available)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Process.getCurrentThreadId());");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
}

TESTCASE (process_threads_can_be_enumerated)
{
#ifdef HAVE_LINUX
  if (!check_exception_handling_testable ())
    return;
#endif

#ifdef HAVE_MIPS
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "const threads = Process.enumerateThreads();"
      "send(threads.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_threads_can_be_enumerated_legacy_style)
{
  gboolean done = FALSE;
  GThread * thread_a, * thread_b;

#ifdef HAVE_LINUX
  if (!check_exception_handling_testable ())
    return;
#endif

#if defined (HAVE_MIPS)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateThreads({"
        "onMatch(thread) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  thread_a = g_thread_new ("script-test-sleeping-dummy-a", sleeping_dummy,
      &done);
  thread_b = g_thread_new ("script-test-sleeping-dummy-b", sleeping_dummy,
      &done);

  COMPILE_AND_LOAD_SCRIPT ("send(Process.enumerateThreadsSync().length >= 2);");
  EXPECT_SEND_MESSAGE_WITH ("true");

  done = TRUE;
  g_thread_join (thread_b);
  g_thread_join (thread_a);
}

static gpointer
sleeping_dummy (gpointer data)
{
  volatile gboolean * done = (gboolean *) data;

  while (!(*done))
    g_thread_yield ();

  return NULL;
}

TESTCASE (process_threads_have_names)
{
#if defined (HAVE_LINUX) && !defined (HAVE_PTHREAD_SETNAME_NP)
  g_print ("<skipping, libc is too old> ");
#else
  GumNamedSleeperContext ctx;
  GThread * thread;

# ifdef HAVE_LINUX
  if (!check_exception_handling_testable ())
    return;
# endif

# ifdef HAVE_MIPS
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
# endif

  ctx.controller_messages = g_async_queue_new ();
  ctx.sleeper_messages = g_async_queue_new ();

  thread = g_thread_new ("named-sleeper", named_sleeper, &ctx);
  g_assert_cmpstr (g_async_queue_pop (ctx.controller_messages), ==, "ready");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateThreads().some(t => t.name === 'named-sleeper'));"
  );
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  g_async_queue_push (ctx.sleeper_messages, "done");
  g_thread_join (thread);

  g_async_queue_unref (ctx.sleeper_messages);
  g_async_queue_unref (ctx.controller_messages);
#endif
}

static gpointer
named_sleeper (gpointer data)
{
  GumNamedSleeperContext * ctx = data;

  /*
   * On Linux g_thread_new() may not actually set the thread name, which is due
   * to GLib potentially having been prebuilt against an old libc. Therefore we
   * set the name manually using pthreads.
   */
#if defined (HAVE_LINUX) && defined (HAVE_PTHREAD_SETNAME_NP)
  pthread_setname_np (pthread_self (), "named-sleeper");
#endif

  g_async_queue_push (ctx->controller_messages, "ready");

  g_assert_cmpstr (g_async_queue_pop (ctx->sleeper_messages), ==, "done");

  return NULL;
}

TESTCASE (process_modules_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const modules = Process.enumerateModules();"
      "send(modules.length > 0);"
      "const m = modules[0];"
      "send(typeof m.name === 'string');"
      "send(typeof m.path === 'string');"
      "send(m.base instanceof NativePointer);"
      "send(typeof m.size === 'number');"
      "send(JSON.stringify(m) !== \"{}\");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_modules_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateModules({"
        "onMatch(module) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT ("send(Process.enumerateModulesSync().length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_module_can_be_looked_up_from_address)
{
#ifndef HAVE_LINUX
  gpointer f;

  f = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT));
  g_assert_nonnull (f);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findModuleByAddress(" GUM_PTR_CONST ".strip()) !== null);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getModuleByAddress(" GUM_PTR_CONST
      ".strip())).length > 0);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "const someModule = Process.enumerateModules()[1];"
      "const foundModule = Process.findModuleByAddress(someModule.base);"
      "send(foundModule !== null);"
      "send(foundModule.name === someModule.name);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const map = new ModuleMap();"
      "const someModule = Process.enumerateModules()[1];"

      "send(map.has(someModule.base));"
      "send(map.has(ptr(1)));"

      "let foundModule = map.find(someModule.base);"
      "send(foundModule !== null);"
      "send(foundModule.name === someModule.name);"
      "send(map.find(ptr(1)));"

      "map.update();"
      "foundModule = map.get(someModule.base);"
      "send(foundModule.name === someModule.name);"
      "try {"
      "  map.get(ptr(1));"
      "} catch (e) {"
      "  send(e.message);"
      "}"

      "send(map.findName(someModule.base) === someModule.name);"
      "send(map.findName(ptr(1)));"
      "send(map.getName(someModule.base) === someModule.name);"
      "try {"
      "  map.getName(ptr(1));"
      "} catch (e) {"
      "  send(e.message);"
      "}"

      "send(map.findPath(someModule.base) === someModule.path);"
      "send(map.findPath(ptr(1)));"
      "send(map.getPath(someModule.base) === someModule.path);"
      "try {"
      "  map.getPath(ptr(1));"
      "} catch (e) {"
      "  send(e.message);"
      "}");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("null");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"unable to find module containing 0x1\"");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"unable to find module containing 0x1\"");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"unable to find module containing 0x1\"");

  EXPECT_NO_MESSAGES ();

#ifdef HAVE_DARWIN
  COMPILE_AND_LOAD_SCRIPT (
      "const systemModule = Process.enumerateModules()"
      "  .filter(m => m.path.startsWith('/System/'))[0];"
      "const map = new ModuleMap(m => !m.path.startsWith('/System/'));"
      "const foundModule = map.find(systemModule.base);"
      "send(foundModule === null);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#endif
}

TESTCASE (process_module_can_be_looked_up_from_name)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findModuleByName('%s') !== null);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getModuleByName('%s')).length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const ranges = Process.enumerateRanges('--x');"
      "send(ranges.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_ranges_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateRanges('--x', {"
        "onMatch(range) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateRangesSync('--x').length > 1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_ranges_can_be_enumerated_with_neighbors_coalesced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const a = Process.enumerateRanges('--x');"
      "const b = Process.enumerateRanges({"
        "protection: '--x',"
        "coalesce: true"
      "});"
      "send(b.length <= a.length);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_range_can_be_looked_up_from_address)
{
  gpointer f;

  f = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT));
  g_assert_nonnull (f);

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.findRangeByAddress(" GUM_PTR_CONST ".strip()) !== null);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "const someRange = Process.enumerateRanges('r-x')[1];"
      "const foundRange = Process.findRangeByAddress(someRange.base);"
      "send(foundRange !== null);"
      "send(foundRange.base.equals(someRange.base));");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "send(Object.keys(Process.getRangeByAddress(" GUM_PTR_CONST
      ".strip())).length > 0);",
      f);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#ifdef HAVE_DARWIN

TESTCASE (process_malloc_ranges_can_be_enumerated)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    ret
```