Response:
Let's break down the thought process for analyzing the provided C++ code snippet for Frida.

**1. Initial Skim and Identification of Key Areas:**

The first step is to quickly read through the code, looking for recognizable patterns and keywords. This helps in forming a high-level understanding. Some initial observations:

* **Includes:**  Headers like `gumv8socket.h`, `gumv8macros.h`, `gio/gnetworking.h`,  and system-specific headers (`errno.h`, `unistd.h` or Windows equivalents) strongly suggest network/socket functionality interacting with the V8 JavaScript engine.
* **Namespaces:** `using namespace v8;` confirms the V8 interaction.
* **Structs:**  `GumV8ListenOperation`, `GumV8ConnectOperation`, etc., appear to represent asynchronous operations related to sockets. The presence of `GumV8ModuleOperation` and `GumV8ObjectOperation` suggests a framework for managing these operations.
* **Function Declarations:**  `GUMJS_DECLARE_FUNCTION`, `GUMJS_DEFINE_FUNCTION`, `GUMJS_DECLARE_CONSTRUCTOR` point to the creation of JavaScript-callable functions and constructors within the Frida environment. The names themselves (e.g., `gumjs_socket_listen`, `gumjs_socket_connect`) are very telling.
* **Callbacks and Async:** The presence of `GAsyncReadyCallback` and functions like `g_socket_client_connect_async` strongly indicate asynchronous operations and callback mechanisms.
* **Object Creation:** Functions like `gum_v8_socket_listener_new` and `gum_v8_socket_connection_new` suggest the creation of JavaScript objects representing socket listeners and connections.
* **Platform Differences:** The `#ifdef HAVE_WINDOWS` and `#ifdef G_OS_UNIX` sections highlight platform-specific implementations.

**2. Focusing on Functionality:**

Next, focus on the `GUMJS_DEFINE_FUNCTION` blocks. These are the entry points from the JavaScript side. Analyze what each function does:

* **`gumjs_socket_listen`:** Takes arguments like `family`, `host`, `port`, `path`, `backlog`, and a callback. It uses `g_socket_listener_add_address` or `g_socket_listener_add_inet_port` to start listening on a socket. This clearly implements the server-side socket functionality.
* **`gumjs_socket_connect`:**  Takes `family`, `host`, `port`, `path`, `tls`, and a callback. It uses `g_socket_client_connect_async` to initiate a connection. This is the client-side.
* **`gumjs_socket_get_type`:** Takes a file descriptor (integer) and uses `getsockopt` to determine the socket type (TCP, UDP, Unix socket). This is for introspection.
* **`gumjs_socket_get_local_address` and `gumjs_socket_get_peer_address`:** Take a file descriptor and use `getsockname` and `getpeername` respectively to retrieve socket addresses. More introspection.
* **`gumjs_socket_listener_close`:** Closes a socket listener using `g_socket_listener_close`.
* **`gumjs_socket_listener_accept`:**  Asynchronously accepts a new connection on a listener using `g_socket_listener_accept_async`.
* **`gumjs_socket_connection_set_no_delay`:**  Sets the `TCP_NODELAY` option on a socket connection using `g_socket_set_option`.

**3. Connecting to Reverse Engineering:**

Now, think about how these functions would be *used* in a reverse engineering context. Consider typical tasks:

* **Intercepting Network Traffic:** The `connect` and `listen` functions are prime candidates for interception. A reverse engineer could hook these functions to observe connection attempts or to set up a "honeypot" listener to capture incoming connections.
* **Analyzing Communication Protocols:**  Once a connection is established, the data flowing through it is of interest. While this file doesn't handle the data transfer itself (that's likely in `gumv8stream.cpp`), the establishment of the connection is a crucial first step.
* **Modifying Behavior:**  By hooking `connect`, a reverse engineer could redirect connections to different servers. By hooking `listen`, they could prevent the application from listening on certain ports.
* **Gaining Internal Information:** Functions like `get_type`, `get_local_address`, and `get_peer_address` can reveal details about the application's network configuration.

**4. Identifying Binary/Kernel/Framework Interactions:**

Look for system calls or interactions with OS-level APIs.

* **Socket API:** Functions like `getsockopt`, `getsockname`, `getpeername`, `bind` are all standard socket API calls.
* **GIO:** The use of `gio/gnetworking.h`, `GSocketListener`, `GSocketClient`, etc., indicates reliance on the GLib I/O library, which provides cross-platform abstractions for network operations.
* **Platform Differences:** The `#ifdef` blocks clearly show adaptations for Windows and Unix-like systems. This often involves different system calls or library functions (e.g., `WSAAddressToStringW` on Windows vs. `inet_ntop` on Unix).
* **Kernel Interaction (Implicit):**  While not directly calling `syscall()`, the underlying socket functions eventually translate into kernel-level system calls.

**5. Logical Reasoning and Examples:**

Think about the flow of data and control. Consider a simple scenario:

* **Hypothetical Input:**  A Frida script calls `Socket._connect('ipv4', '127.0.0.1', 8080, null, null, false, function(error, connection) { ... });`
* **Expected Flow:**
    1. `gumjs_socket_connect` is called.
    2. `gum_v8_connect_operation_start` is executed, creating a `GSocketClient`.
    3. `g_socket_client_connect_to_host_async` initiates the asynchronous connection attempt.
    4. When the connection succeeds or fails, `gum_v8_connect_operation_finish` is called.
    5. The JavaScript callback function receives either an error or a `SocketConnection` object.

**6. Common User/Programming Errors:**

Consider mistakes developers might make when using this API:

* **Incorrect Argument Types:** Passing a number as a hostname, for example. The `_gum_v8_args_parse` function is designed to catch some of these.
* **Invalid Host/Port:**  Providing a non-existent hostname or port. This will likely result in an error callback.
* **Permissions Issues:**  Trying to listen on a privileged port without sufficient permissions.
* **Not Handling Errors:**  Forgetting to check the `error` argument in the callbacks.
* **Resource Leaks:**  Not closing listeners or connections properly.

**7. Tracing User Operations (Debugging):**

Imagine a user trying to connect to a server:

1. **Frida Script:** The user writes a Frida script using the `Socket` API to connect to a specific address and port.
2. **`Socket._connect()` Call:** The script executes, calling the JavaScript `Socket._connect` function.
3. **Native Function Invocation:** This call bridges to the native C++ function `gumjs_socket_connect`.
4. **Operation Setup:**  `gumjs_socket_connect` creates a `GumV8ConnectOperation` to manage the asynchronous operation.
5. **GIO Call:**  The `g_socket_client_connect_async` function from GIO is invoked.
6. **OS-Level Connection:** The operating system handles the actual TCP handshake or socket connection.
7. **Callback Invocation:** When the connection attempt completes (success or failure), the `gum_v8_connect_operation_finish` callback is triggered.
8. **JavaScript Callback Execution:** The JavaScript callback function defined in the Frida script is executed, receiving the result.

By following this chain of events, a debugger could be used at each step to inspect variables, function arguments, and the state of the system, helping to pinpoint issues.

This systematic approach, starting with a broad overview and then drilling down into specific functionalities and their implications, allows for a comprehensive understanding of the code's role within the Frida framework.
这个C++源代码文件 `gumv8socket.cpp` 是 Frida 动态 instrumentation 工具中 `frida-gum` 组件的一部分，专门负责提供在 JavaScript 中操作网络套接字 (sockets) 的功能。它将底层的套接字操作封装起来，使得 Frida 脚本可以通过 V8 引擎调用这些功能。

以下是该文件的主要功能分解：

**1. 提供 JavaScript 接口用于创建和管理套接字:**

* **监听 (Listen):**  `gumjs_socket_listen` 函数允许 JavaScript 代码创建一个监听套接字，可以指定网络协议族 (IPv4, IPv6, Unix)，主机地址/路径，端口号，以及 backlog 队列大小。
* **连接 (Connect):** `gumjs_socket_connect` 函数允许 JavaScript 代码连接到远程主机或本地 Unix 套接字。可以指定协议族，主机地址/路径，端口号，以及是否使用 TLS。
* **获取套接字类型 (Get Type):** `gumjs_socket_get_type` 函数允许获取现有套接字的类型，例如 "tcp", "udp", "tcp6", "udp6", "unix:stream", "unix:dgram"。
* **获取本地地址 (Get Local Address):** `gumjs_socket_get_local_address` 函数获取套接字的本地地址和端口。
* **获取对端地址 (Get Peer Address):** `gumjs_socket_get_peer_address` 函数获取已连接套接字的对端地址和端口。
* **关闭监听器 (Close Listener):** `gumjs_socket_listener_close` 函数关闭一个监听套接字。
* **接受连接 (Accept):** `gumjs_socket_listener_accept` 函数异步地接受来自客户端的连接请求。
* **设置 No Delay (Set No Delay):** `gumjs_socket_connection_set_no_delay` 函数用于设置 TCP_NODELAY 选项，禁用 Nagle 算法，从而减少延迟。

**2. 异步操作管理:**

* 该文件大量使用了异步操作 (`_async`) 和回调函数。例如，`gumjs_socket_listen` 和 `gumjs_socket_connect` 都以异步方式执行，并在操作完成时调用 JavaScript 中提供的回调函数。
* 使用 `GumV8ListenOperation` 和 `GumV8ConnectOperation` 等结构体来管理异步操作的状态和数据。
* 利用 GLib 的异步机制 (`g_socket_listener_add_address`, `g_socket_client_connect_async`, `g_socket_listener_accept_async`) 来执行非阻塞的套接字操作。

**3. 与 V8 JavaScript 引擎集成:**

* 使用 `GUMJS_DECLARE_FUNCTION` 和 `GUMJS_DEFINE_FUNCTION` 宏来声明和定义可以从 JavaScript 调用的函数。
* 使用 V8 的 API (`Local<Value>`, `String::NewFromUtf8`, `Object::New`, `Function::Call`) 来处理 JavaScript 的参数和返回值。
* 创建 JavaScript 的类和对象，例如 `SocketListener` 和 `SocketConnection`，并在 C++ 中管理它们的生命周期。

**4. 跨平台兼容性:**

* 使用条件编译 (`#ifdef HAVE_WINDOWS`, `#ifdef G_OS_UNIX`) 来处理不同操作系统之间的差异，例如套接字选项和地址结构。
* 依赖 GLib 库提供的跨平台套接字抽象 (`GSocket`, `GSocketAddress`, `GSocketListener`, `GSocketClient`)。

**与逆向方法的关系及举例说明:**

该文件提供的功能对于逆向工程非常有用，因为它允许逆向工程师在运行时与目标应用程序的网络通信进行交互和分析。

* **拦截和修改网络通信:** 逆向工程师可以使用 `Socket.listen` 创建一个本地监听器，模拟服务器的行为，拦截目标应用程序发送的网络请求。反之，可以使用 `Socket.connect` 连接到目标应用程序，并发送自定义的数据包。
    * **例子:**  假设一个应用程序连接到 `api.example.com:8080`。逆向工程师可以使用 Frida 脚本 hook `Socket.connect` 函数，当检测到连接到该地址时，阻止连接并使用 `Socket.listen` 在本地启动一个监听器，监听 8080 端口，然后分析应用程序尝试发送的数据。
* **动态分析网络协议:** 通过监听网络端口和连接到目标应用程序，逆向工程师可以观察应用程序的网络行为，分析其使用的网络协议。
    * **例子:** 使用 `Socket.listen` 监听某个端口，然后运行目标应用程序，观察是否有连接请求到来，并使用 `SocketConnection` 对象接收数据，从而分析应用程序使用的自定义协议格式。
* **模拟网络环境:**  在没有实际网络连接的情况下，可以模拟网络环境来测试应用程序的健壮性或发现潜在的安全漏洞。
    * **例子:**  使用 `Socket.listen` 创建一个监听器，并返回特定的错误或延迟响应，以测试应用程序对网络异常的处理能力。
* **Fuzzing 网络接口:**  通过 `Socket.connect` 连接到目标应用程序，并发送各种畸形或随机数据，以发现应用程序的网络接口是否存在漏洞。

**涉及到的二进制底层，Linux, Android 内核及框架的知识及举例说明:**

* **二进制底层:**  该文件直接操作底层的套接字 API，例如 `getsockopt`, `getsockname`, `getpeername`, `bind` 等，这些 API 直接与操作系统的网络协议栈交互，涉及到二进制数据的打包和解包，网络字节序转换等底层细节。
    * **例子:** `gumjs_socket_get_type` 函数使用 `getsockopt(handle, SOL_SOCKET, SO_TYPE, ...)` 来获取套接字的类型，这里的 `SOL_SOCKET` 和 `SO_TYPE` 是定义在系统头文件中的常量，代表了底层的套接字选项。
* **Linux 内核:** 在 Linux 系统上，该文件依赖 Linux 内核提供的套接字实现。例如，`AF_INET`, `AF_INET6`, `AF_UNIX`, `SOCK_STREAM`, `SOCK_DGRAM` 等常量都定义在 Linux 内核相关的头文件中。
    * **例子:** `gum_v8_socket_family_get` 函数将 JavaScript 传递的字符串 (如 "ipv4", "ipv6", "unix") 转换为对应的 Linux 内核中定义的套接字族常量 (`G_SOCKET_FAMILY_IPV4`, `G_SOCKET_FAMILY_IPV6`, `G_SOCKET_FAMILY_UNIX`)。
* **Android 内核及框架:** 虽然代码本身是跨平台的，但在 Android 环境下运行时，会涉及到 Android 基于 Linux 内核的网络协议栈。同时，Android 框架层也提供了一些网络相关的 API，但 Frida Gum 通常直接与底层的 Linux 套接字 API 交互。
    * **例子:**  在 Android 上使用 Unix 域套接字进行进程间通信时，`gumjs_socket_listen` 和 `gumjs_socket_connect` 可以用来hook和分析这类通信。
* **套接字选项:** 代码中使用了 `g_socket_set_option` 来设置套接字选项，例如 `TCP_NODELAY`。这些选项直接影响着底层网络行为，需要对 TCP/IP 协议有一定的了解。

**逻辑推理及假设输入与输出:**

假设 JavaScript 代码调用 `Socket._listen('ipv4', '127.0.0.1', 12345, null, null, 5, function(error, listener) { ... });`

* **假设输入:**
    * `family_value`:  表示 'ipv4' 的 V8 字符串对象。
    * `host`:  C 字符串 "127.0.0.1"。
    * `port`:  整数 12345。
    * `type_value`:  null (表示默认类型)。
    * `path`:  null。
    * `backlog`: 整数 5。
    * `callback`:  一个 JavaScript 函数对象。
* **逻辑推理:**
    1. `gumjs_socket_listen` 函数被调用，解析参数。
    2. `gum_v8_socket_family_get` 将 'ipv4' 转换为 `G_SOCKET_FAMILY_IPV4`。
    3. 创建 `GInetSocketAddress` 对象，表示 `127.0.0.1:12345`。
    4. 创建 `GumV8ListenOperation` 对象，存储操作相关信息。
    5. `gum_v8_listen_operation_perform` 函数被调度执行。
    6. 创建 `GSocketListener` 对象，并设置 backlog。
    7. 调用 `g_socket_listener_add_address` 尝试绑定到指定的地址和端口。
    8. 如果绑定成功，创建一个 JavaScript `SocketListener` 对象。
    9. 调用 JavaScript 回调函数，传递 `null` 作为 error 参数，并将创建的 `SocketListener` 对象作为 listener 参数传递。
    10. 如果绑定失败，创建一个 V8 错误对象，并将其作为 error 参数传递给回调函数，listener 参数为 null。
* **预期输出 (成功情况):** JavaScript 回调函数被调用，`error` 参数为 `null`，`listener` 参数是一个表示监听套接字的 JavaScript 对象，该对象可以用于接受连接。
* **预期输出 (失败情况，例如端口被占用):** JavaScript 回调函数被调用，`error` 参数是一个 V8 错误对象，描述了绑定失败的原因，`listener` 参数为 `null`。

**用户或编程常见的使用错误及举例说明:**

* **忘记处理错误回调:** 用户在调用异步套接字操作时，如果没有正确处理回调函数中的 `error` 参数，可能会导致程序在套接字操作失败时无提示地继续执行，导致难以调试的问题。
    * **例子:**  用户调用 `Socket._connect` 但没有检查回调函数中的 `error`，如果连接失败（例如目标主机不可达），程序可能不会给出任何提示。
* **传递错误的参数类型:**  例如，将字符串传递给期望是数字的端口参数，或者传递无效的地址字符串。`_gum_v8_args_parse` 宏会在一定程度上进行参数校验，但仍然可能存在用户使用不当的情况。
    * **例子:**  `Socket._listen('ipv4', 12345, '127.0.0.1', ...)`  // 主机和端口参数类型错误。
* **资源泄漏:**  创建了套接字监听器或连接后，忘记显式关闭，可能导致资源泄漏。
    * **例子:**  在 Frida 脚本中创建了一个 `SocketListener`，但在脚本结束时没有调用 `listener.close()`。
* **在错误的时机调用函数:**  例如，在一个尚未建立连接的 `SocketConnection` 对象上尝试发送数据（尽管这个文件没有包含发送数据的功能，但这是套接字编程中常见的错误）。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

当用户在 Frida 脚本中使用 `Socket` 模块提供的功能时，会触发以下步骤最终到达 `gumv8socket.cpp` 中的代码：

1. **Frida 脚本执行:** 用户编写的 JavaScript 代码通过 Frida 执行环境运行。
2. **调用 `Socket` 模块的函数:**  用户在脚本中调用 `Socket.listen()`, `Socket.connect()` 等函数。
3. **V8 引擎处理:** V8 JavaScript 引擎接收到函数调用。
4. **查找 Native 函数绑定:** Frida 的 JavaScript 绑定机制会将这些 JavaScript 函数调用路由到对应的 C++ 函数，这些绑定关系在 `_gum_v8_socket_init` 函数中建立。例如，`Socket._listen` 对应 `gumjs_socket_listen`。
5. **执行 `gumv8socket.cpp` 中的 C++ 代码:**  相应的 C++ 函数（如 `gumjs_socket_listen`）被执行，开始进行底层的套接字操作。
6. **GLib 套接字操作:**  C++ 代码调用 GLib 库提供的套接字函数（例如 `g_socket_listener_add_address`）来完成实际的网络操作。
7. **操作系统内核交互:** GLib 库进一步调用操作系统提供的系统调用来完成底层的网络通信。
8. **回调执行:**  对于异步操作，当操作系统完成网络操作后，GLib 会调用预先注册的回调函数（例如 `gum_v8_listen_operation_perform`）。
9. **结果返回 JavaScript:**  回调函数将操作结果（成功或失败，以及相关数据）转换成 V8 的对象，并通过回调函数传递回 JavaScript 脚本。

**作为调试线索:**

* **断点:** 可以在 `gumv8socket.cpp` 中的关键函数（如 `gumjs_socket_listen`, `gumjs_socket_connect`, 以及异步操作的回调函数）设置断点，以观察参数的值和程序的执行流程。
* **日志输出:** 在 C++ 代码中添加日志输出，可以将关键信息打印到 Frida 的控制台，帮助理解程序的运行状态。
* **V8 Inspector:**  可以使用 V8 Inspector 来调试 JavaScript 代码，查看调用栈，了解 JavaScript 是如何调用到 Native 层的。
* **Tracing 工具:**  使用 `frida-trace` 工具可以跟踪对 `Socket` 模块函数的调用，查看参数和返回值。

总而言之，`gumv8socket.cpp` 是 Frida 中实现网络套接字操作的关键组成部分，它连接了 JavaScript 脚本和底层的操作系统网络功能，为逆向工程师提供了强大的网络交互和分析能力。理解其功能和实现细节对于有效地使用 Frida 进行网络相关的逆向分析至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8socket.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8socket.h"

#include "gumv8macros.h"
#include "gumv8scope.h"
#include "gumv8script-priv.h"

#include <gio/gnetworking.h>
#ifdef HAVE_WINDOWS
# define GUM_SOCKOPT_OPTVAL(v) ((char *) (v))
  typedef int gum_socklen_t;
#else
# include <errno.h>
# define GUM_SOCKOPT_OPTVAL(v) (v)
  typedef socklen_t gum_socklen_t;
#endif
#ifdef G_OS_UNIX
# include <gio/gunixsocketaddress.h>
#endif

#define GUMJS_MODULE_NAME Socket

using namespace v8;

struct GumV8ListenOperation : public GumV8ModuleOperation<GumV8Socket>
{
  guint16 port;

  gchar * path;

  GSocketAddress * address;
  gint backlog;
};

struct GumV8ConnectOperation : public GumV8ModuleOperation<GumV8Socket>
{
  GSocketClient * client;
  GSocketFamily family;

  gchar * host;
  guint16 port;

  GSocketConnectable * connectable;

  gboolean tls;
};

struct GumV8CloseListenerOperation
    : public GumV8ObjectOperation<GSocketListener, GumV8Socket>
{
};

struct GumV8AcceptOperation
    : public GumV8ObjectOperation<GSocketListener, GumV8Socket>
{
};

struct GumV8SetNoDelayOperation
    : public GumV8ObjectOperation<GSocketConnection, GumV8Stream>
{
  gboolean no_delay;
};

GUMJS_DECLARE_FUNCTION (gumjs_socket_listen)
static void gum_v8_listen_operation_dispose (GumV8ListenOperation * self);
static void gum_v8_listen_operation_perform (GumV8ListenOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_connect)
static void gum_v8_connect_operation_dispose (GumV8ConnectOperation * self);
static void gum_v8_connect_operation_start (GumV8ConnectOperation * self);
static void gum_v8_connect_operation_finish (GSocketClient * client,
    GAsyncResult * result, GumV8ConnectOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_type)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_local_address)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_peer_address)

static Local<Object> gum_v8_socket_listener_new (GSocketListener * listener,
    GumV8Socket * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_listener_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_listener_close)
static void gum_v8_close_listener_operation_perform (
    GumV8CloseListenerOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_listener_accept)
static void gum_v8_accept_operation_start (GumV8AcceptOperation * self);
static void gum_v8_accept_operation_finish (GSocketListener * listener,
    GAsyncResult * result, GumV8AcceptOperation * self);

static Local<Object> gum_v8_socket_connection_new (
    GSocketConnection * connection, GumV8Socket * module);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_connection_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_connection_set_no_delay)
static void gum_v8_set_no_delay_operation_perform (
    GumV8SetNoDelayOperation * self);

static gboolean gum_v8_socket_family_get (Local<Value> value,
    GSocketFamily * family, GumV8Core * core);
static gboolean gum_v8_unix_socket_address_type_get (Local<Value> value,
    GUnixSocketAddressType * type, GumV8Core * core);

static Local<Value> gum_v8_socket_address_to_value (
    struct sockaddr * addr, GumV8Core * core);

static const GumV8Function gumjs_socket_functions[] =
{
  { "_listen", gumjs_socket_listen },
  { "_connect", gumjs_socket_connect },
  { "type", gumjs_socket_get_type },
  { "localAddress", gumjs_socket_get_local_address },
  { "peerAddress", gumjs_socket_get_peer_address },

  { NULL, NULL }
};

static const GumV8Function gumjs_socket_listener_functions[] =
{
  { "_close", gumjs_socket_listener_close },
  { "_accept", gumjs_socket_listener_accept },

  { NULL, NULL }
};

static const GumV8Function gumjs_socket_connection_functions[] =
{
  { "_setNoDelay", gumjs_socket_connection_set_no_delay },

  { NULL, NULL }
};

void
_gum_v8_socket_init (GumV8Socket * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto socket = _gum_v8_create_module ("Socket", scope, isolate);
  _gum_v8_module_add (module, socket, gumjs_socket_functions, isolate);

  auto listener = _gum_v8_create_class ("SocketListener",
      gumjs_socket_listener_construct, scope, module, isolate);
  _gum_v8_class_add (listener, gumjs_socket_listener_functions, module,
      isolate);
  self->listener = new Global<FunctionTemplate> (isolate, listener);

  auto connection = _gum_v8_create_class ("SocketConnection",
      gumjs_socket_connection_construct, scope, module, isolate);
  auto io_stream (Local<FunctionTemplate>::New (isolate,
      *core->script->stream.io_stream));
  connection->Inherit (io_stream);
  _gum_v8_class_add (connection, gumjs_socket_connection_functions, module,
      isolate);
  self->connection = new Global<FunctionTemplate> (isolate, connection);
}

void
_gum_v8_socket_realize (GumV8Socket * self)
{
  gum_v8_object_manager_init (&self->objects);
}

void
_gum_v8_socket_flush (GumV8Socket * self)
{
  gum_v8_object_manager_flush (&self->objects);
}

void
_gum_v8_socket_dispose (GumV8Socket * self)
{
  gum_v8_object_manager_free (&self->objects);
}

void
_gum_v8_socket_finalize (GumV8Socket * self)
{
  delete self->listener;
  delete self->connection;
  self->listener = nullptr;
  self->connection = nullptr;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_listen)
{
  Local<Value> family_value;
  gchar * host;
  guint port;
  Local<Value> type_value;
  gchar * path;
  guint backlog;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "Vs?uVs?uF", &family_value, &host, &port,
      &type_value, &path, &backlog, &callback))
    return;

  GSocketFamily family;
  GUnixSocketAddressType type;
  if (!gum_v8_socket_family_get (family_value, &family, core) ||
      !gum_v8_unix_socket_address_type_get (type_value, &type, core))
  {
    g_free (host);
    g_free (path);
    return;
  }

  GSocketAddress * address = NULL;
  if (host != NULL)
  {
    address = g_inet_socket_address_new_from_string (host, port);
    g_clear_pointer (&host, g_free);
    if (address == NULL)
    {
      g_free (path);
      _gum_v8_throw_ascii_literal (isolate, "invalid host");
      return;
    }
  }
  else if (path != NULL)
  {
#ifdef G_OS_UNIX
    address = g_unix_socket_address_new_with_type (path, -1, type);
    g_assert (address != NULL);
#else
    g_free (path);
    _gum_v8_throw_ascii_literal (isolate, "UNIX sockets not available");
    return;
#endif
  }
  else if (family != G_SOCKET_FAMILY_INVALID)
  {
    address = g_inet_socket_address_new_from_string (
        (family == G_SOCKET_FAMILY_IPV4) ? "0.0.0.0" : "::",
        port);
    g_assert (address != NULL);
  }

  auto op = gum_v8_module_operation_new (module, callback,
      gum_v8_listen_operation_perform, gum_v8_listen_operation_dispose);
  op->port = port;
  op->path = path;
  op->address = address;
  op->backlog = backlog;
  gum_v8_module_operation_schedule (op);
}

static void
gum_v8_listen_operation_dispose (GumV8ListenOperation * self)
{
  g_clear_object (&self->address);
  g_free (self->path);
}

static void
gum_v8_listen_operation_perform (GumV8ListenOperation * self)
{
  auto listener = G_SOCKET_LISTENER (g_object_new (G_TYPE_SOCKET_LISTENER,
      "listen-backlog", self->backlog,
      NULL));

  GSocketAddress * effective_address = NULL;
  GError * error = NULL;
  if (self->address != NULL)
  {
    g_socket_listener_add_address (listener, self->address,
        G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, NULL,
        &effective_address, &error);
  }
  else
  {
    if (self->port != 0)
    {
      g_socket_listener_add_inet_port (listener, self->port, NULL, &error);
    }
    else
    {
      self->port =
          g_socket_listener_add_any_inet_port (listener, NULL, &error);
    }
  }

  if (error != NULL)
    g_clear_object (&listener);

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    Local<Value> error_value;
    Local<Value> listener_value;
    if (error == NULL)
    {
      error_value = Null (isolate);
      listener_value = gum_v8_socket_listener_new (listener, self->module);

      auto listener_object = listener_value.As<Object> ();
      if (self->path != NULL)
      {
        _gum_v8_object_set_utf8 (listener_object, "path", self->path, core);
      }
      else
      {
        if (effective_address != NULL)
        {
          self->port = g_inet_socket_address_get_port (
              G_INET_SOCKET_ADDRESS (effective_address));
          g_clear_object (&effective_address);
        }

        _gum_v8_object_set_uint (listener_object, "port", self->port, core);
      }
    }
    else
    {
      error_value = _gum_v8_error_new_take_error (isolate, &error);
      listener_value = Null (isolate);
    }

    Local<Value> argv[] = { error_value, listener_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto result = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (result);
  }

  gum_v8_module_operation_finish (self);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_connect)
{
  Local<Value> family_value;
  gchar * host;
  guint port;
  Local<Value> type_value;
  gchar * path;
  gboolean tls;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "Vs?uVs?tF", &family_value, &host, &port,
      &type_value, &path, &tls, &callback))
    return;

  GSocketFamily family;
  GUnixSocketAddressType type;
  if (!gum_v8_socket_family_get (family_value, &family, core) ||
      !gum_v8_unix_socket_address_type_get (type_value, &type, core))
  {
    g_free (host);
    g_free (path);
    return;
  }

  GSocketConnectable * connectable = NULL;
  if (path != NULL)
  {
#ifdef G_OS_UNIX
    family = G_SOCKET_FAMILY_UNIX;
    connectable = G_SOCKET_CONNECTABLE (g_unix_socket_address_new_with_type (
        path, -1, type));
    g_assert (connectable != NULL);
    g_clear_pointer (&path, g_free);
#else
    g_free (host);
    g_free (path);
    _gum_v8_throw_ascii_literal (isolate, "UNIX sockets not available");
    return;
#endif
  }

  auto op = gum_v8_module_operation_new (module, callback,
      gum_v8_connect_operation_start, gum_v8_connect_operation_dispose);
  op->client = NULL;
  op->family = family;
  op->host = host;
  op->port = port;
  op->connectable = connectable;
  op->tls = tls;
  gum_v8_module_operation_schedule (op);
}

static void
gum_v8_connect_operation_dispose (GumV8ConnectOperation * self)
{
  g_clear_object (&self->connectable);
  g_free (self->host);
  g_object_unref (self->client);
}

static void
gum_v8_connect_operation_start (GumV8ConnectOperation * self)
{
  self->client = G_SOCKET_CLIENT (g_object_new (G_TYPE_SOCKET_CLIENT,
      "family", self->family,
      "tls", self->tls,
      NULL));

  if (self->connectable != NULL)
  {
    g_socket_client_connect_async (self->client, self->connectable,
        self->cancellable,
        (GAsyncReadyCallback) gum_v8_connect_operation_finish, self);
  }
  else
  {
    g_socket_client_connect_to_host_async (self->client, self->host, self->port,
        self->cancellable,
        (GAsyncReadyCallback) gum_v8_connect_operation_finish, self);
  }
}

static void
gum_v8_connect_operation_finish (GSocketClient * client,
                                 GAsyncResult * result,
                                 GumV8ConnectOperation * self)
{
  GSocketConnection * connection;
  GError * error = NULL;
  if (self->connectable != NULL)
  {
    connection = g_socket_client_connect_finish (client, result, &error);
  }
  else
  {
    connection = g_socket_client_connect_to_host_finish (client, result,
        &error);
  }

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    Local<Value> error_value;
    Local<Value> connection_value;
    if (error == NULL)
    {
      error_value = Null (isolate);
      connection_value =
          gum_v8_socket_connection_new (connection, self->module);
    }
    else
    {
      error_value = _gum_v8_error_new_take_error (isolate, &error);
      connection_value = Null (isolate);
    }

    Local<Value> argv[] = { error_value, connection_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto res = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (res);
  }

  gum_v8_module_operation_finish (self);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_type)
{
  gint handle;
  if (!_gum_v8_args_parse (args, "i", &handle))
    return;

  const gchar * res = NULL;
  int type;
  gum_socklen_t len = sizeof (int);
  if (getsockopt (handle, SOL_SOCKET, SO_TYPE, GUM_SOCKOPT_OPTVAL (&type),
      &len) == 0)
  {
    int family;

    struct sockaddr_in6 addr;
    len = sizeof (addr);
    if (getsockname (handle, (struct sockaddr *) &addr, &len) == 0)
    {
      family = addr.sin6_family;
    }
    else
    {
      struct sockaddr_in invalid_sockaddr;
      invalid_sockaddr.sin_family = AF_INET;
      invalid_sockaddr.sin_port = GUINT16_TO_BE (0);
      invalid_sockaddr.sin_addr.s_addr = GUINT32_TO_BE (0xffffffff);
      bind (handle, (struct sockaddr *) &invalid_sockaddr,
          sizeof (invalid_sockaddr));
#ifdef HAVE_WINDOWS
      family = (WSAGetLastError () == WSAEADDRNOTAVAIL) ? AF_INET : AF_INET6;
#else
      family = (errno == EADDRNOTAVAIL) ? AF_INET : AF_INET6;
#endif
    }

    switch (family)
    {
      case AF_INET:
        switch (type)
        {
          case SOCK_STREAM: res = "tcp"; break;
          case  SOCK_DGRAM: res = "udp"; break;
        }
        break;
      case AF_INET6:
        switch (type)
        {
          case SOCK_STREAM: res = "tcp6"; break;
          case  SOCK_DGRAM: res = "udp6"; break;
        }
        break;
#ifndef HAVE_WINDOWS
      case AF_UNIX:
        switch (type)
        {
          case SOCK_STREAM: res = "unix:stream"; break;
          case  SOCK_DGRAM: res = "unix:dgram";  break;
        }
        break;
#endif
    }
  }

  if (res != NULL)
  {
    info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, res)
        .ToLocalChecked ());
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_local_address)
{
  gint handle;
  if (!_gum_v8_args_parse (args, "i", &handle))
    return;

  struct sockaddr_in6 large_addr;
  auto addr = (struct sockaddr *) &large_addr;
  gum_socklen_t len = sizeof (large_addr);
  if (getsockname (handle, addr, &len) == 0)
    info.GetReturnValue ().Set (gum_v8_socket_address_to_value (addr, core));
  else
    info.GetReturnValue ().SetNull ();
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_peer_address)
{
  gint handle;
  if (!_gum_v8_args_parse (args, "i", &handle))
    return;

  struct sockaddr_in6 large_addr;
  auto addr = (struct sockaddr *) (&large_addr);
  gum_socklen_t len = sizeof (large_addr);
  if (getpeername (handle, addr, &len) == 0)
    info.GetReturnValue ().Set (gum_v8_socket_address_to_value (addr, core));
  else
    info.GetReturnValue ().SetNull ();
}

static Local<Object>
gum_v8_socket_listener_new (GSocketListener * listener,
                            GumV8Socket * module)
{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto ctor (Local<FunctionTemplate>::New (isolate, *module->listener));
  Local<Value> argv[] = { External::New (isolate, listener) };
  return ctor->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, G_N_ELEMENTS (argv), argv).ToLocalChecked ();
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_listener_construct)
{
  GSocketListener * listener;
  if (!_gum_v8_args_parse (args, "X", &listener))
    return;

  gum_v8_object_manager_add (&module->objects, wrapper, listener, module);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_socket_listener_close, GumV8SocketListener)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F", &callback))
    return;

  g_cancellable_cancel (self->cancellable);

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_close_listener_operation_perform);
  gum_v8_object_operation_schedule_when_idle (op);
}

static void
gum_v8_close_listener_operation_perform (GumV8CloseListenerOperation * self)
{
  g_socket_listener_close (self->object->handle);

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto result = callback->Call (context, recv, 0, nullptr);
    _gum_v8_ignore_result (result);
  }

  gum_v8_object_operation_finish (self);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_socket_listener_accept, GumV8SocketListener)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F", &callback))
    return;

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_accept_operation_start);
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_accept_operation_start (GumV8AcceptOperation * self)
{
  auto listener = self->object;

  g_socket_listener_accept_async (listener->handle, listener->cancellable,
      (GAsyncReadyCallback) gum_v8_accept_operation_finish, self);
}

static void
gum_v8_accept_operation_finish (GSocketListener * listener,
                                GAsyncResult * result,
                                GumV8AcceptOperation * self)
{
  GError * error = NULL;
  GSocketConnection * connection;

  connection = g_socket_listener_accept_finish (listener, result, NULL, &error);

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    Local<Value> error_value;
    Local<Value> connection_value;
    if (error == NULL)
    {
      error_value = Null (isolate);
      connection_value =
          gum_v8_socket_connection_new (connection, self->object->module);
    }
    else
    {
      error_value = _gum_v8_error_new_take_error (isolate, &error);
      connection_value = Null (isolate);
    }

    Local<Value> argv[] = { error_value, connection_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto res = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (res);
  }

  gum_v8_object_operation_finish (self);
}

static Local<Object>
gum_v8_socket_connection_new (GSocketConnection * connection,
                              GumV8Socket * module)
{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();

  Local<FunctionTemplate> ctor (
      Local<FunctionTemplate>::New (isolate, *module->connection));
  Local<Value> argv[] = { External::New (isolate, connection) };
  return ctor->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, G_N_ELEMENTS (argv), argv).ToLocalChecked ();
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_connection_construct)
{
  auto context = isolate->GetCurrentContext ();

  GSocketConnection * connection;
  if (!_gum_v8_args_parse (args, "X", &connection))
    return;

  auto base_ctor (Local<FunctionTemplate>::New (isolate,
      *core->script->stream.io_stream));
  Local<Value> argv[] = { External::New (isolate, connection) };
  base_ctor->GetFunction (context).ToLocalChecked ()
      ->Call (context, wrapper, G_N_ELEMENTS (argv), argv).ToLocalChecked ();
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_socket_connection_set_no_delay, GumV8IOStream)
{
  gboolean no_delay;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "tF", &no_delay, &callback))
    return;

  auto op = gum_v8_object_operation_new (self, callback,
      gum_v8_set_no_delay_operation_perform);
  op->no_delay = no_delay;
  gum_v8_object_operation_schedule (op);
}

static void
gum_v8_set_no_delay_operation_perform (GumV8SetNoDelayOperation * self)
{
  GSocket * socket = g_socket_connection_get_socket (self->object->handle);

  GError * error = NULL;
  gboolean success = g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY,
      self->no_delay, &error);

  {
    auto core = self->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    Local<Value> error_value = _gum_v8_error_new_take_error (isolate, &error);
    auto success_value = success ? True (isolate) : False (isolate);

    Local<Value> argv[] = { error_value, success_value };
    auto callback (Local<Function>::New (isolate, *self->callback));
    auto recv = Undefined (isolate);
    auto result = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (result);
  }

  gum_v8_object_operation_finish (self);
}

static gboolean
gum_v8_socket_family_get (Local<Value> value,
                          GSocketFamily * family,
                          GumV8Core * core)
{
  auto isolate = core->isolate;

  if (value->IsNull ())
  {
    *family = G_SOCKET_FAMILY_INVALID;
    return TRUE;
  }

  if (!value->IsString ())
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid socket address family");
    return FALSE;
  }
  String::Utf8Value value_utf8 (isolate, value);
  auto value_str = *value_utf8;

  if (strcmp (value_str, "unix") == 0)
  {
    *family = G_SOCKET_FAMILY_UNIX;
    return TRUE;
  }

  if (strcmp (value_str, "ipv4") == 0)
  {
    *family = G_SOCKET_FAMILY_IPV4;
    return TRUE;
  }

  if (strcmp (value_str, "ipv6") == 0)
  {
    *family = G_SOCKET_FAMILY_IPV6;
    return TRUE;
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid socket address family");
  return FALSE;
}

static gboolean
gum_v8_unix_socket_address_type_get (Local<Value> value,
                                     GUnixSocketAddressType * type,
                                     GumV8Core * core)
{
  auto isolate = core->isolate;

  if (value->IsNull ())
  {
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
    return TRUE;
  }

  if (!value->IsString ())
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid UNIX socket address type");
    return FALSE;
  }
  String::Utf8Value value_utf8 (isolate, value);
  auto value_str = *value_utf8;

  if (strcmp (value_str, "anonymous") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_ANONYMOUS;
    return TRUE;
  }

  if (strcmp (value_str, "path") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
    return TRUE;
  }

  if (strcmp (value_str, "abstract") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT;
    return TRUE;
  }

  if (strcmp (value_str, "abstract-padded") == 0)
  {
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT_PADDED;
    return TRUE;
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid UNIX socket address type");
  return FALSE;
}

static Local<Value>
gum_v8_socket_address_to_value (struct sockaddr * addr,
                                GumV8Core * core)
{
  auto isolate = core->isolate;

  switch (addr->sa_family)
  {
    case AF_INET:
    {
      auto inet_addr = (struct sockaddr_in *) addr;
#ifdef HAVE_WINDOWS
      gunichar2 ip_utf16[15 + 1 + 5 + 1];
      gchar ip[15 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      WSAAddressToStringW (addr, sizeof (struct sockaddr_in), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      gchar * p = strchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET_ADDRSTRLEN];
      inet_ntop (AF_INET, &inet_addr->sin_addr, ip, sizeof (ip));
#endif
      Local<Object> result (Object::New (isolate));
      _gum_v8_object_set_ascii (result, "ip", ip, core);
      _gum_v8_object_set_uint (result, "port",
          GUINT16_FROM_BE (inet_addr->sin_port), core);
      return result;
    }
    case AF_INET6:
    {
      auto inet_addr = (struct sockaddr_in6 *) addr;
#ifdef HAVE_WINDOWS
      gunichar2 ip_utf16[45 + 1 + 5 + 1];
      gchar ip[45 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      WSAAddressToStringW (addr, sizeof (struct sockaddr_in6), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      gchar * p = strrchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, &inet_addr->sin6_addr, ip, sizeof (ip));
#endif
      auto result (Object::New (isolate));
      _gum_v8_object_set_ascii (result, "ip", ip, core);
      _gum_v8_object_set_uint (result, "port",
          GUINT16_FROM_BE (inet_addr->sin6_port), core);
      return result;
    }
    case AF_UNIX:
    {
      auto result (Object::New (isolate));
      _gum_v8_object_set_ascii (result, "path", "", core); /* FIXME */
      return result;
    }
  }

  return Null (isolate);
}
```