Response:
Let's break down the thought process for analyzing this `gumquicksocket.c` file.

**1. Initial Understanding and Purpose:**

The first step is to grasp the file's role within the larger Frida ecosystem. The path `frida/subprojects/frida-gum/bindings/gumjs/gumquicksocket.c` immediately suggests:

* **`frida`**: This is definitely part of the Frida dynamic instrumentation toolkit.
* **`subprojects/frida-gum`**: This points to the core instrumentation engine of Frida (Gum).
* **`bindings/gumjs`**:  Indicates that this file bridges the gap between Gum's C/C++ code and the JavaScript environment Frida exposes to users.
* **`gumquicksocket.c`**:  The name strongly implies it handles socket operations within this bridging layer, likely providing a way for JavaScript code to interact with network sockets.

**2. Core Functionality Identification (Scanning for Key Terms and Structures):**

Next, I'd scan the code for keywords, function names, and data structures that reveal its capabilities. Look for patterns and connections.

* **`#include` directives:** These tell us about dependencies. Seeing `<gio/gnetworking.h>`, `<gio/gunixsocketaddress.h>`, and socket-related includes (even with platform variations like `HAVE_WINDOWS`) confirms socket handling.
* **`typedef struct _GumQuick...Operation`**:  The repeated "Operation" suffix suggests an asynchronous or event-driven architecture. These structures likely hold data needed for specific socket actions. The different `...ListenOperation`, `...ConnectOperation`, `...CloseListenerOperation`, etc., directly map to different socket functionalities.
* **`GUMJS_DECLARE_FUNCTION(...)` and `GUMJS_DEFINE_FUNCTION(...)`**:  These macros clearly mark functions intended to be exposed to the JavaScript environment. The names like `gumjs_socket_listen`, `gumjs_socket_connect`, `gumjs_socket_get_type`, etc., are strong indicators of their purpose.
* **`JS_CFUNC_DEF(...)`**:  These entries in `gumjs_socket_entries`, `gumjs_socket_listener_entries`, and `gumjs_socket_connection_entries` link the C functions to the JavaScript API names.
* **`JS_NewObject`, `JS_DefinePropertyValueStr`, `JS_SetPropertyFunctionList`**:  These are JavaScript API calls, further solidifying the binding nature of this code. They are used to create and configure JavaScript objects that represent sockets and related entities.
* **`GSocketListener`, `GSocketClient`, `GSocketConnection`**: These are GIO (GLib's I/O library) types, indicating the underlying socket implementation.
* **Asynchronous Function Calls:**  Functions like `g_socket_listener_add_address_async`, `g_socket_client_connect_async`, and the associated `..._finish` callbacks signal asynchronous operations, which is typical for non-blocking I/O.

**3. Connecting Functionality to Reverse Engineering:**

Once the core functionalities are identified (listening, connecting, accepting, getting socket info), the connection to reverse engineering becomes apparent:

* **Monitoring Network Traffic:**  The ability to listen on ports or connect to hosts directly allows a reverse engineer to observe the network communication of an application. This is crucial for understanding protocols, identifying APIs, and potentially finding vulnerabilities.
* **Intercepting Communication:** By attaching Frida and using these socket functions, one could potentially intercept and modify data being sent or received by the target application.
* **Understanding Application Behavior:** Observing which network connections an application makes and what data it exchanges can provide insights into its inner workings and dependencies.

**4. Identifying Binary/Kernel/Framework Aspects:**

The code reveals these low-level aspects:

* **System Calls (Implicit):**  While not directly calling `socket()`, `bind()`, `listen()`, `connect()`, etc., the GIO library functions internally use these system calls. Frida, by instrumenting the application at runtime, ultimately interacts with these underlying system calls.
* **Linux/Android Kernel (Conditional Compilation):** The `#ifdef G_OS_UNIX` blocks clearly handle Unix domain sockets, which are a feature of Linux and Android kernels.
* **Android Framework (Indirectly):** Although not directly interacting with Android framework APIs in *this* file,  Frida as a whole is heavily used in Android reverse engineering. This `gumquicksocket.c` provides a foundational network interaction capability that would be used in that context.
* **Socket Options (TCP_NODELAY):** The `gumjs_socket_connection_set_no_delay` function and the use of `g_socket_set_option` demonstrate interaction with low-level socket options, which are OS-specific.

**5. Logical Inference (Input/Output):**

For functions like `gumjs_socket_listen` and `gumjs_socket_connect`, I consider the arguments they take (host, port, family, path, callbacks) and what they aim to achieve (create a listener, establish a connection). The success and failure paths, handled by the callbacks, are key to defining potential outputs.

**6. Common User Errors:**

Thinking about how a user might misuse the API is important. Focus on the parameters and the expected behavior:

* **Invalid Host/Port:**  Typographical errors or incorrect values.
* **Permission Issues:** Trying to bind to a privileged port without sufficient rights.
* **Address Already in Use:** Attempting to listen on a port already occupied.
* **Incorrect Socket Family:**  Trying to connect to a Unix socket using IPv4, for example.
* **Type Mismatches:**  Providing a path when expecting a host and port.

**7. Tracing User Operations (Debugging):**

To understand how a user reaches this code, I consider the typical Frida workflow:

1. **Write a Frida script (JavaScript):** The user would write JavaScript code that uses the `Socket` API exposed by Frida.
2. **Call `Socket._listen()` or `Socket._connect()`:** The user's JavaScript code would call these functions, passing arguments like host, port, and callbacks.
3. **Frida's JavaScript bridge:** This call would be intercepted by Frida's JavaScript engine.
4. **Invocation of native functions:** Frida would then call the corresponding native C functions in `gumquicksocket.c`, like `gumjs_socket_listen`.

By following this path, I can trace the execution flow from the user's JavaScript code down to the native implementation.

**Self-Correction/Refinement during the process:**

* **Initial Assumption Check:**  Double-checking the purpose of each function based on its name and arguments. If something seems ambiguous, look for related functions or data structures that provide context.
* **GIO Library Familiarity:**  Leveraging existing knowledge about GLib/GIO helps in understanding the underlying mechanisms. If unfamiliar, a quick search for the relevant GIO types (like `GSocketListener`) is necessary.
* **Platform-Specific Considerations:**  Paying attention to `#ifdef` blocks highlights platform-specific behavior and is crucial for a complete understanding.
* **Asynchronous Nature:**  Recognizing the asynchronous nature of many operations (using `_async` and `_finish` functions) is essential for accurately describing the execution flow and potential outcomes.

This iterative process of scanning, identifying, connecting, inferring, and considering error scenarios allows for a comprehensive analysis of the code's functionality and its role in the broader Frida context.
好的，让我们来详细分析一下 `gumquicksocket.c` 这个文件。

**文件功能概述**

`gumquicksocket.c` 是 Frida 工具中 `frida-gum` 组件的一个模块，主要负责在 Frida 的 JavaScript 绑定 (gumjs) 中提供操作网络 Socket 的能力。它允许 JavaScript 代码在被 Frida 注入的目标进程中创建、监听、连接和管理网络 Socket。

简单来说，它在 JavaScript 中暴露了类似于操作系统 Socket API 的功能，使得 Frida 脚本能够与目标进程的网络通信进行交互，这对于动态分析和逆向工程至关重要。

**与逆向方法的关系及举例说明**

这个文件提供的 Socket 功能与逆向方法有着非常紧密的联系。逆向工程师经常需要理解目标应用程序的网络行为，例如：

* **分析通信协议:**  了解应用程序使用了哪些协议进行通信，数据的格式是什么样的。
* **模拟服务器/客户端:**  为了测试应用程序的特定功能或漏洞，可能需要模拟应用程序连接的服务器，或者模拟客户端向应用程序发送特定的请求。
* **拦截和修改网络数据:**  在运行时拦截应用程序发送和接收的网络数据，并可能对其进行修改，以观察应用程序的行为变化。

**举例说明：**

假设你想逆向一个移动应用程序，该程序会定期向某个服务器发送数据。你可以使用 Frida 和 `gumquicksocket.c` 提供的功能来：

1. **监听端口（`gumjs_socket_listen`）：**  如果应用程序充当服务器，你可以使用 Frida 脚本在设备上监听应用程序正在使用的端口，以便观察是否有其他进程尝试连接。
2. **连接到服务器（`gumjs_socket_connect`）：** 如果你想模拟应用程序的行为，你可以使用 Frida 脚本连接到应用程序通常连接的服务器，并发送自定义的数据包。
3. **拦截连接（`gumjs_socket_listener_accept`）：**  当目标应用程序创建一个监听器时，你可以Hook它的 `accept` 函数（虽然这个文件本身不直接 Hook，但它提供了创建监听器的基础），并在连接建立后，使用 `gumjs_socket_connection_new` 创建的连接对象来读取或修改数据。
4. **获取连接信息（`gumjs_socket_get_local_address`, `gumjs_socket_get_peer_address`）：**  你可以获取已建立连接的本地和远程地址信息，帮助你理解连接的目标和来源。
5. **修改 TCP 选项（`gumjs_socket_connection_set_no_delay`）：**  有时，修改 TCP 选项（例如禁用 Nagle 算法）可以影响网络通信的时序，这在某些逆向场景下可能有用。

**涉及到二进制底层、Linux/Android 内核及框架的知识及举例说明**

`gumquicksocket.c` 的实现依赖于底层的操作系统 API 和概念：

* **二进制底层:**
    * **Socket 文件描述符:**  代码中可以看到 `getsockopt` 和 `getsockname` 等函数，这些函数操作的是 Socket 的文件描述符，这是操作系统内核用于表示打开的 Socket 连接的整数。
    * **Socket 地址结构:**  `struct sockaddr_in`, `struct sockaddr_in6`, `struct sockaddr` 等结构体定义了不同网络协议族的地址格式，例如 IPv4、IPv6 和 Unix 域套接字。
    * **字节序转换:** 代码中使用了 `GUINT16_TO_BE` 和 `GUINT16_FROM_BE` 等宏，表明需要处理网络字节序和主机字节序之间的转换，这是底层网络编程中常见的概念。
* **Linux/Android 内核:**
    * **系统调用:**  虽然代码没有直接调用 `socket()`, `bind()`, `listen()`, `connect()` 等系统调用，但 `gio` 库 (GLib 的 I/O 库) 提供的函数如 `g_socket_listener_add_address` 和 `g_socket_client_connect_async` 等底层最终会调用这些系统调用来完成 Socket 操作。
    * **Unix 域套接字:** 代码中包含了对 Unix 域套接字的支持 (`#ifdef G_OS_UNIX`)，这是一种进程间通信机制，常用于本地服务之间的交互，在 Android 系统中也很常见。
* **框架知识:**
    * **GLib/GIO 库:**  `gumquicksocket.c` 大量使用了 GLib 的 GIO 库，这是一个跨平台的 I/O 库，提供了高级的 Socket 操作接口，简化了底层系统调用的使用。Frida 使用 GIO 库来提高代码的可移植性。
    * **Frida 的模块化架构:**  `gumquicksocket.c` 作为 Frida 的一个模块，与 Frida 的核心 (Gum) 以及 JavaScript 绑定 (gumjs) 协同工作。它接收来自 JavaScript 层的请求，并调用底层的 GIO 函数来执行 Socket 操作。

**举例说明:**

* 当 JavaScript 代码调用 `Socket._listen()` 时，`gumjs_socket_listen` 函数会被调用。这个函数会解析 JavaScript 传递的参数（例如端口号、地址族），然后调用 `g_socket_listener_new` 和 `g_socket_listener_add_inet_port` (或 `g_socket_listener_add_unix_address` 等) 等 GIO 函数。这些 GIO 函数最终会调用 Linux 或 Android 内核的 `socket()`, `bind()`, `listen()` 等系统调用，创建一个监听 Socket。
* 在处理 Unix 域套接字时，`g_unix_socket_address_new_with_type` 函数会被用来创建 `GSocketAddress` 对象，这个对象会封装 Unix 域套接字的路径和类型信息。这直接关联到 Linux 内核中关于 Unix 域套接字的实现。

**逻辑推理、假设输入与输出**

让我们以 `gumjs_socket_listen` 函数为例进行逻辑推理：

**假设输入:**

* `family_value`:  JavaScript 中传入的 Socket 地址族，例如 "ipv4", "ipv6", "unix"。
* `host`:  如果地址族是 IPv4 或 IPv6，则为要监听的 IP 地址字符串，可以为 `null` 表示监听所有地址。
* `port`:  要监听的端口号。
* `type_val`:  如果地址族是 "unix"，则为 Unix 域套接字的类型，例如 "path", "abstract"。
* `path`:  如果地址族是 "unix"，则为 Unix 域套接字的路径。
* `backlog`:  监听队列的最大长度。
* `callback`:  一个 JavaScript 回调函数，用于接收操作结果。

**逻辑推理:**

1. 函数首先解析传入的 JavaScript 参数，包括地址族、主机、端口、路径等。
2. 根据地址族的不同，创建不同的 `GSocketAddress` 对象。
    * 如果是 IPv4 或 IPv6，使用 `g_inet_socket_address_new_from_string` 创建。
    * 如果是 Unix 域套接字，使用 `g_unix_socket_address_new_with_type` 创建。
3. 创建一个 `GumQuickListenOperation` 结构体，用于保存操作所需的信息。
4. 调用 `_gum_quick_module_operation_schedule` 调度一个异步操作。
5. 在 `gum_quick_listen_operation_perform` 函数中：
    * 创建一个 `GSocketListener` 对象。
    * 调用 `g_socket_listener_add_address` 或 `g_socket_listener_add_inet_port` 将地址添加到监听器。
    * 如果操作成功，创建一个 JavaScript 的 `SocketListener` 对象，并通过回调函数返回。
    * 如果操作失败，创建一个 JavaScript 的错误对象，并通过回调函数返回。

**可能的输出:**

* **成功:** 回调函数被调用，传入 `null` 作为错误参数，以及一个 `SocketListener` 对象的 JavaScript 表示。该对象可能包含 `path` 或 `port` 属性，取决于监听的类型。
* **失败:** 回调函数被调用，传入一个 JavaScript 的 `Error` 对象，描述了失败的原因（例如，端口被占用，无效的地址）。

**用户或编程常见的使用错误及举例说明**

* **未处理错误:** 用户可能在 JavaScript 回调函数中没有正确处理错误，导致程序在 Socket 操作失败时出现未预期的行为。
    ```javascript
    // 错误的使用方式
    Socket._listen("tcp", null, 8080, function(error, listener) {
        // 没有检查 error
        console.log("Listener created:", listener);
    });

    // 正确的使用方式
    Socket._listen("tcp", null, 8080, function(error, listener) {
        if (error) {
            console.error("Failed to create listener:", error);
            return;
        }
        console.log("Listener created:", listener);
    });
    ```
* **尝试绑定到受保护的端口:**  非特权用户尝试绑定到小于 1024 的端口，这在许多操作系统上需要 root 权限。Frida 脚本运行时通常以目标进程的权限运行，如果目标进程没有足够的权限，绑定会失败。
    ```javascript
    Socket._listen("tcp", null, 80, function(error, listener) { // 可能会失败
        // ...
    });
    ```
* **地址已被占用:** 尝试监听已被其他进程占用的地址和端口。
    ```javascript
    Socket._listen("tcp", null, 8080, function(error, listener) {
        // 如果 8080 端口已被占用，会收到错误
    });
    ```
* **错误的参数类型:**  向 `_listen` 或 `_connect` 函数传递了错误的参数类型，例如将字符串作为端口号传递。这会被 Frida 的参数解析逻辑捕获，并抛出 JavaScript 异常。
* **在未初始化的状态下使用 Socket 对象:**  虽然这个文件没有直接暴露用户可以创建的 Socket 对象构造函数，但在其他相关文件中，如果用户错误地直接实例化内部类，可能会导致未定义的行为。

**用户操作是如何一步步到达这里的作为调试线索**

1. **编写 Frida JavaScript 脚本:** 用户首先会编写一个 Frida 脚本，该脚本使用了 Frida 提供的 `Socket` API。例如：
   ```javascript
   // Frida 脚本
   console.log("Attaching to process...");
   Process.enumerateModules()[0].base; // 确保 Frida 已连接

   const Socket = Module.findExportByName(null, 'gumjs_api_get_socket'); // 假设的获取 Socket API 的方式

   if (Socket) {
       const socketApi = Socket(); // 获取 Socket API 对象

       socketApi._listen("tcp", "127.0.0.1", 12345, function(error, listener) {
           if (error) {
               console.error("Error listening:", error);
               return;
           }
           console.log("Listening on port 12345");
           listener._accept(function(acceptError, connection) {
               if (acceptError) {
                   console.error("Error accepting connection:", acceptError);
                   return;
               }
               console.log("Accepted connection:", connection);
           });
       });
   } else {
       console.error("Socket API not found.");
   }
   ```

2. **使用 Frida CLI 或 API 注入脚本:** 用户会使用 Frida 的命令行工具或编程接口 (如 Python 的 `frida` 库) 将该脚本注入到目标进程中。
   ```bash
   frida -p <进程ID> -l your_script.js
   ```

3. **JavaScript 引擎执行脚本:** Frida 的 JavaScript 引擎 (QuickJS，如代码中所示) 会执行该脚本。当脚本调用 `socketApi._listen()` 时，会触发以下流程：

4. **调用 JavaScript 绑定函数:**  Frida 的绑定机制会将 JavaScript 的函数调用映射到 native 的 C 函数，即 `gumjs_socket_listen`。

5. **执行 `gumjs_socket_listen`:**  `gumjs_socket_listen` 函数会解析 JavaScript 传递的参数，创建 `GumQuickListenOperation` 结构体，并调度异步操作。

6. **执行 `gum_quick_listen_operation_perform`:**  在 Frida 的事件循环中，`gum_quick_listen_operation_perform` 函数会被执行，它会调用 GIO 库的函数来创建和绑定 Socket。

7. **回调 JavaScript 函数:**  当 Socket 成功创建并开始监听后，或者发生错误时，之前在 JavaScript 中提供的回调函数会被调用，并将结果传递回 JavaScript 层。

**调试线索:**

* **查看 Frida 脚本:** 检查用户编写的 Frida 脚本，确认 `Socket._listen` 或 `Socket._connect` 等函数的调用方式和参数是否正确。
* **使用 Frida 的 `console.log`:** 在 Frida 脚本中添加 `console.log` 输出，可以跟踪脚本的执行流程和变量的值。
* **查看 Frida 的错误信息:** Frida 在控制台或通过 API 会输出错误信息，这些信息可以帮助定位问题，例如参数解析错误、Socket 操作失败的原因等。
* **使用 GDB 等调试器:**  对于更深入的调试，可以使用 GDB 等调试器附加到 Frida Server 或目标进程，并设置断点在 `gumjs_socket_listen` 或相关的 GIO 函数中，以检查执行流程和变量状态。
* **检查目标进程的网络状态:**  使用 `netstat` 或类似的工具检查目标进程的网络连接和监听状态，可以确认 Socket 是否被成功创建和绑定。

总而言之，`gumquicksocket.c` 是 Frida 中一个关键的模块，它桥接了 JavaScript 和底层的 Socket API，为逆向工程师提供了强大的网络交互能力，并涉及到操作系统底层、内核、框架等多个层面的知识。理解其功能和实现原理，对于有效地使用 Frida 进行动态分析至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquicksocket.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquicksocket.h"

#include "gumquickmacros.h"

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4214)
#endif
#include <gio/gnetworking.h>
#ifdef _MSC_VER
# pragma warning (pop)
#endif
#ifdef HAVE_WINDOWS
# define GUM_SOCKOPT_OPTVAL(v) (gchar *) (v)
  typedef int gum_socklen_t;
#else
# include <errno.h>
# define GUM_SOCKOPT_OPTVAL(v) (v)
  typedef socklen_t gum_socklen_t;
#endif
#ifdef G_OS_UNIX
# include <gio/gunixsocketaddress.h>
#endif
#include <string.h>

typedef struct _GumQuickListenOperation GumQuickListenOperation;
typedef struct _GumQuickConnectOperation GumQuickConnectOperation;

typedef struct _GumQuickCloseListenerOperation GumQuickCloseListenerOperation;
typedef struct _GumQuickAcceptOperation GumQuickAcceptOperation;

typedef struct _GumQuickSetNoDelayOperation GumQuickSetNoDelayOperation;

struct _GumQuickListenOperation
{
  GumQuickModuleOperation operation;

  guint16 port;

  gchar * path;

  GSocketAddress * address;
  gint backlog;
};

struct _GumQuickConnectOperation
{
  GumQuickModuleOperation operation;

  GSocketClient * client;
  GSocketFamily family;

  gchar * host;
  guint16 port;

  GSocketConnectable * connectable;

  gboolean tls;
};

struct _GumQuickCloseListenerOperation
{
  GumQuickObjectOperation operation;
};

struct _GumQuickAcceptOperation
{
  GumQuickObjectOperation operation;
};

struct _GumQuickSetNoDelayOperation
{
  GumQuickObjectOperation parent;
  gboolean no_delay;
};

GUMJS_DECLARE_FUNCTION (gumjs_socket_listen)
static void gum_quick_listen_operation_dispose (GumQuickListenOperation * self);
static void gum_quick_listen_operation_perform (GumQuickListenOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_connect)
static void gum_quick_connect_operation_dispose (
    GumQuickConnectOperation * self);
static void gum_quick_connect_operation_start (GumQuickConnectOperation * self);
static void gum_quick_connect_operation_finish (GSocketClient * client,
    GAsyncResult * result, GumQuickConnectOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_type)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_local_address)
GUMJS_DECLARE_FUNCTION (gumjs_socket_get_peer_address)

static JSValue gum_quick_socket_listener_new (JSContext * ctx,
    GSocketListener * listener, GumQuickSocket * parent);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_listener_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_listener_close)
static void gum_quick_close_listener_operation_perform (
    GumQuickCloseListenerOperation * self);
GUMJS_DECLARE_FUNCTION (gumjs_socket_listener_accept)
static void gum_quick_accept_operation_start (GumQuickAcceptOperation * self);
static void gum_quick_accept_operation_finish (GSocketListener * listener,
    GAsyncResult * result, GumQuickAcceptOperation * self);

static JSValue gum_quick_socket_connection_new (JSContext * ctx,
    GSocketConnection * connection, GumQuickSocket * parent);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_socket_connection_construct)
GUMJS_DECLARE_FUNCTION (gumjs_socket_connection_set_no_delay)
static void gum_quick_set_no_delay_operation_perform (
    GumQuickSetNoDelayOperation * self);

static gboolean gum_quick_socket_family_get (JSContext * ctx, JSValue val,
    GSocketFamily * family);
static gboolean gum_quick_unix_socket_address_type_get (JSContext * ctx,
    JSValue val, GUnixSocketAddressType * type);
static JSValue gum_quick_socket_address_new (JSContext * ctx,
    struct sockaddr * addr, GumQuickCore * core);

static const JSCFunctionListEntry gumjs_socket_entries[] =
{
  JS_CFUNC_DEF ("_listen", 0, gumjs_socket_listen),
  JS_CFUNC_DEF ("_connect", 0, gumjs_socket_connect),
  JS_CFUNC_DEF ("type", 0, gumjs_socket_get_type),
  JS_CFUNC_DEF ("localAddress", 0, gumjs_socket_get_local_address),
  JS_CFUNC_DEF ("peerAddress", 0, gumjs_socket_get_peer_address),
};

static const JSClassDef gumjs_socket_listener_def =
{
  .class_name = "SocketListener",
};

static const JSCFunctionListEntry gumjs_socket_listener_entries[] =
{
  JS_CFUNC_DEF ("_close", 0, gumjs_socket_listener_close),
  JS_CFUNC_DEF ("_accept", 0, gumjs_socket_listener_accept),
};

static const JSClassDef gumjs_socket_connection_def =
{
  .class_name = "SocketConnection",
};

static const JSCFunctionListEntry gumjs_socket_connection_entries[] =
{
  JS_CFUNC_DEF ("_setNoDelay", 0, gumjs_socket_connection_set_no_delay),
};

void
_gum_quick_socket_init (GumQuickSocket * self,
                        JSValue ns,
                        GumQuickStream * stream,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj, proto, ctor;

  self->stream = stream;
  self->core = core;

  _gum_quick_core_store_module_data (core, "socket", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_socket_entries,
      G_N_ELEMENTS (gumjs_socket_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Socket", obj, JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_socket_listener_def, core,
      &self->socket_listener_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_socket_listener_construct,
      gumjs_socket_listener_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_socket_listener_entries,
      G_N_ELEMENTS (gumjs_socket_listener_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_socket_listener_def.class_name,
      ctor, JS_PROP_C_W_E);

  _gum_quick_create_subclass (ctx, &gumjs_socket_connection_def,
      stream->io_stream_class, stream->io_stream_proto, core,
      &self->socket_connection_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_socket_connection_construct,
      gumjs_socket_connection_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_socket_connection_entries,
      G_N_ELEMENTS (gumjs_socket_connection_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_socket_connection_def.class_name,
      ctor, JS_PROP_C_W_E);

  _gum_quick_object_manager_init (&self->objects, self, core);
}

void
_gum_quick_socket_flush (GumQuickSocket * self)
{
  _gum_quick_object_manager_flush (&self->objects);
}

void
_gum_quick_socket_dispose (GumQuickSocket * self)
{
  _gum_quick_object_manager_free (&self->objects);
}

void
_gum_quick_socket_finalize (GumQuickSocket * self)
{
}

static GumQuickSocket *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "socket");
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_listen)
{
  GumQuickSocket * parent;
  GSocketFamily family;
  JSValue family_value;
  const gchar * host;
  guint port;
  GUnixSocketAddressType type;
  JSValue type_val;
  const gchar * path;
  guint backlog;
  JSValue callback;
  GSocketAddress * address = NULL;
  GumQuickListenOperation * op;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "V?s?uV?s?uF", &family_value, &host, &port,
      &type_val, &path, &backlog, &callback))
    return JS_EXCEPTION;
  if (!gum_quick_socket_family_get (ctx, family_value, &family))
    return JS_EXCEPTION;
  if (!gum_quick_unix_socket_address_type_get (ctx, type_val, &type))
    return JS_EXCEPTION;

  if (host != NULL)
  {
    address = g_inet_socket_address_new_from_string (host, port);
    if (address == NULL)
      return _gum_quick_throw_literal (ctx, "invalid host");
  }
  else if (path != NULL)
  {
#ifdef G_OS_UNIX
    address = g_unix_socket_address_new_with_type (path, -1, type);
    g_assert (address != NULL);
#else
    return _gum_quick_throw_literal (ctx, "UNIX sockets not available");
#endif
  }
  else if (family != G_SOCKET_FAMILY_INVALID)
  {
    address = g_inet_socket_address_new_from_string (
        (family == G_SOCKET_FAMILY_IPV4) ? "0.0.0.0" : "::",
        port);
    g_assert (address != NULL);
  }

  op = _gum_quick_module_operation_new (GumQuickListenOperation, parent,
      callback, gum_quick_listen_operation_perform,
      gum_quick_listen_operation_dispose);
  op->port = port;
  op->path = g_strdup (path);
  op->address = address;
  op->backlog = backlog;
  _gum_quick_module_operation_schedule (op);

  return JS_UNDEFINED;
}

static void
gum_quick_listen_operation_dispose (GumQuickListenOperation * self)
{
  g_clear_object (&self->address);
  g_free (self->path);
}

static void
gum_quick_listen_operation_perform (GumQuickListenOperation * self)
{
  GumQuickModuleOperation * op = GUM_QUICK_MODULE_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  GSocketListener * listener;
  GSocketAddress * effective_address = NULL;
  GError * error = NULL;
  GumQuickScope scope;
  JSValue argv[2];

  listener = g_object_new (G_TYPE_SOCKET_LISTENER,
      "listen-backlog", self->backlog,
      NULL);

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

  _gum_quick_scope_enter (&scope, core);

  if (error == NULL)
  {
    JSValue listener_obj =
        gum_quick_socket_listener_new (ctx, listener, op->module);

    if (self->path != NULL)
    {
      JS_DefinePropertyValue (ctx, listener_obj,
          GUM_QUICK_CORE_ATOM (core, path),
          JS_NewString (ctx, self->path),
          JS_PROP_C_W_E);
    }
    else
    {
      guint16 port;

      if (effective_address != NULL)
      {
        port = g_inet_socket_address_get_port (
            G_INET_SOCKET_ADDRESS (effective_address));
        g_clear_object (&effective_address);
      }
      else
      {
        port = self->port;
      }

      JS_DefinePropertyValue (ctx, listener_obj,
          GUM_QUICK_CORE_ATOM (core, port),
          JS_NewInt32 (ctx, port),
          JS_PROP_C_W_E);
    }

    argv[0] = JS_NULL;
    argv[1] = listener_obj;
  }
  else
  {
    argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
    argv[1] = JS_NULL;
  }

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);
  JS_FreeValue (ctx, argv[1]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_module_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_connect)
{
  GumQuickSocket * parent;
  GSocketFamily family;
  JSValue family_value;
  const gchar * host;
  guint port;
  GUnixSocketAddressType type;
  JSValue type_val;
  const gchar * path;
  gboolean tls;
  JSValue callback;
  GSocketConnectable * connectable = NULL;
  GumQuickConnectOperation * op;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "V?s?uV?s?tF", &family_value, &host, &port,
      &type_val, &path, &tls, &callback))
    return JS_EXCEPTION;
  if (!gum_quick_socket_family_get (ctx, family_value, &family))
    return JS_EXCEPTION;
  if (!gum_quick_unix_socket_address_type_get (ctx, type_val, &type))
    return JS_EXCEPTION;

  if (path != NULL)
  {
#ifdef G_OS_UNIX
    family = G_SOCKET_FAMILY_UNIX;
    connectable = G_SOCKET_CONNECTABLE (g_unix_socket_address_new_with_type (
        path, -1, type));
    g_assert (connectable != NULL);
#else
    return _gum_quick_throw_literal (ctx, "UNIX sockets not available");
#endif
  }

  op = _gum_quick_module_operation_new (GumQuickConnectOperation, parent,
      callback, gum_quick_connect_operation_start,
      gum_quick_connect_operation_dispose);
  op->client = NULL;
  op->family = family;
  op->host = g_strdup (host);
  op->port = port;
  op->connectable = connectable;
  op->tls = tls;
  _gum_quick_module_operation_schedule (op);

  return JS_UNDEFINED;
}

static void
gum_quick_connect_operation_dispose (GumQuickConnectOperation * self)
{
  g_clear_object (&self->connectable);
  g_free (self->host);
  g_object_unref (self->client);
}

static void
gum_quick_connect_operation_start (GumQuickConnectOperation * self)
{
  GumQuickModuleOperation * op = GUM_QUICK_MODULE_OPERATION (self);

  self->client = g_object_new (G_TYPE_SOCKET_CLIENT,
      "family", self->family,
      "tls", self->tls,
      NULL);

  if (self->connectable != NULL)
  {
    g_socket_client_connect_async (self->client, self->connectable,
        op->cancellable,
        (GAsyncReadyCallback) gum_quick_connect_operation_finish,
        self);
  }
  else
  {
    g_socket_client_connect_to_host_async (self->client, self->host, self->port,
        op->cancellable,
        (GAsyncReadyCallback) gum_quick_connect_operation_finish,
        self);
  }
}

static void
gum_quick_connect_operation_finish (GSocketClient * client,
                                    GAsyncResult * result,
                                    GumQuickConnectOperation * self)
{
  GumQuickModuleOperation * op = GUM_QUICK_MODULE_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  GError * error = NULL;
  GSocketConnection * connection;
  GumQuickScope scope;
  JSValue argv[2];

  if (self->connectable != NULL)
  {
    connection = g_socket_client_connect_finish (client, result, &error);
  }
  else
  {
    connection = g_socket_client_connect_to_host_finish (client, result,
        &error);
  }

  _gum_quick_scope_enter (&scope, core);

  if (error == NULL)
  {
    argv[0] = JS_NULL;
    argv[1] = gum_quick_socket_connection_new (ctx, connection, op->module);
  }
  else
  {
    argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
    argv[1] = JS_NULL;
  }

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);
  JS_FreeValue (ctx, argv[1]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_module_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_type)
{
  const gchar * result = NULL;
  gint sock, type;
  gum_socklen_t len;

  if (!_gum_quick_args_parse (args, "i", &sock))
    return JS_EXCEPTION;

  len = sizeof (gint);
  if (getsockopt (sock, SOL_SOCKET, SO_TYPE, GUM_SOCKOPT_OPTVAL (&type),
      &len) == 0)
  {
    gint family;
    struct sockaddr_in6 addr;

    len = sizeof (addr);
    if (getsockname (sock, (struct sockaddr *) &addr, &len) == 0)
    {
      family = addr.sin6_family;
    }
    else
    {
      struct sockaddr_in invalid_sockaddr;

      invalid_sockaddr.sin_family = AF_INET;
      invalid_sockaddr.sin_port = GUINT16_TO_BE (0);
      invalid_sockaddr.sin_addr.s_addr = GUINT32_TO_BE (0xffffffff);

      bind (sock,
          (struct sockaddr *) &invalid_sockaddr,
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
          case SOCK_STREAM: result = "tcp"; break;
          case  SOCK_DGRAM: result = "udp"; break;
        }
        break;
      case AF_INET6:
        switch (type)
        {
          case SOCK_STREAM: result = "tcp6"; break;
          case  SOCK_DGRAM: result = "udp6"; break;
        }
        break;
#ifndef HAVE_WINDOWS
      case AF_UNIX:
        switch (type)
        {
          case SOCK_STREAM: result = "unix:stream"; break;
          case  SOCK_DGRAM: result = "unix:dgram";  break;
        }
        break;
#endif
    }
  }

  return (result != NULL)
      ? JS_NewString (ctx, result)
      : JS_NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_local_address)
{
  gint sock;
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = (struct sockaddr *) &large_addr;
  gum_socklen_t len = sizeof (large_addr);

  if (!_gum_quick_args_parse (args, "i", &sock))
    return JS_EXCEPTION;

  if (getsockname (sock, addr, &len) != 0)
    return JS_NULL;

  return gum_quick_socket_address_new (ctx, addr, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_get_peer_address)
{
  gint sock;
  struct sockaddr_in6 large_addr;
  struct sockaddr * addr = (struct sockaddr *) &large_addr;
  gum_socklen_t len = sizeof (large_addr);

  if (!_gum_quick_args_parse (args, "i", &sock))
    return JS_EXCEPTION;

  if (getpeername (sock, addr, &len) != 0)
    return JS_NULL;

  return gum_quick_socket_address_new (ctx, addr, core);
}

static JSValue
gum_quick_socket_listener_new (JSContext * ctx,
                               GSocketListener * listener,
                               GumQuickSocket * parent)
{
  JSValue wrapper = JS_NewObjectClass (ctx, parent->socket_listener_class);

  _gum_quick_object_manager_add (&parent->objects, ctx, wrapper, listener);

  return wrapper;
}

static gboolean
gum_quick_socket_listener_get (JSContext * ctx,
                               JSValueConst val,
                               GumQuickCore * core,
                               GumQuickObject ** object)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->socket_listener_class, core,
      (gpointer *) object);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_listener_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_listener_close)
{
  GumQuickObject * self;
  JSValue callback;
  GumQuickCloseListenerOperation * op;

  if (!gum_quick_socket_listener_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F", &callback))
    return JS_EXCEPTION;

  g_cancellable_cancel (self->cancellable);

  op = _gum_quick_object_operation_new (GumQuickCloseListenerOperation, self,
      callback, gum_quick_close_listener_operation_perform, NULL);
  _gum_quick_object_operation_schedule_when_idle (op, NULL);

  return JS_UNDEFINED;
}

static void
gum_quick_close_listener_operation_perform (
    GumQuickCloseListenerOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickScope scope;

  g_socket_listener_close (op->object->handle);

  _gum_quick_scope_enter (&scope, op->core);
  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED, 0, NULL);
  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_listener_accept)
{
  GumQuickObject * self;
  JSValue callback;
  GumQuickAcceptOperation * op;

  if (!gum_quick_socket_listener_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "F", &callback))
    return JS_EXCEPTION;

  op = _gum_quick_object_operation_new (GumQuickAcceptOperation, self, callback,
      gum_quick_accept_operation_start, NULL);
  _gum_quick_object_operation_schedule (op);

  return JS_UNDEFINED;
}

static void
gum_quick_accept_operation_start (GumQuickAcceptOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickObject * listener = op->object;

  g_socket_listener_accept_async (listener->handle, listener->cancellable,
      (GAsyncReadyCallback) gum_quick_accept_operation_finish, self);
}

static void
gum_quick_accept_operation_finish (GSocketListener * listener,
                                   GAsyncResult * result,
                                   GumQuickAcceptOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  GError * error = NULL;
  GSocketConnection * connection;
  GumQuickScope scope;
  JSValue argv[2];

  connection = g_socket_listener_accept_finish (listener, result, NULL, &error);

  _gum_quick_scope_enter (&scope, core);

  if (error == NULL)
  {
    argv[0] = JS_NULL;
    argv[1] = gum_quick_socket_connection_new (ctx, connection,
        gumjs_get_parent_module (core));
  }
  else
  {
    argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
    argv[1] = JS_NULL;
  }

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);
  JS_FreeValue (ctx, argv[1]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

static JSValue
gum_quick_socket_connection_new (JSContext * ctx,
                                 GSocketConnection * connection,
                                 GumQuickSocket * parent)
{
  JSValue wrapper = JS_NewObjectClass (ctx, parent->socket_connection_class);

  _gum_quick_object_manager_add (&parent->objects, ctx, wrapper, connection);

  return wrapper;
}

static gboolean
gum_quick_socket_connection_get (JSContext * ctx,
                                 JSValueConst val,
                                 GumQuickCore * core,
                                 GumQuickObject ** object)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->socket_connection_class, core,
      (gpointer *) object);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_socket_connection_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FUNCTION (gumjs_socket_connection_set_no_delay)
{
  GumQuickObject * self;
  gboolean no_delay;
  JSValue callback;
  GumQuickSetNoDelayOperation * op;

  if (!gum_quick_socket_connection_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "tF", &no_delay, &callback))
    return JS_EXCEPTION;

  op = _gum_quick_object_operation_new (GumQuickSetNoDelayOperation, self,
      callback, gum_quick_set_no_delay_operation_perform, NULL);
  op->no_delay = no_delay;
  _gum_quick_object_operation_schedule (op);

  return JS_UNDEFINED;
}

static void
gum_quick_set_no_delay_operation_perform (GumQuickSetNoDelayOperation * self)
{
  GumQuickObjectOperation * op = GUM_QUICK_OBJECT_OPERATION (self);
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;
  GSocket * socket;
  GError * error = NULL;
  gboolean success;
  GumQuickScope scope;
  JSValue argv[2];

  socket = g_socket_connection_get_socket (op->object->handle);

  success = g_socket_set_option (socket, IPPROTO_TCP, TCP_NODELAY,
      self->no_delay, &error);

  _gum_quick_scope_enter (&scope, core);

  argv[0] = _gum_quick_error_new_take_error (ctx, &error, core);
  argv[1] = JS_NewBool (ctx, success);

  _gum_quick_scope_call_void (&scope, op->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  _gum_quick_scope_leave (&scope);

  _gum_quick_object_operation_finish (op);
}

static gboolean
gum_quick_socket_family_get (JSContext * ctx,
                             JSValue val,
                             GSocketFamily * family)
{
  gboolean success = FALSE;
  const char * str = NULL;

  if (JS_IsNull (val))
  {
    *family = G_SOCKET_FAMILY_INVALID;
    success = TRUE;
    goto beach;
  }

  if (!JS_IsString (val))
    goto invalid_value;
  str = JS_ToCString (ctx, val);

  if (strcmp (str, "unix") == 0)
    *family = G_SOCKET_FAMILY_UNIX;
  else if (strcmp (str, "ipv4") == 0)
    *family = G_SOCKET_FAMILY_IPV4;
  else if (strcmp (str, "ipv6") == 0)
    *family = G_SOCKET_FAMILY_IPV6;
  else
    goto invalid_value;

  success = TRUE;
  goto beach;

invalid_value:
  {
    _gum_quick_throw_literal (ctx, "invalid socket address family");
    goto beach;
  }
beach:
  {
    JS_FreeCString (ctx, str);

    return success;
  }
}

static gboolean
gum_quick_unix_socket_address_type_get (JSContext * ctx,
                                        JSValue val,
                                        GUnixSocketAddressType * type)
{
  gboolean success = FALSE;
  const char * str = NULL;

  if (JS_IsNull (val))
  {
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
    success = TRUE;
    goto beach;
  }

  if (!JS_IsString (val))
    goto invalid_value;
  str = JS_ToCString (ctx, val);

  if (strcmp (str, "anonymous") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_ANONYMOUS;
  else if (strcmp (str, "path") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_PATH;
  else if (strcmp (str, "abstract") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT;
  else if (strcmp (str, "abstract-padded") == 0)
    *type = G_UNIX_SOCKET_ADDRESS_ABSTRACT_PADDED;
  else
    goto invalid_value;

  success = TRUE;
  goto beach;

invalid_value:
  {
    _gum_quick_throw_literal (ctx, "invalid UNIX socket address type");
    goto beach;
  }
beach:
  {
    JS_FreeCString (ctx, str);

    return success;
  }
}

static JSValue
gum_quick_socket_address_new (JSContext * ctx,
                              struct sockaddr * addr,
                              GumQuickCore * core)
{
  JSValue obj;

  switch (addr->sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in * inet_addr = (struct sockaddr_in *) addr;
#ifdef HAVE_WINDOWS
      gunichar2 ip_utf16[15 + 1 + 5 + 1];
      gchar ip[15 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      gchar * p;

      WSAAddressToStringW (addr, sizeof (struct sockaddr_in), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      p = strchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET_ADDRSTRLEN];

      inet_ntop (AF_INET, &inet_addr->sin_addr, ip, sizeof (ip));
#endif

      obj = JS_NewObject (ctx);

      JS_DefinePropertyValue (ctx, obj,
          GUM_QUICK_CORE_ATOM (core, ip),
          JS_NewString (ctx, ip),
          JS_PROP_C_W_E);
      JS_DefinePropertyValue (ctx, obj,
          GUM_QUICK_CORE_ATOM (core, port),
          JS_NewInt32 (ctx, GUINT16_FROM_BE (inet_addr->sin_port)),
          JS_PROP_C_W_E);

      break;
    }
    case AF_INET6:
    {
      struct sockaddr_in6 * inet_addr = (struct sockaddr_in6 *) addr;
#ifdef HAVE_WINDOWS
      gunichar2 ip_utf16[45 + 1 + 5 + 1];
      gchar ip[45 + 1 + 5 + 1];
      DWORD len = G_N_ELEMENTS (ip_utf16);
      gchar * p;

      WSAAddressToStringW (addr, sizeof (struct sockaddr_in6), NULL,
          (LPWSTR) ip_utf16, &len);
      WideCharToMultiByte (CP_UTF8, 0, (LPWSTR) ip_utf16, -1, ip, len, NULL,
          NULL);
      p = strrchr (ip, ':');
      if (p != NULL)
        *p = '\0';
#else
      gchar ip[INET6_ADDRSTRLEN];

      inet_ntop (AF_INET6, &inet_addr->sin6_addr, ip, sizeof (ip));
#endif

      obj = JS_NewObject (ctx);

      JS_DefinePropertyValue (ctx, obj,
          GUM_QUICK_CORE_ATOM (core, ip),
          JS_NewString (ctx, ip),
          JS_PROP_C_W_E);
      JS_DefinePropertyValue (ctx, obj,
          GUM_QUICK_CORE_ATOM (core, port),
          JS_NewInt32 (ctx, GUINT16_FROM_BE (inet_addr->sin6_port)),
          JS_PROP_C_W_E);

      break;
    }
    case AF_UNIX:
    {
      const gchar * path = ""; /* FIXME */

      obj = JS_NewObject (ctx);

      JS_DefinePropertyValue (ctx, obj,
          GUM_QUICK_CORE_ATOM (core, path),
          JS_NewString (ctx, path),
          JS_PROP_C_W_E);

      break;
    }
    default:
      return JS_NULL;
  }

  return obj;
}
```