Response:
The user has provided a snippet of C code from `extension.c`, a file within the Frida project related to Python bindings. They are asking for an explanation of its functionality, specifically focusing on connections to reverse engineering, low-level aspects, logical inferences, common user errors, and debugging context. Since this is part 2 of 5, I need to focus on the provided code block specifically and summarize its purpose.

The provided code mainly defines `PyMethodDef` structures, which are used by Python's C API to expose C functions as methods of Python objects. It also defines `PyMemberDef` structures to expose C struct members as Python object attributes. Finally, it defines `PYFRIDA_DEFINE_TYPE` macros, which likely register custom Python types corresponding to Frida's internal GObject types.

Therefore, the core functionality is about *bridging the gap between Frida's C/GObject-based API and its Python interface*. It defines the available methods and attributes for various Frida objects when accessed from Python.

Here's a breakdown of the individual components:

*   **`PyPortalService_methods`**: Defines methods for a `PortalService` object, allowing interaction with in-process control channels.
*   **`PyPortalService_members`**: Defines members for a `PortalService` object, including a `device` attribute.
*   **`PyCompiler_methods`**: Defines methods for a `Compiler` object, used for building Frida agents.
*   **`PyFileMonitor_methods`**: Defines methods for a `FileMonitor` object, used for monitoring file system events.
*   **`PyIOStream_methods`**: Defines methods for an `IOStream` object, providing read/write capabilities.
*   **`PyCancellable_methods`**: Defines methods for a `Cancellable` object, used for managing asynchronous operations.
*   **`PYFRIDA_DEFINE_BASETYPE` and `PYFRIDA_DEFINE_TYPE` macros**:  These macros are likely responsible for:
    *   Creating Python type objects.
    *   Associating the C struct representing the Frida object with its Python counterpart.
    *   Defining basic Python object behaviors like initialization (`Py_tp_init`), deallocation (`Py_tp_dealloc`), representation (`Py_tp_repr`), and potentially more.
    *   Registering the defined methods and members for each type.

**Summary of functionality for Part 2:**

This section of the `extension.c` file defines the Python interface for several core Frida functionalities. It declares the methods and attributes that will be accessible in Python for interacting with concepts like portal services, agent compilation, file system monitoring, input/output streams, and cancellable operations. Essentially, it's a blueprint for how these Frida features are exposed and controlled from Python.
这是 `frida/subprojects/frida-python/frida/_frida/extension.c` 文件的第二部分，主要功能是 **定义了 Frida 库中各种核心对象的 Python 接口，包括它们的方法和成员变量**。

以下是更详细的功能归纳：

**1. 定义 Python 对象的方法 (Methods):**

*   **`PyPortalService_methods`**:  定义了 `PortalService` 对象的 Python 方法，用于管理 Frida Agent 内的通信通道 (Portal)。这些方法允许：
    *   `start`: 启动监听连接。
    *   `stop`: 停止监听连接，并断开所有已连接的客户端。
    *   `kick`: 断开指定的连接。
    *   `post`: 向特定的控制通道发送消息。
    *   `narrowcast`: 向带有特定标签的控制通道发送消息。
    *   `broadcast`: 向所有控制通道广播消息。
    *   `enumerate_tags`: 枚举特定连接的标签。
    *   `tag`: 给特定的控制通道添加标签。
    *   `untag`: 移除特定控制通道的标签。

*   **`PyCompiler_methods`**: 定义了 `Compiler` 对象的 Python 方法，用于编译 Frida Agent 代码。
    *   `build`: 构建一个 Agent。
    *   `watch`: 持续构建一个 Agent，通常用于监听文件变化并自动重新编译。

*   **`PyFileMonitor_methods`**: 定义了 `FileMonitor` 对象的 Python 方法，用于监控文件系统的变化。
    *   `enable`: 启用文件监控。
    *   `disable`: 禁用文件监控。

*   **`PyIOStream_methods`**: 定义了 `IOStream` 对象的 Python 方法，用于进行输入/输出操作。
    *   `is_closed`: 查询流是否已关闭。
    *   `close`: 关闭流。
    *   `read`: 从流中读取指定数量的字节。
    *   `read_all`: 从流中读取指定数量的字节，如果无法读取到足够的数据则会阻塞或抛出异常。
    *   `write`: 将提供的数据写入流。
    *   `write_all`: 将所有提供的数据写入流，如果无法写入所有数据则会阻塞或抛出异常。

*   **`PyCancellable_methods`**: 定义了 `Cancellable` 对象的 Python 方法，用于支持取消异步操作。
    *   `is_cancelled`: 查询是否已被取消。
    *   `raise_if_cancelled`: 如果已被取消，则抛出异常。
    *   `get_fd`: 获取用于集成到事件循环的文件描述符。
    *   `release_fd`: 释放 `get_fd()` 分配的资源。
    *   `get_current`: 获取当前栈顶的 `Cancellable` 对象。
    *   `push_current`: 将 `Cancellable` 对象压入栈顶。
    *   `pop_current`: 将 `Cancellable` 对象从栈顶弹出。
    *   `connect`: 注册取消通知回调函数。
    *   `disconnect`: 取消注册取消通知回调函数。
    *   `cancel`: 设置为已取消状态。

**2. 定义 Python 对象的成员变量 (Members):**

*   **`PyPortalService_members`**: 定义了 `PortalService` 对象的 Python 成员变量。
    *   `device`:  只读属性，表示用于进程内控制的 `Device` 对象。

**3. 定义和注册 Python 类型 (Types):**

*   使用 `PYFRIDA_DEFINE_BASETYPE` 和 `PYFRIDA_DEFINE_TYPE` 宏定义了各种 Frida 对象的 Python 类型，例如 `Object`, `DeviceManager`, `Device`, `Application`, `Process`, `Spawn`, `Child`, `Crash`, `Bus`, `Service`, `Session`, `Script`, `Relay`, `PortalMembership`, `PortalService`, `EndpointParameters`, `Compiler`, `FileMonitor`, `IOStream`, `Cancellable`。
*   这些宏负责：
    *   关联 C 结构体 (例如 `Device`) 与其对应的 Python 类 (`_frida.Device`)。
    *   设置 Python 对象的文档字符串 (`Py_tp_doc`)。
    *   指定初始化 (`Py_tp_init`)、析构 (`Py_tp_dealloc`) 和表示 (`Py_tp_repr`) 等特殊方法。
    *   关联定义的方法 (`Py_tp_methods`) 和成员变量 (`Py_tp_members`)。

**与逆向方法的联系及举例说明:**

*   **`PortalService`**: 在 Frida Agent 内部创建通信通道，Agent 可以通过这些通道与 Frida 宿主程序 (例如 Python 脚本) 进行通信。这在逆向分析中非常有用，Agent 可以将 Hook 到的信息、执行状态等发送回 Python 脚本进行分析和展示。
    *   **例子**:  在 Android 逆向中，Agent 可以 Hook 一个函数，并通过 `portal_service.post()` 将函数的参数和返回值发送回 Python 脚本进行记录和分析。
*   **`Compiler`**:  允许在运行时编译 Frida Agent 代码。这可以用于动态加载和更新 Agent 功能，而无需重启目标进程。
    *   **例子**:  在逆向过程中，如果需要添加新的 Hook 点或修改现有 Hook 逻辑，可以使用 `compiler.build()` 或 `compiler.watch()` 动态更新 Agent。
*   **`FileMonitor`**:  监控目标进程访问的文件，可以帮助逆向工程师了解目标程序的行为，例如配置文件读取、日志写入等。
    *   **例子**:  在 Windows 逆向中，可以使用 `file_monitor.enable()` 监控目标程序是否访问特定的注册表项或文件，以了解其功能或查找漏洞。
*   **`IOStream`**:  提供底层的输入/输出流操作，可以用于与目标进程内的特定文件描述符进行交互。
    *   **例子**:  在 Linux 逆向中，如果目标进程使用了自定义的 socket 通信，可以通过 `IOStream` 对象读取或写入 socket 的数据。
*   **`Cancellable`**:  用于取消长时间运行的操作，这在编写复杂的 Frida 脚本时可以提高效率和响应性。
    *   **例子**:  在逆向分析中，如果需要枚举目标进程的所有模块，这个操作可能耗时较长，可以使用 `Cancellable` 对象来允许用户中断枚举过程。

**涉及二进制底层、Linux, Android 内核及框架的知识及举例说明:**

*   **所有对象类型**: 这些对象类型 (例如 `Device`, `Process`, `Session`) 的实现都依赖于与目标进程的底层交互，涉及到进程间通信、内存读写、代码注入等二进制层面的操作。Frida 内部使用了操作系统提供的 API (例如 Linux 的 ptrace，Android 的 Debugger API) 来实现这些功能。
*   **`PortalService`**:  底层的实现可能涉及到共享内存、管道等进程间通信机制，这些都是操作系统层面的概念。在 Android 上，可能涉及到 Binder IPC 机制。
*   **`Compiler`**:  需要理解目标平台的指令集架构，才能生成能在目标进程中执行的代码。
*   **`FileMonitor`**:  依赖于操作系统提供的文件系统事件通知机制，例如 Linux 的 inotify，Android 的 FileObserver。
*   **`IOStream`**:  直接操作文件描述符，这是 Linux 和 Android 等 POSIX 系统中的核心概念。
*   **`Cancellable`**:  底层的实现可能涉及到线程同步、信号处理等机制。

**逻辑推理，假设输入与输出:**

由于这段代码主要是定义接口，并没有直接的逻辑运算，因此很难给出假设输入和输出。 逻辑推理更多发生在 Frida 库的 C++ 核心部分以及使用这些接口的 Python 脚本中。

**涉及用户或者编程常见的使用错误及举例说明:**

*   **`PortalService`**:
    *   **错误**:  多次调用 `start()` 而不先调用 `stop()`，可能导致端口占用或资源泄漏。
    *   **例子**:  用户在 Agent 代码中重复执行 `portal_service.start()` 而没有相应的 `portal_service.stop()`。
    *   **调试线索**:  如果用户报告连接失败或资源耗尽，可以检查 Agent 代码中 `start()` 和 `stop()` 的调用是否匹配。
*   **`IOStream`**:
    *   **错误**:  在流已关闭后尝试读取或写入数据。
    *   **例子**:  用户在 Python 脚本中对一个已经 `close()` 的 `IOStream` 对象调用 `read()`。
    *   **调试线索**:  检查用户代码中对 `close()` 的调用时机，以及是否在关闭后继续使用了该 `IOStream` 对象。
*   **`Cancellable`**:
    *   **错误**:  `push_current()` 和 `pop_current()` 不匹配，可能导致意外的取消行为。
    *   **例子**:  用户在异步操作开始时调用了 `push_current()`, 但在操作结束时忘记调用 `pop_current()`。
    *   **调试线索**:  检查用户代码中 `push_current()` 和 `pop_current()` 的调用是否成对出现。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户安装 Frida 和 frida-python 库。**
2. **用户编写 Python 脚本，使用 `frida` 模块与目标进程进行交互。**
3. **在 Python 脚本中，用户创建或获取 Frida 的各种对象实例，例如 `frida.get_usb_device()` 获取设备，`device.attach(process_name)` 连接到进程。**
4. **用户可能会使用这些对象的方法，例如 `session.create_script()` 创建脚本，`script.load()` 加载脚本。**
5. **在 Agent 代码中 (通常是 JavaScript)，用户可能会使用 `rpc.exports` 暴露接口，并通过 `portal_service` 与 Python 脚本进行通信。**
6. **当 Python 脚本调用这些对象的方法时，例如 `portal_service.start()`, Python 的 C 扩展模块 `_frida.extension.c` 中的对应函数 (`PyPortalService_start`) 会被调用。**

作为调试线索，如果用户报告某个 Frida 功能 (例如 Portal 服务) 不工作，你可以查看 `_frida.extension.c` 中对应方法的实现，以及用户 Python 脚本中对这些方法的调用方式，来定位问题。 例如，如果用户报告无法连接到 Agent 的 Portal 服务，你可能会检查 `PyPortalService_start` 和相关的 C 代码，以及用户 Agent 代码中 `portal_service.start()` 的调用。

**总结一下它的功能 (基于提供的代码片段):**

这段代码片段的核心功能是 **定义了 Frida Python 绑定的接口，将 Frida C 库中的各种功能以 Python 对象和方法的形式暴露给 Python 开发者使用**。 它详细描述了 `PortalService`, `Compiler`, `FileMonitor`, `IOStream`, 和 `Cancellable` 等关键 Frida 对象的 Python 接口，包括它们可以执行的操作和可以访问的属性。  这是 Frida Python 绑定实现的关键部分，使得 Python 程序员能够方便地利用 Frida 的强大功能进行动态 instrumentation 和逆向分析。

### 提示词
```
这是目录为frida/subprojects/frida-python/frida/_frida/extension.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
) PyPortalService_start, METH_NOARGS, "Start listening for incoming connections." },
  { "stop", (PyCFunction) PyPortalService_stop, METH_NOARGS, "Stop listening for incoming connections, and kick any connected clients." },
  { "kick", (PyCFunction) PyPortalService_kick, METH_VARARGS, "Kick out a specific connection." },
  { "post", (PyCFunction) PyPortalService_post, METH_VARARGS | METH_KEYWORDS, "Post a message to a specific control channel." },
  { "narrowcast", (PyCFunction) PyPortalService_narrowcast, METH_VARARGS | METH_KEYWORDS, "Post a message to control channels with a specific tag." },
  { "broadcast", (PyCFunction) PyPortalService_broadcast, METH_VARARGS | METH_KEYWORDS, "Broadcast a message to all control channels." },
  { "enumerate_tags", (PyCFunction) PyPortalService_enumerate_tags, METH_VARARGS, "Enumerate tags of a specific connection." },
  { "tag", (PyCFunction) PyPortalService_tag, METH_VARARGS | METH_KEYWORDS, "Tag a specific control channel." },
  { "untag", (PyCFunction) PyPortalService_untag, METH_VARARGS | METH_KEYWORDS, "Untag a specific control channel." },
  { NULL }
};

static PyMemberDef PyPortalService_members[] =
{
  { "device", T_OBJECT_EX, G_STRUCT_OFFSET (PyPortalService, device), READONLY, "Device for in-process control." },
  { NULL }
};

static PyMethodDef PyCompiler_methods[] =
{
  { "build", (PyCFunction) PyCompiler_build, METH_VARARGS | METH_KEYWORDS, "Build an agent." },
  { "watch", (PyCFunction) PyCompiler_watch, METH_VARARGS | METH_KEYWORDS, "Continuously build an agent." },
  { NULL }
};

static PyMethodDef PyFileMonitor_methods[] =
{
  { "enable", (PyCFunction) PyFileMonitor_enable, METH_NOARGS, "Enable the file monitor." },
  { "disable", (PyCFunction) PyFileMonitor_disable, METH_NOARGS, "Disable the file monitor." },
  { NULL }
};

static PyMethodDef PyIOStream_methods[] =
{
  { "is_closed", (PyCFunction) PyIOStream_is_closed, METH_NOARGS, "Query whether the stream is closed." },
  { "close", (PyCFunction) PyIOStream_close, METH_NOARGS, "Close the stream." },
  { "read", (PyCFunction) PyIOStream_read, METH_VARARGS, "Read up to the specified number of bytes from the stream." },
  { "read_all", (PyCFunction) PyIOStream_read_all, METH_VARARGS, "Read exactly the specified number of bytes from the stream." },
  { "write", (PyCFunction) PyIOStream_write, METH_VARARGS, "Write as much as possible of the provided data to the stream." },
  { "write_all", (PyCFunction) PyIOStream_write_all, METH_VARARGS, "Write all of the provided data to the stream." },
  { NULL }
};

static PyMethodDef PyCancellable_methods[] =
{
  { "is_cancelled", (PyCFunction) PyCancellable_is_cancelled, METH_NOARGS, "Query whether cancellable has been cancelled." },
  { "raise_if_cancelled", (PyCFunction) PyCancellable_raise_if_cancelled, METH_NOARGS, "Raise an exception if cancelled." },
  { "get_fd", (PyCFunction) PyCancellable_get_fd, METH_NOARGS, "Get file descriptor for integrating with an event loop." },
  { "release_fd", (PyCFunction) PyCancellable_release_fd, METH_NOARGS, "Release a resource previously allocated by get_fd()." },
  { "get_current", (PyCFunction) PyCancellable_get_current, METH_CLASS | METH_NOARGS, "Get the top cancellable from the stack." },
  { "push_current", (PyCFunction) PyCancellable_push_current, METH_NOARGS, "Push cancellable onto the cancellable stack." },
  { "pop_current", (PyCFunction) PyCancellable_pop_current, METH_NOARGS, "Pop cancellable off the cancellable stack." },
  { "connect", (PyCFunction) PyCancellable_connect, METH_VARARGS, "Register notification callback." },
  { "disconnect", (PyCFunction) PyCancellable_disconnect, METH_VARARGS, "Unregister notification callback." },
  { "cancel", (PyCFunction) PyCancellable_cancel, METH_NOARGS, "Set cancellable to cancelled." },
  { NULL }
};

PYFRIDA_DEFINE_BASETYPE ("_frida.Object", GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida Object" },
  { Py_tp_init, PyGObject_init },
  { Py_tp_dealloc, PyGObject_dealloc },
  { Py_tp_methods, PyGObject_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.DeviceManager", DeviceManager, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida Device Manager" },
  { Py_tp_init, PyDeviceManager_init },
  { Py_tp_dealloc, PyDeviceManager_dealloc },
  { Py_tp_methods, PyDeviceManager_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Device", Device, GObject, PyDevice_init_from_handle, frida_unref,
  { Py_tp_doc, "Frida Device" },
  { Py_tp_init, PyDevice_init },
  { Py_tp_dealloc, PyDevice_dealloc },
  { Py_tp_repr, PyDevice_repr },
  { Py_tp_methods, PyDevice_methods },
  { Py_tp_members, PyDevice_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Application", Application, GObject, PyApplication_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Application" },
  { Py_tp_init, PyApplication_init },
  { Py_tp_dealloc, PyApplication_dealloc },
  { Py_tp_repr, PyApplication_repr },
  { Py_tp_members, PyApplication_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Process", Process, GObject, PyProcess_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Process" },
  { Py_tp_init, PyProcess_init },
  { Py_tp_dealloc, PyProcess_dealloc },
  { Py_tp_repr, PyProcess_repr },
  { Py_tp_members, PyProcess_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Spawn", Spawn, GObject, PySpawn_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Spawn" },
  { Py_tp_init, PySpawn_init },
  { Py_tp_dealloc, PySpawn_dealloc },
  { Py_tp_repr, PySpawn_repr },
  { Py_tp_members, PySpawn_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Child", Child, GObject, PyChild_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Child" },
  { Py_tp_init, PyChild_init },
  { Py_tp_dealloc, PyChild_dealloc },
  { Py_tp_repr, PyChild_repr },
  { Py_tp_members, PyChild_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Crash", Crash, GObject, PyCrash_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Crash Details" },
  { Py_tp_init, PyCrash_init },
  { Py_tp_dealloc, PyCrash_dealloc },
  { Py_tp_repr, PyCrash_repr },
  { Py_tp_members, PyCrash_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Bus", Bus, GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida Message Bus" },
  { Py_tp_methods, PyBus_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Service", Service, GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida Service" },
  { Py_tp_methods, PyService_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Session", Session, GObject, PySession_init_from_handle, frida_unref,
  { Py_tp_doc, "Frida Session" },
  { Py_tp_init, PySession_init },
  { Py_tp_repr, PySession_repr },
  { Py_tp_methods, PySession_methods },
  { Py_tp_members, PySession_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Script", Script, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida Script" },
  { Py_tp_methods, PyScript_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Relay", Relay, GObject, PyRelay_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Relay" },
  { Py_tp_init, PyRelay_init },
  { Py_tp_dealloc, PyRelay_dealloc },
  { Py_tp_repr, PyRelay_repr },
  { Py_tp_members, PyRelay_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.PortalMembership", PortalMembership, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida Portal Membership" },
  { Py_tp_methods, PyPortalMembership_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.PortalService", PortalService, GObject, PyPortalService_init_from_handle, frida_unref,
  { Py_tp_doc, "Frida Portal Service" },
  { Py_tp_init, PyPortalService_init },
  { Py_tp_dealloc, PyPortalService_dealloc },
  { Py_tp_methods, PyPortalService_methods },
  { Py_tp_members, PyPortalService_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.EndpointParameters", EndpointParameters, GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida EndpointParameters" },
  { Py_tp_init, PyEndpointParameters_init },
);

PYFRIDA_DEFINE_TYPE ("_frida.Compiler", Compiler, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida File Monitor" },
  { Py_tp_init, PyCompiler_init },
  { Py_tp_methods, PyCompiler_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.FileMonitor", FileMonitor, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida File Monitor" },
  { Py_tp_init, PyFileMonitor_init },
  { Py_tp_methods, PyFileMonitor_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.IOStream", IOStream, GObject, PyIOStream_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida IOStream" },
  { Py_tp_init, PyIOStream_init },
  { Py_tp_repr, PyIOStream_repr },
  { Py_tp_methods, PyIOStream_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Cancellable", Cancellable, GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida Cancellable" },
  { Py_tp_init, PyCancellable_init },
  { Py_tp_repr, PyCancellable_repr },
  { Py_tp_methods, PyCancellable_methods },
);


static PyObject *
PyGObject_new_take_handle (gpointer handle, const PyGObjectType * pytype)
{
  PyObject * object;

  if (handle == NULL)
    PyFrida_RETURN_NONE;

  object = PyGObject_try_get_from_handle (handle);
  if (object == NULL)
  {
    object = PyObject_CallFunction (pytype->object, NULL);
    PyGObject_take_handle (PY_GOBJECT (object), handle, pytype);

    if (pytype->init_from_handle != NULL)
      pytype->init_from_handle (object, handle);
  }
  else
  {
    pytype->destroy (handle);
    Py_IncRef (object);
  }

  return object;
}

static PyObject *
PyGObject_try_get_from_handle (gpointer handle)
{
  return g_object_get_data (handle, "pyobject");
}

static int
PyGObject_init (PyGObject * self)
{
  self->handle = NULL;
  self->type = PYFRIDA_TYPE (GObject);

  self->signal_closures = NULL;

  return 0;
}

static void
PyGObject_dealloc (PyGObject * self)
{
  gpointer handle;

  handle = PyGObject_steal_handle (self);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    self->type->destroy (handle);
    Py_END_ALLOW_THREADS
  }

  ((freefunc) PyType_GetSlot (Py_TYPE (self), Py_tp_free)) (self);
}

static void
PyGObject_take_handle (PyGObject * self, gpointer handle, const PyGObjectType * type)
{
  self->handle = handle;
  self->type = type;

  if (handle != NULL)
    g_object_set_data (G_OBJECT (handle), "pyobject", self);
}

static gpointer
PyGObject_steal_handle (PyGObject * self)
{
  gpointer handle = self->handle;
  GSList * entry;

  if (handle == NULL)
    return NULL;

  for (entry = self->signal_closures; entry != NULL; entry = entry->next)
  {
    PyGObjectSignalClosure * closure = entry->data;
    G_GNUC_UNUSED guint num_matches;

    num_matches = g_signal_handlers_disconnect_matched (handle, G_SIGNAL_MATCH_CLOSURE, closure->signal_id, 0, &closure->parent, NULL, NULL);
    g_assert (num_matches == 1);
  }
  g_clear_pointer (&self->signal_closures, g_slist_free);

  g_object_set_data (G_OBJECT (handle), "pyobject", NULL);

  self->handle = NULL;

  return handle;
}

static PyObject *
PyGObject_on (PyGObject * self, PyObject * args)
{
  GType instance_type;
  guint signal_id;
  PyObject * callback;
  guint max_arg_count, allowed_arg_count_including_sender;
  GSignalQuery query;
  GClosure * closure;

  instance_type = G_OBJECT_TYPE (self->handle);

  if (!PyGObject_parse_signal_method_args (args, instance_type, &signal_id, &callback))
    return NULL;

  max_arg_count = PyFrida_get_max_argument_count (callback);
  if (max_arg_count != G_MAXUINT)
  {
    g_signal_query (signal_id, &query);

    allowed_arg_count_including_sender = 1 + query.n_params;

    if (max_arg_count > allowed_arg_count_including_sender)
      goto too_many_arguments;
  }

  closure = PyGObject_make_closure_for_signal (signal_id, callback, max_arg_count);
  g_signal_connect_closure_by_id (self->handle, signal_id, 0, closure, TRUE);

  self->signal_closures = g_slist_prepend (self->signal_closures, closure);

  PyFrida_RETURN_NONE;

too_many_arguments:
  {
    return PyErr_Format (PyExc_TypeError,
        "callback expects too many arguments, the '%s' signal only has %u but callback expects %u",
        g_signal_name (signal_id), query.n_params, max_arg_count);
  }
}

static PyObject *
PyGObject_off (PyGObject * self, PyObject * args)
{
  guint signal_id;
  PyObject * callback;
  GSList * entry;
  GClosure * closure;
  G_GNUC_UNUSED guint num_matches;

  if (!PyGObject_parse_signal_method_args (args, G_OBJECT_TYPE (self->handle), &signal_id, &callback))
    return NULL;

  entry = g_slist_find_custom (self->signal_closures, callback, (GCompareFunc) PyGObject_compare_signal_closure_callback);
  if (entry == NULL)
    goto unknown_callback;

  closure = entry->data;
  self->signal_closures = g_slist_delete_link (self->signal_closures, entry);

  num_matches = g_signal_handlers_disconnect_matched (self->handle, G_SIGNAL_MATCH_CLOSURE, signal_id, 0, closure, NULL, NULL);
  g_assert (num_matches == 1);

  PyFrida_RETURN_NONE;

unknown_callback:
  {
    PyErr_SetString (PyExc_ValueError, "unknown callback");
    return NULL;
  }
}

static gint
PyGObject_compare_signal_closure_callback (PyGObjectSignalClosure * closure,
                                           PyObject * callback)
{
  int result;

  result = PyObject_RichCompareBool (closure->parent.data, callback, Py_EQ);

  return (result == 1) ? 0 : -1;
}

static gboolean
PyGObject_parse_signal_method_args (PyObject * args, GType instance_type, guint * signal_id, PyObject ** callback)
{
  const gchar * signal_name;

  if (!PyArg_ParseTuple (args, "sO", &signal_name, callback))
    return FALSE;

  if (!PyCallable_Check (*callback))
  {
    PyErr_SetString (PyExc_TypeError, "second argument must be callable");
    return FALSE;
  }

  *signal_id = g_signal_lookup (signal_name, instance_type);
  if (*signal_id == 0)
    goto invalid_signal_name;

  return TRUE;

invalid_signal_name:
  {
    GString * message;
    guint * ids, n_ids, i;

    message = g_string_sized_new (128);

    g_string_append (message, PyGObject_class_name_from_c (g_type_name (instance_type)));

    ids = g_signal_list_ids (instance_type, &n_ids);

    if (n_ids > 0)
    {
      g_string_append_printf (message, " does not have a signal named '%s', it only has: ", signal_name);

      for (i = 0; i != n_ids; i++)
      {
        if (i != 0)
          g_string_append (message, ", ");
        g_string_append_c (message, '\'');
        g_string_append (message, g_signal_name (ids[i]));
        g_string_append_c (message, '\'');
      }
    }
    else
    {
      g_string_append (message, " does not have any signals");
    }

    g_free (ids);

    PyErr_SetString (PyExc_ValueError, message->str);

    g_string_free (message, TRUE);

    return FALSE;
  }
}

static const gchar *
PyGObject_class_name_from_c (const gchar * cname)
{
  if (g_str_has_prefix (cname, "Frida"))
    return cname + 5;

  return cname;
}

static void
PyGObject_class_init (void)
{
  pygobject_type_spec_by_type = g_hash_table_new_full (NULL, NULL, NULL, NULL);
}

static void
PyGObject_register_type (GType instance_type, PyGObjectType * python_type)
{
  g_hash_table_insert (pygobject_type_spec_by_type, GSIZE_TO_POINTER (instance_type), python_type);
}

static GClosure *
PyGObject_make_closure_for_signal (guint signal_id, PyObject * callback, guint max_arg_count)
{
  GClosure * closure;
  PyGObjectSignalClosure * pyclosure;

  closure = g_closure_new_simple (sizeof (PyGObjectSignalClosure), callback);
  Py_IncRef (callback);

  g_closure_add_finalize_notifier (closure, callback, (GClosureNotify) PyGObjectSignalClosure_finalize);
  g_closure_set_marshal (closure, PyGObjectSignalClosure_marshal);

  pyclosure = PY_GOBJECT_SIGNAL_CLOSURE (closure);
  pyclosure->signal_id = signal_id;
  pyclosure->max_arg_count = max_arg_count;

  return closure;
}

static void
PyGObjectSignalClosure_finalize (PyObject * callback)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();
  Py_DecRef (callback);
  PyGILState_Release (gstate);
}

static void
PyGObjectSignalClosure_marshal (GClosure * closure, GValue * return_gvalue, guint n_param_values, const GValue * param_values,
    gpointer invocation_hint, gpointer marshal_data)
{
  PyGObjectSignalClosure * self = PY_GOBJECT_SIGNAL_CLOSURE (closure);
  PyObject * callback = closure->data;
  PyGILState_STATE gstate;
  PyObject * args, * result;

  (void) return_gvalue;
  (void) invocation_hint;
  (void) marshal_data;

  if (g_atomic_int_get (&toplevel_objects_alive) == 0)
    return;

  gstate = PyGILState_Ensure ();

  if (PyGObject_try_get_from_handle (g_value_get_object (&param_values[0])) == NULL)
    goto beach;

  if (self->max_arg_count == n_param_values)
    args = PyGObjectSignalClosure_marshal_params (param_values, n_param_values);
  else
    args = PyGObjectSignalClosure_marshal_params (param_values + 1, MIN (n_param_values - 1, self->max_arg_count));
  if (args == NULL)
  {
    PyErr_Print ();
    goto beach;
  }

  result = PyObject_CallObject (callback, args);
  if (result != NULL)
    Py_DecRef (result);
  else
    PyErr_Print ();

  Py_DecRef (args);

beach:
  PyGILState_Release (gstate);
}

static PyObject *
PyGObjectSignalClosure_marshal_params (const GValue * params, guint params_length)
{
  PyObject * args;
  guint i;

  args = PyTuple_New (params_length);

  for (i = 0; i != params_length; i++)
  {
    PyObject * arg;

    arg = PyGObject_marshal_value (&params[i]);
    if (arg == NULL)
      goto marshal_error;

    PyTuple_SetItem (args, i, arg);
  }

  return args;

marshal_error:
  {
    Py_DecRef (args);
    return NULL;
  }
}

static PyObject *
PyGObject_marshal_value (const GValue * value)
{
  GType type;

  type = G_VALUE_TYPE (value);

  switch (type)
  {
    case G_TYPE_BOOLEAN:
      return PyBool_FromLong (g_value_get_boolean (value));

    case G_TYPE_INT:
      return PyLong_FromLong (g_value_get_int (value));

    case G_TYPE_UINT:
      return PyLong_FromUnsignedLong (g_value_get_uint (value));

    case G_TYPE_FLOAT:
      return PyFloat_FromDouble (g_value_get_float (value));

    case G_TYPE_DOUBLE:
      return PyFloat_FromDouble (g_value_get_double (value));

    case G_TYPE_STRING:
      return PyGObject_marshal_string (g_value_get_string (value));

    case G_TYPE_VARIANT:
      return PyGObject_marshal_variant (g_value_get_variant (value));

    default:
      if (G_TYPE_IS_ENUM (type))
        return PyGObject_marshal_enum (g_value_get_enum (value), type);

      if (type == G_TYPE_BYTES)
        return PyGObject_marshal_bytes (g_value_get_boxed (value));

      if (G_TYPE_IS_OBJECT (type))
        return PyGObject_marshal_object (g_value_get_object (value), type);

      goto unsupported_type;
  }

  g_assert_not_reached ();

unsupported_type:
  {
    return PyErr_Format (PyExc_NotImplementedError,
        "unsupported type: '%s'",
        g_type_name (type));
  }
}

static PyObject *
PyGObject_marshal_string (const gchar * str)
{
  if (str == NULL)
    PyFrida_RETURN_NONE;

  return PyUnicode_FromString (str);
}

static gboolean
PyGObject_unmarshal_string (PyObject * value, gchar ** str)
{
  PyObject * bytes;

  *str = NULL;

  bytes = PyUnicode_AsUTF8String (value);
  if (bytes == NULL)
    return FALSE;

  *str = g_strdup (PyBytes_AsString (bytes));

  Py_DecRef (bytes);

  return *str != NULL;
}

static PyObject *
PyGObject_marshal_datetime (const gchar * iso8601_text)
{
  PyObject * result;
  GDateTime * raw_dt, * dt;

  raw_dt = g_date_time_new_from_iso8601 (iso8601_text, NULL);
  if (raw_dt == NULL)
    PyFrida_RETURN_NONE;

  dt = g_date_time_to_local (raw_dt);

  result = PyObject_CallFunction (datetime_constructor, "iiiiiii",
      g_date_time_get_year (dt),
      g_date_time_get_month (dt),
      g_date_time_get_day_of_month (dt),
      g_date_time_get_hour (dt),
      g_date_time_get_minute (dt),
      g_date_time_get_second (dt),
      g_date_time_get_microsecond (dt));

  g_date_time_unref (dt);
  g_date_time_unref (raw_dt);

  return result;
}

static PyObject *
PyGObject_marshal_strv (gchar * const * strv, gint length)
{
  PyObject * result;
  gint i;

  if (strv == NULL)
    PyFrida_RETURN_NONE;

  result = PyList_New (length);

  for (i = 0; i != length; i++)
  {
    PyList_SetItem (result, i, PyGObject_marshal_string (strv[i]));
  }

  return result;
}

static gboolean
PyGObject_unmarshal_strv (PyObject * value, gchar *** strv, gint * length)
{
  gint n, i;
  gchar ** elements;

  if (!PyList_Check (value) && !PyTuple_Check (value))
    goto invalid_type;

  n = PySequence_Size (value);
  elements = g_new0 (gchar *, n + 1);

  for (i = 0; i != n; i++)
  {
    PyObject * element;

    element = PySequence_GetItem (value, i);
    if (PyUnicode_Check (element))
    {
      Py_DecRef (element);
      element = PyUnicode_AsUTF8String (element);
    }
    if (PyBytes_Check (element))
      elements[i] = g_strdup (PyBytes_AsString (element));
    Py_DecRef (element);

    if (elements[i] == NULL)
      goto invalid_element;
  }

  *strv = elements;
  *length = n;

  return TRUE;

invalid_type:
  {
    PyErr_SetString (PyExc_TypeError, "expected list or tuple of strings");
    return FALSE;
  }
invalid_element:
  {
    g_strfreev (elements);

    PyErr_SetString (PyExc_TypeError, "expected list or tuple with string elements only");
    return FALSE;
  }
}

static PyObject *
PyGObject_marshal_envp (gchar * const * envp, gint length)
{
  PyObject * result;
  gint i;

  if (envp == NULL)
    PyFrida_RETURN_NONE;

  result = PyDict_New ();

  for (i = 0; i != length; i++)
  {
    gchar ** tokens;

    tokens = g_strsplit (envp[i], "=", 2);

    if (g_strv_length (tokens) == 2)
    {
      const gchar * name;
      PyObject * value;

      name = tokens[0];
      value = PyGObject_marshal_string (tokens[1]);

      PyDict_SetItemString (result, name, value);

      Py_DecRef (value);
    }

    g_strfreev (tokens);
  }

  return result;
}

static gboolean
PyGObject_unmarshal_envp (PyObject * dict, gchar *** envp, gint * length)
{
  gint n;
  gchar ** elements;
  gint i;
  Py_ssize_t pos;
  PyObject * name, * value;
  gchar * raw_name = NULL;
  gchar * raw_value = NULL;

  if (!PyDict_Check (dict))
    goto invalid_type;

  n = PyDict_Size (dict);
  elements = g_new0 (gchar *, n + 1);

  i = 0;
  pos = 0;
  while (PyDict_Next (dict, &pos, &name, &value))
  {
    if (!PyGObject_unmarshal_string (name, &raw_name))
      goto invalid_dict_key;

    if (!PyGObject_unmarshal_string (value, &raw_value))
      goto invalid_dict_value;

    elements[i] = g_strconcat (raw_name, "=", raw_value, NULL);

    g_free (g_steal_pointer (&raw_value));
    g_free (g_steal_pointer (&raw_name));

    i++;
  }

  *envp = elements;
  *length = n;

  return TRUE;

invalid_type:
  {
    PyErr_SetString (PyExc_TypeError, "expected dict");
    return FALSE;
  }
invalid_dict_key:
invalid_dict_value:
  {
    g_free (raw_value);
    g_free (raw_name);
    g_strfreev (elements);

    PyErr_SetString (PyExc_TypeError, "expected dict with strings only");
    return FALSE;
  }
}

static PyObject *
PyGObject_marshal_enum (gint value, GType type)
{
  GEnumClass * enum_class;
  GEnumValue * enum_value;
  PyObject * result;

  enum_class = g_type_class_ref (type);

  enum_value = g_enum_get_value (enum_class, value);
  g_assert (enum_value != NULL);

  result = PyUnicode_FromString (enum_value->value_nick);

  g_type_class_unref (enum_class);

  return result;
}

static gboolean
PyGObject_unmarshal_enum (const gchar * str, GType type, gpointer value)
{
  GEnumClass * enum_class;
  GEnumValue * enum_value;

  enum_class = g_type_class_ref (type);

  enum_value = g_enum_get_value_by_nick (enum_class, str);
  if (enum_value == NULL)
    goto invalid_value;

  *((gint *) value) = enum_value->value;

  g_type_class_unref (enum_class);

  return TRUE;

invalid_value:
  {
    GString * message;
    guint i;

    message = g_string_sized_new (128);

    g_string_append_printf (message,
        "Enum type %s does not have a value named '%s', it only has: ",
        PyGObject_class_name_from_c (g_type_name (type)), str);

    for (i = 0; i != enum_class->n_values; i++)
    {
      if (i != 0)
        g_string_append (message, ", ");
      g_string_append_c (message, '\'');
      g_string_append (message, enum_class->values[i].value_nick);
      g_string_append_c (message, '\'');
    }

    PyErr_SetString (PyExc_ValueError, message->str);

    g_string_free (message, TRUE);

    g_type_class_unref (enum_class);

    return FALSE;
  }
}

static PyObject *
PyGObject_marshal_bytes (GBytes * bytes)
{
  if (bytes == NULL)
    PyFrida_RETURN_NONE;

  return PyGObject_marshal_bytes_non_nullable (bytes);
}

static PyObject *
PyGObject_marshal_bytes_non_nullable (GBytes * bytes)
{
  gconstpointer data;
  gsize size;

  data = g_bytes_get_data (bytes, &size);

  return PyBytes_FromStringAndSize (data, size);
}

static PyObject *
PyGObject_marshal_variant (GVariant * variant)
{
  switch (g_variant_classify (variant))
  {
    case G_VARIANT_CLASS_STRING:
      return PyGObject_marshal_string (g_variant_get_string (variant, NULL));
    case G_VARIANT_CLASS_INT64:
      return PyLong_FromLongLong (g_variant_get_int64 (variant));
    case G_VARIANT_CLASS_UINT64:
      return PyLong_FromLongLong (g_variant_get_uint64 (variant));
    case G_VARIANT_CLASS_DOUBLE:
      return PyFloat_FromDouble (g_variant_get_double (variant));
    case G_VARIANT_CLASS_BOOLEAN:
      return PyBool_FromLong (g_variant_get_boolean (variant));
    case G_VARIANT_CLASS_ARRAY:
      if (g_variant_is_of_type (variant, G_VARIANT_TYPE ("ay")))
        return PyGObject_marshal_variant_byte_array (variant);

      if (g_variant_is_of_type (variant, G_VARIANT_TYPE_VARDICT))
        return PyGObject_marshal_variant_dict (variant);

      return PyGObject_marshal_variant_array (variant);
    default:
      break;
  }

  PyFrida_RETURN_NONE;
}

static PyObject *
PyGObject_marshal_variant_byte_array (GVariant * variant)
{
  gconstpointer elements;
  gsize n_elements;

  elements = g_variant_get_fixed_array (variant, &n_elements, sizeof (guint8));

  return PyBytes_FromStringAndSize (elements, n_elements);
}

static PyObject *
PyGObject_marshal_variant_dict (GVariant * variant)
{
  PyObject * dict;
  GVariantIter iter;
  gchar * key;
  GVariant * raw_value;

  dict = PyDict_New ();

  g_variant_iter_init (&iter, variant);

  while (g_variant_iter_next (&iter, "{sv}", &key, &raw_value))
  {
    PyObject * value = PyGObject_marshal_variant (raw_value);

    PyDict_SetItemString (dict, key, value);

    Py_DecRef (value);
    g_variant_unref (raw_value);
    g_free (key);
  }

  return dict;
}

static PyObject *
PyGObject_marshal_variant_array (GVariant * variant)
{
  GVariantIter iter;
  PyObject * list;
  guint i;
  GVariant * child;

  g_variant_iter_init (&iter, variant);

  list = PyList_New (g_variant_iter_n_children (&iter));

  for (i = 0; (child = g_variant_iter_next_value (&iter)) != NULL; i++)
  {
    if (g_variant_is_of_type (child, G_VARIANT_TYPE_VARIANT))
    {
      GVariant * inner = g_variant_get_variant (child);
      g_variant_unref (child);
      child = inner;
    }

    PyList_SetItem (list, i, PyGObject_marshal_variant (child));

    g_variant_unref (child);
  }

  return list;
}

static gboolean
PyGObject_unmarshal_variant (PyObject * value, GVariant ** variant)
{
  if (PyUnicode_Check (value))
  {
    gchar * str;

    PyGObject_unmarshal_string (value, &str);

    *variant = g_variant_new_take_string (str);

    return TRUE;
  }

  if (PyBool_Check (value))
  {
    *variant = g_variant_new_boolean (value == Py_True);

    return TRUE;
  }

  if (PyLong_Check (value))
  {
    PY_LONG_LONG l;

    l = PyLong_AsLongLong (value);
    if (l == -1 && PyErr_Occurred ())
      return FALSE;

    *variant = g_variant_new_int64 (l);

    return TRUE;
  }

  if (PyFloat_Check (value))
  {
    *variant = g_variant_new_double (PyFloat_AsDouble (value));

    return TRUE;
  }

  if (PyBytes_Check (value))
  {
    char * buffer;
    Py_ssize_t length;
    gpointer copy;

    PyBytes_AsStringAndSize (value, &buffer, &length);

    copy = g_memdup2 (buffer, length);
    *variant = g_variant_new_from_data (G_VARIANT_TYPE_BYTESTRING, copy, length, TRUE, g_free, copy);

    return TRUE;
  }

  if (PySequence_Check (value))
    return PyGObject_unmarshal_variant_from_sequence (value, variant);

  if (PyMapping_Check (value))
    return PyGObject_unmarshal_variant_from_mapping (value, variant);

  PyErr_SetString (PyExc_TypeError, "unsupported type");
  return FALSE;
}

static gboolean
PyGObject_unmarshal_variant_from_mapping (PyObject * mapping, GVariant ** variant)
{
  GVariantBuilder builder;
  PyObject * items = NULL;
  Py_ssize_t n, i;

  g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

  items = PyMapping_Items (mapping);
  if (items == NULL)
    goto propagate_error;

  n = PyList_Size (items);

  for (i = 0; i != n; i++)
  {
    PyObject * pair, * key, * val, * key_bytes;
    GVariant * raw_value;

    pair = PyList_GetItem (items, i);
    key = PyTuple_GetItem (pair, 0);
    val = PyTuple_GetItem (pair, 1);

    if (!PyGObject_unmarshal_variant (val, &raw_value))
      goto propagate_error;

    key_bytes = PyUnicode_AsUTF8String (key);

    g_variant_builder_add (&builder, "{sv}", PyBytes_AsString (key_bytes), raw_value);

    Py_DecRef (key_bytes);
  }

  Py_DecRef (items);

  *variant = g_variant_builder_end (&builder);

  return TRUE;

propagate_error:
  {
    Py_DecRef (items);
    g_variant_builder_clear (&builder);

    return FALSE;
  }
}

static gboolean
PyGObject_unmarshal_variant_from_sequence (PyObject * sequence, GVariant ** variant)
{
  gboolean is_tuple;
  GVariantBuilder builder;
  Py_ssize_t n, i;
  PyObject * val = NULL;

  is_tuple = PyTuple_Check (sequence);

  g_variant_builder_init (&builder, is_tuple ? G_VARIANT_TYPE_TUPLE : G_VARIANT_TYPE ("av"));

  n = PySequence_Length (sequence);
  if (n == -1)
    goto propagate_error;

  for (i = 0; i != n; i++)
  {
    GVariant * raw_value;

    val = PySequence_GetItem (sequence, i);
    if (val == NULL)
      goto propagate_error;

    if (!PyGObject_unmarshal_variant (val, &raw_value))
      goto propagate_error;

    if (is_tuple)
      g_variant_builder_add_value (&builder, raw_value);
    else
      g_variant_builder_add (&builder, "v", raw_value);

    Py_DecRef (val);
  }

  *variant = g_variant_builder_end (&builder);

  return TRUE;

propagate_error:
  {
    Py_DecRef (val);
    g_variant_builder_clear (&builder);

    return FALSE;
  }
}

static PyObject *
PyGObject_marshal_parameters_dict (GHashTable * dict)
{
  PyObject * result;
  GHashTableIter iter;
  const gchar * key;
  GVariant * raw_value;

  result = PyDict_New ();

  g_hash_table_iter_init (&iter, dict);

  while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &raw_value))
  {
    PyObject * value = PyGObject_marshal_variant (raw_value);

    PyDict_SetItemString (result, key, value);

    Py_DecRef (value);
  }

  return result;
}

static PyObject *
PyGObject_marshal_object (gpointer handle, GType type)
{
  const PyGObjectType * pytype;

  if (handle == NULL)
    PyFrida_RETURN_NONE;

  pytype = g_hash_table_lookup (pygobject_type_spec_by_type, GSIZE_TO_POINTER (type));
  if (pytype == NULL)
    pytype = PYFRIDA_TYPE (GObject);

  if (G_IS_SOCKET_ADDRESS (handle))
    return PyGObject_marshal_socket_address (handle);

  return PyGObject_new_take_handle (g_object_ref (handle), pytype);
}

static PyObject *
PyGObject_marshal_socket_address (GSocketAddress * address)
{
  PyObject * result = NULL;

  if (G_IS_INET_SOCKET_ADDRESS (address))
  {
    GInetSocketAddress * sa;
    GInetAddress * ia;
    gchar * host;
    guint16 port;

    sa = G_INET_SOCKET_ADDRESS (address);
    ia = g_inet_socket_address_get_address (sa);

    host = g_inet_address_to_string (ia);
    port = g_inet_socket_address_get_port (sa);

    if (g_socket_address_get_family (address) == G_SOCKET_FAMILY_IPV4)
      result = Py_BuildValue ("(sH)", host, port);
    else
      result = Py_BuildValue ("(sHII)", host, port, g_inet_socket_address_get_flowinfo (sa), g_inet_socket_address_get_scope_id (sa));

    g_free (host);
  }
  else if (G_IS_UNIX_SOCKET_ADDRESS (address))
  {
    GUnixSocketAddress * sa = G_UNIX_SOCKET_ADDRESS (address);

    switch (g_unix_socket_address_get_address_type (sa))
    {
      case G_UNIX_SOCKET_ADDRESS_ANONYMOUS:
      {
        result = PyUnicode_FromString ("");
        break;
      }
      case G_UNIX_SOCKET_ADDRESS_PATH:
      {
        gchar * path = g_filename_to_utf8 (g_unix_socket_address_get_path (sa), -1, NULL, NULL, NULL);
        result = PyUnicode_FromString (path);
        g_free (path);
        break;
      }
      case G_UNIX_SOCKET_ADDRESS_ABSTRACT:
      case G_UNIX_SOCKET_ADDRESS_ABSTRACT_PADDED:
      {
        result = PyBytes_FromStringAndSize (g_unix_socket_address_get_path (sa), g_unix_socket_address_get_path_len (sa));
        break;
      }
      default:
```