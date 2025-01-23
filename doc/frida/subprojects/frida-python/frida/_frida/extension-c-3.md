Response:
The user wants a summary of the functionality of the provided C code file, `extension.c`, which is part of the Frida dynamic instrumentation tool's Python bindings. I need to identify the main purpose of the code, the data structures it defines, and the operations it supports.

Here's a breakdown of the code's content and how it relates to the user's requests:

1. **Object Definitions:** The code defines several Python wrapper objects for Frida core concepts like `Child`, `Crash`, `Bus`, `Service`, `Session`, `Script`, `Relay`, `PortalMembership`, `PortalService`, and `EndpointParameters`. These wrappers allow Python code to interact with the underlying Frida C API.

2. **`repr` Implementations:** Many of these wrapper objects have a `__repr__` method implemented in C (`PyChild_repr`, `PyCrash_repr`, `PyRelay_repr`). This is a standard Python mechanism for providing a string representation of an object, useful for debugging and logging. These methods construct strings that show the object's key attributes.

3. **Initialization and Deallocation:** Each wrapper object has `__init__` (`PyChild_init`, `PyCrash_init`, etc.) and `__dealloc__` (`PyChild_dealloc`, `PyCrash_dealloc`, etc.) methods. The `__init__` methods initialize the Python object, often by taking a handle to the underlying Frida C object. The `__dealloc__` methods clean up resources, including decrementing reference counts of associated Python objects and the underlying Frida C objects.

4. **Methods for Frida Functionality:** The code exposes various Frida functionalities as Python methods on these wrapper objects. For example:
    - `PySession_create_script`: Creates a Frida script within a session.
    - `PyScript_load`: Loads a Frida script.
    - `PyBus_post`: Sends a message on the Frida bus.
    - `PyService_activate`: Activates a Frida service.
    - `PySession_detach`: Detaches from a Frida session.

5. **Error Handling:** The code uses `GError` for error reporting in the Frida C API and translates these errors into Python exceptions using `PyFrida_raise`.

6. **Threading:**  The code uses `Py_BEGIN_ALLOW_THREADS` and `Py_END_ALLOW_THREADS` to release the Global Interpreter Lock (GIL) when calling potentially blocking Frida C functions. This allows other Python threads to run concurrently.

7. **Data Marshalling:** The code uses functions like `PyGObject_marshal_string`, `PyGObject_marshal_parameters_dict`, `PyGObject_marshal_variant`, and `PyGObject_unmarshal_variant` to convert between Python objects and their corresponding C representations (like strings, dictionaries, and `GVariant`).

8. **Type Checking:** The code performs type checking, for example, in `PySession_parse_peer_options` to ensure that the `relays` argument is a sequence of `Relay` objects.

**Relating to the User's Requests:**

* **Functionality:** I'll list the different types of Frida objects wrapped and the key operations available on each.
* **Reverse Engineering:** Frida is a reverse engineering tool. The ability to create and load scripts (`PySession_create_script`, `PyScript_load`) allows users to inject code into running processes for analysis and modification. For example, a user could write a script to hook functions and log their arguments.
* **Binary/Kernel/Framework:**  While this C code doesn't directly interact with the Linux kernel or Android framework, the underlying Frida library does. The `Child` object provides information about processes, which are kernel-level entities. The ability to attach to processes and inject scripts touches upon operating system and process management concepts.
* **Logical Reasoning:** The parsing of options for script creation and snapshotting (`PySession_parse_script_options`, `PySession_parse_snapshot_options`) involves logical checks and conditional setting of parameters.
* **User Errors:**  Incorrect arguments to functions (e.g., passing a string where an integer is expected) will lead to `PyArg_ParseTupleAndKeywords` failing and returning `NULL`, which the Python interpreter will translate into a `TypeError`. Providing invalid data for marshaling (e.g., a Python object that can't be converted to a `GVariant`) will also cause errors.
* **User Journey:** A user would typically start by importing the `frida` Python module. They might then use functions like `frida.attach()` or `frida.spawn()` to connect to a process. From a `Session` object, they would then call methods like `create_script()` to inject code.
* **归纳功能 (Summarize Functionality):** The core function is to provide Python bindings for interacting with Frida's core functionalities, enabling dynamic instrumentation from Python scripts.

**Plan for the Response:**

I will structure the response by listing the functionalities of the `extension.c` file, categorizing them based on the types of Frida objects they handle. I will then address each of the user's specific points (reverse engineering, binary/kernel knowledge, logical reasoning, user errors, and user journey) with relevant examples from the code. Finally, I'll provide a concise summary of the file's overall purpose.
这是 `frida/subprojects/frida-python/frida/_frida/extension.c` 文件的第四部分，主要定义了 Frida 动态插桩工具在 Python 端的扩展功能，涵盖了多个核心概念的 Python 绑定，包括 `Session`, `Script`, `Relay`, `PortalMembership`, `PortalService`, 和 `EndpointParameters`。

**归纳一下它的功能:**

这部分代码的主要功能是：**将 Frida C 核心库中的关键对象和功能暴露给 Python，使得 Python 开发者能够方便地使用 Frida 进行动态插桩操作。** 具体来说，它定义了与会话管理、脚本操作、网络连接中继、以及基于 Portal 的服务相关的 Python 类和方法。

**以下列举一下它的功能，并根据要求进行说明:**

**1. `PySession` (会话管理)**

* **功能:**  提供了与 Frida 会话交互的 Python 接口，例如创建脚本、分离会话、启用/禁用子进程门控、编译脚本、创建脚本快照、建立点对点连接、加入 Portal 服务等。
* **与逆向方法的关系:**
    * **创建脚本 (`PySession_create_script`, `PySession_create_script_from_bytes`):** 这是 Frida 进行动态插桩的核心步骤。逆向工程师可以通过编写 JavaScript 脚本注入到目标进程中，监控函数调用、修改内存数据、Hook 系统 API 等。
        * **举例说明:**  逆向工程师可以使用 `session.create_script('console.log("Hello from Frida!");')` 将简单的日志打印脚本注入到目标进程，验证 Frida 是否成功连接。更复杂的脚本可以用于监控特定函数的参数和返回值。
    * **分离会话 (`PySession_detach`):**  允许在不终止目标进程的情况下断开 Frida 的连接，方便在分析完成后释放资源。
    * **启用/禁用子进程门控 (`PySession_enable_child_gating`, `PySession_disable_child_gating`):**  控制 Frida 是否需要干预新创建的子进程。这在分析父子进程交互时非常重要。
* **涉及到二进制底层，Linux, Android 内核及框架的知识:**
    * **进程 ID (`self->pid`):**  `PySession` 对象存储了会话关联的进程 ID，这是操作系统级别的概念。
    * **脚本运行时 (`runtime` 参数):**  Frida 允许选择不同的脚本运行时（例如 v8 或 QuickJS），这涉及到 JavaScript 引擎的底层实现。
    * **快照 (`snapshot` 参数):**  创建脚本快照涉及到将脚本的编译状态保存下来，以便后续快速加载，这与二进制代码的加载和执行优化相关。
    * **点对点连接 (`PySession_setup_peer_connection`):**  涉及到网络编程和 NAT 穿透等技术，可能使用到 STUN 服务器和 Relay 服务器，这些是网络协议和基础设施的概念。
* **做了逻辑推理:**
    * **`PySession_parse_script_options` 和 `PySession_parse_snapshot_options`:** 这些函数根据传入的参数（例如脚本名称、快照数据、运行时环境）进行逻辑判断，设置 `FridaScriptOptions` 和 `FridaSnapshotOptions` 结构体，为后续的脚本创建和快照操作做准备。
        * **假设输入:** `name="my_script"`, `runtime="v8"`
        * **输出:**  一个 `FridaScriptOptions` 对象，其中 `name` 属性被设置为 "my_script"，`runtime` 属性被设置为 `FRIDA_SCRIPT_RUNTIME_V8`。
* **涉及用户或者编程常见的使用错误:**
    * **类型错误:**  例如，在调用 `PySession_create_script` 时，如果 `source` 参数不是字符串类型，`PyArg_ParseTupleAndKeywords` 会返回错误。
    * **无效的运行时环境:** 如果 `runtime` 参数传入了 Frida 不支持的值，`PyGObject_unmarshal_enum` 会返回错误。
* **说明用户操作是如何一步步的到达这里，作为调试线索:**
    1. 用户在 Python 脚本中导入 `frida` 模块。
    2. 用户使用 `frida.attach()` 或 `frida.spawn()` 函数连接到一个目标进程，这将创建一个 `Session` 对象。
    3. 用户调用 `session.create_script(source='...')` 或其他 `PySession_` 开头的方法来执行会话相关的操作。
    4. Python 解释器会调用 `PySession_create_script` 等 C 函数，这些函数会调用 Frida C 核心库的相应功能。

**2. `PyScript` (脚本操作)**

* **功能:** 提供了与 Frida 脚本交互的 Python 接口，例如加载脚本、卸载脚本、持久化脚本、向脚本发送消息、启用/禁用调试器等。
* **与逆向方法的关系:**
    * **加载脚本 (`PyScript_load`):** 将编写好的 JavaScript 脚本注入到目标进程中开始执行，这是动态插桩的关键步骤。
    * **卸载脚本 (`PyScript_unload`):**  停止脚本在目标进程中的执行，用于清理环境或动态调整插桩逻辑。
    * **持久化脚本 (`PyScript_eternalize`):**  使脚本在会话断开后仍然在目标进程中运行，用于需要长期监控的场景。
    * **发送消息 (`PyScript_post`):**  允许 Python 代码向注入到目标进程的 JavaScript 脚本发送消息，实现双向通信，协同完成逆向分析任务。
* **涉及到二进制底层，Linux, Android 内核及框架的知识:**
    * **脚本的加载和卸载:**  涉及到进程的内存管理和代码注入/卸载机制，这些是操作系统底层的概念。
    * **启用/禁用调试器 (`PyScript_enable_debugger`, `PyScript_disable_debugger`):**  涉及到进程的调试接口和协议，例如 gdb 的远程调试协议。
* **做了逻辑推理:**
    *  代码中关于 `PyScript` 的逻辑主要集中在调用 Frida C 核心库的相应函数，进行错误处理和 Python 对象的管理。
* **涉及用户或者编程常见的使用错误:**
    * **脚本加载失败:**  如果提供的 JavaScript 代码有语法错误或逻辑错误，Frida C 核心库可能会返回错误，`PyScript_load` 会抛出异常。
    * **向未加载的脚本发送消息:** 如果在调用 `script.post()` 之前没有调用 `script.load()`，可能会导致错误。

**3. `PyRelay` (网络连接中继)**

* **功能:**  定义了网络连接中继的 Python 表示，用于在 Frida 的点对点连接中充当中间节点，解决 NAT 穿透等问题.
* **与逆向方法的关系:** 在需要跨越网络边界进行 Frida 连接时使用，例如远程调试 Android 设备。
* **涉及到二进制底层，Linux, Android 内核及框架的知识:**  涉及到网络编程、TCP/IP 协议、NAT 穿透技术（例如 STUN, TURN）。
* **做了逻辑推理:**  `PyRelay_init` 函数根据传入的地址、用户名、密码和类型来创建 `FridaRelay` 对象。
    * **假设输入:** `address="relay.example.com:3478"`, `username="user"`, `password="pass"`, `kind="TURN"`
    * **输出:**  一个 `PyRelay` 对象，其内部的 `FridaRelay` 结构体包含了这些信息。
* **涉及用户或者编程常见的使用错误:**
    * **提供错误的 Relay 服务器信息:**  如果地址、用户名或密码不正确，会导致连接失败。
    * **指定错误的 Relay 类型:**  需要根据实际的 Relay 服务器类型选择合适的 `kind`。

**4. `PyPortalMembership` (Portal 服务成员关系)**

* **功能:**  表示一个会话加入到 Frida Portal 服务的成员关系，提供了终止成员关系的功能。
* **与逆向方法的关系:**  Frida Portal 允许在多个客户端之间共享插桩会话，方便团队协作进行逆向分析。
* **涉及到二进制底层，Linux, Android 内核及框架的知识:**  涉及到网络通信、身份验证、访问控制等概念。
* **做了逻辑推理:**  `PyPortalMembership_terminate` 函数调用 Frida C 核心库的相应函数来终止 Portal 成员关系。

**5. `PyPortalService` (Portal 服务)**

* **功能:**  定义了 Frida Portal 服务的 Python 接口，允许创建和管理 Portal 服务，并进行消息的广播、窄播、标记等操作。
* **与逆向方法的关系:**  为多用户协同的动态插桩提供基础设施，例如多人同时在一个目标进程上进行分析。
* **涉及到二进制底层，Linux, Android 内核及框架的知识:**  涉及到更复杂的网络通信、服务发现、消息路由、身份验证和授权机制。
* **做了逻辑推理:**  `PyPortalService_init` 函数根据传入的集群参数和控制参数来创建 `FridaPortalService` 对象。其他函数则根据传入的参数进行消息的发送和标记操作。
* **涉及用户或者编程常见的使用错误:**
    * **配置错误的集群或控制参数:**  可能导致 Portal 服务启动失败或无法正常工作。
    * **向不存在的连接 ID 发送消息:**  会导致消息发送失败。

**6. `PyEndpointParameters` (端点参数)**

* **功能:**  定义了网络端点的参数，例如地址、端口、证书、身份验证令牌等，用于配置 Frida 的网络服务。
* **与逆向方法的关系:**  用于配置 Frida 服务器的监听地址和安全设置，以便远程连接到 Frida 服务。
* **涉及到二进制底层，Linux, Android 内核及框架的知识:**  涉及到网络编程、TLS/SSL 证书、身份验证和授权机制。
* **做了逻辑推理:**  `PyEndpointParameters_init` 函数根据传入的参数创建 `FridaEndpointParameters` 对象。
    * **假设输入:** `address="0.0.0.0"`, `port=27042`, `certificate="cert.pem"`
    * **输出:**  一个 `PyEndpointParameters` 对象，包含了这些网络配置信息。
* **涉及用户或者编程常见的使用错误:**
    * **提供无效的证书路径或格式:**  会导致 TLS 连接失败。
    * **端口被占用:**  会导致服务启动失败。

**作为调试线索，用户操作是如何一步步的到达这里:**

总体来说，用户使用 Frida Python 接口进行动态插桩的流程通常是：

1. **导入 `frida` 模块。**
2. **连接到目标进程:** 使用 `frida.attach(pid)` 或 `frida.spawn(program)` 等函数创建一个 `Session` 对象。
3. **创建脚本:** 调用 `session.create_script(source='...')` 或 `session.create_script_from_bytes(data=...)` 创建一个 `Script` 对象。
4. **加载脚本:** 调用 `script.load()` 将脚本注入到目标进程。
5. **与脚本交互:**  使用 `script.post(message)` 向脚本发送消息，或监听脚本发出的消息。
6. **根据需要执行其他操作:** 例如分离会话 (`session.detach()`)、卸载脚本 (`script.unload()`)、加入 Portal 服务 (`session.join_portal()`) 等。

每一步操作都会调用到 `extension.c` 中定义的相应 Python C 扩展函数，这些函数负责调用 Frida C 核心库的功能，并将结果返回给 Python。

总而言之，这部分代码是 Frida Python 绑定的核心组成部分，它将 Frida C 核心库的强大功能以 Pythonic 的方式暴露出来，使得 Python 开发者能够方便地进行动态插桩、逆向工程和安全分析等任务。

### 提示词
```
这是目录为frida/subprojects/frida-python/frida/_frida/extension.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
repr, "pid=%u, parent_pid=%u", self->pid, self->parent_pid);

  origin = frida_child_get_origin (handle);
  origin_class = g_type_class_ref (FRIDA_TYPE_CHILD_ORIGIN);
  origin_value = g_enum_get_value (origin_class, origin);
  g_string_append_printf (repr, ", origin=%s", origin_value->value_nick);
  g_type_class_unref (origin_class);

  if (self->identifier != Py_None)
  {
    gchar * identifier;

    identifier = PyFrida_repr (self->identifier);

    g_string_append_printf (repr, ", identifier=%s", identifier);

    g_free (identifier);
  }

  if (origin != FRIDA_CHILD_ORIGIN_FORK)
  {
    gchar * path, * argv, * envp;

    path = PyFrida_repr (self->path);
    argv = PyFrida_repr (self->argv);
    envp = PyFrida_repr (self->envp);

    g_string_append_printf (repr, ", path=%s, argv=%s, envp=%s", path, argv, envp);

    g_free (envp);
    g_free (argv);
    g_free (path);
  }

  g_string_append (repr, ")");

  result = PyUnicode_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}


static int
PyCrash_init (PyCrash * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->process_name = NULL;
  self->summary = NULL;
  self->report = NULL;
  self->parameters = NULL;

  return 0;
}

static void
PyCrash_init_from_handle (PyCrash * self, FridaCrash * handle)
{
  self->pid = frida_crash_get_pid (handle);
  self->process_name = PyGObject_marshal_string (frida_crash_get_process_name (handle));
  self->summary = PyGObject_marshal_string (frida_crash_get_summary (handle));
  self->report = PyGObject_marshal_string (frida_crash_get_report (handle));
  self->parameters = PyGObject_marshal_parameters_dict (frida_crash_get_parameters (handle));
}

static void
PyCrash_dealloc (PyCrash * self)
{
  Py_DecRef (self->parameters);
  Py_DecRef (self->report);
  Py_DecRef (self->summary);
  Py_DecRef (self->process_name);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyCrash_repr (PyCrash * self)
{
  PyObject * result;
  FridaCrash * handle;
  GString * repr;
  gchar * str;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Crash(");

  g_string_append_printf (repr, "pid=%u, process_name=\"%s\", summary=\"%s\", report=<%u bytes>",
      self->pid,
      frida_crash_get_process_name (handle),
      frida_crash_get_summary (handle),
      (guint) strlen (frida_crash_get_report (handle)));

  str = PyFrida_repr (self->parameters);
  g_string_append_printf (repr, ", parameters=%s", str);
  g_free (str);

  g_string_append (repr, ")");

  result = PyUnicode_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}


static PyObject *
PyBus_new_take_handle (FridaBus * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Bus));
}

static PyObject *
PyBus_attach (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_bus_attach_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyBus_post (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "message", "data", NULL };
  char * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|z#", keywords, "utf-8", &message, &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_bus_post (PY_GOBJECT_HANDLE (self), message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  PyFrida_RETURN_NONE;
}


static PyObject *
PyService_new_take_handle (FridaService * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Service));
}

static PyObject *
PyService_activate (PyService * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_service_activate_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyService_cancel (PyService * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_service_cancel_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyService_request (PyService * self, PyObject * args)
{
  PyObject * result, * params;
  GVariant * raw_params, * raw_result;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "O", &params))
    return NULL;

  if (!PyGObject_unmarshal_variant (params, &raw_params))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  raw_result = frida_service_request_sync (PY_GOBJECT_HANDLE (self), raw_params, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_variant_unref (raw_params);

  if (error != NULL)
    return PyFrida_raise (error);

  result = PyGObject_marshal_variant (raw_result);
  g_variant_unref (raw_result);

  return result;
}


static PyObject *
PySession_new_take_handle (FridaSession * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Session));
}

static int
PySession_init (PySession * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;

  return 0;
}

static void
PySession_init_from_handle (PySession * self, FridaSession * handle)
{
  self->pid = frida_session_get_pid (handle);
}

static PyObject *
PySession_repr (PySession * self)
{
  return PyUnicode_FromFormat ("Session(pid=%u)", self->pid);
}

static PyObject *
PySession_is_detached (PySession * self)
{
  gboolean is_detached;

  Py_BEGIN_ALLOW_THREADS
  is_detached = frida_session_is_detached (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  return PyBool_FromLong (is_detached);
}

static PyObject *
PySession_detach (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_detach_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PySession_resume (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_resume_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PySession_enable_child_gating (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_enable_child_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PySession_disable_child_gating (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_disable_child_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PySession_create_script (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "source", "name", "snapshot", "runtime", NULL };
  char * source;
  char * name = NULL;
  gconstpointer snapshot_data = NULL;
  Py_ssize_t snapshot_size = 0;
  const char * runtime_value = NULL;
  FridaScriptOptions * options;
  GError * error = NULL;
  FridaScript * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esy#z", keywords, "utf-8", &source, "utf-8", &name, &snapshot_data, &snapshot_size, &runtime_value))
    return NULL;

  options = PySession_parse_script_options (name, snapshot_data, snapshot_size, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_create_script_sync (PY_GOBJECT_HANDLE (self), source, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyScript_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (name);
  PyMem_Free (source);

  return result;
}

static PyObject *
PySession_create_script_from_bytes (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "data", "name", "snapshot", "runtime", NULL };
  guint8 * data;
  Py_ssize_t size;
  char * name = NULL;
  gconstpointer snapshot_data = NULL;
  Py_ssize_t snapshot_size = 0;
  const char * runtime_value = NULL;
  GBytes * bytes;
  FridaScriptOptions * options;
  GError * error = NULL;
  FridaScript * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "y#|esy#z", keywords, &data, &size, "utf-8", &name, &snapshot_data, &snapshot_size, &runtime_value))
    return NULL;

  bytes = g_bytes_new (data, size);

  options = PySession_parse_script_options (name, snapshot_data, snapshot_size, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_create_script_from_bytes_sync (PY_GOBJECT_HANDLE (self), bytes, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyScript_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);
  g_bytes_unref (bytes);

  PyMem_Free (name);

  return result;
}

static PyObject *
PySession_compile_script (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "source", "name", "runtime", NULL };
  char * source;
  char * name = NULL;
  const char * runtime_value = NULL;
  FridaScriptOptions * options;
  GError * error = NULL;
  GBytes * bytes;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esz", keywords, "utf-8", &source, "utf-8", &name, &runtime_value))
    return NULL;

  options = PySession_parse_script_options (name, NULL, 0, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  bytes = frida_session_compile_script_sync (PY_GOBJECT_HANDLE (self), source, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    result = PyGObject_marshal_bytes_non_nullable (bytes);

    g_bytes_unref (bytes);
  }
  else
  {
    result = PyFrida_raise (error);
  }

beach:
  g_clear_object (&options);

  PyMem_Free (name);
  PyMem_Free (source);

  return result;
}

static FridaScriptOptions *
PySession_parse_script_options (const gchar * name, gconstpointer snapshot_data, gsize snapshot_size, const gchar * runtime_value)
{
  FridaScriptOptions * options;

  options = frida_script_options_new ();

  if (name != NULL)
    frida_script_options_set_name (options, name);

  if (snapshot_data != NULL)
  {
    GBytes * snapshot = g_bytes_new (snapshot_data, snapshot_size);
    frida_script_options_set_snapshot (options, snapshot);
    g_bytes_unref (snapshot);
  }

  if (runtime_value != NULL)
  {
    FridaScriptRuntime runtime;

    if (!PyGObject_unmarshal_enum (runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME, &runtime))
      goto invalid_argument;

    frida_script_options_set_runtime (options, runtime);
  }

  return options;

invalid_argument:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PySession_snapshot_script (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "embed_script", "warmup_script", "runtime", NULL };
  char * embed_script;
  char * warmup_script = NULL;
  const char * runtime_value = NULL;
  FridaSnapshotOptions * options;
  GError * error = NULL;
  GBytes * bytes;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esz", keywords, "utf-8", &embed_script, "utf-8", &warmup_script, &runtime_value))
    return NULL;

  options = PySession_parse_snapshot_options (warmup_script, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  bytes = frida_session_snapshot_script_sync (PY_GOBJECT_HANDLE (self), embed_script, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    result = PyGObject_marshal_bytes_non_nullable (bytes);

    g_bytes_unref (bytes);
  }
  else
  {
    result = PyFrida_raise (error);
  }

beach:
  g_clear_object (&options);

  PyMem_Free (warmup_script);
  PyMem_Free (embed_script);

  return result;
}

static FridaSnapshotOptions *
PySession_parse_snapshot_options (const gchar * warmup_script, const gchar * runtime_value)
{
  FridaSnapshotOptions * options;

  options = frida_snapshot_options_new ();

  if (warmup_script != NULL)
    frida_snapshot_options_set_warmup_script (options, warmup_script);

  if (runtime_value != NULL)
  {
    FridaScriptRuntime runtime;

    if (!PyGObject_unmarshal_enum (runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME, &runtime))
      goto invalid_argument;

    frida_snapshot_options_set_runtime (options, runtime);
  }

  return options;

invalid_argument:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PySession_setup_peer_connection (PySession * self, PyObject * args, PyObject * kw)
{
  gboolean success = FALSE;
  static char * keywords[] = { "stun_server", "relays", NULL };
  char * stun_server = NULL;
  PyObject * relays = NULL;
  FridaPeerOptions * options = NULL;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|esO", keywords,
        "utf-8", &stun_server,
        &relays))
    return NULL;

  options = PySession_parse_peer_options (stun_server, relays);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  frida_session_setup_peer_connection_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error != NULL)
    goto propagate_error;

  success = TRUE;
  goto beach;

propagate_error:
  {
    PyFrida_raise (error);
    goto beach;
  }
beach:
  {
    g_clear_object (&options);

    PyMem_Free (stun_server);

    if (!success)
      return NULL;

    PyFrida_RETURN_NONE;
  }
}

static FridaPeerOptions *
PySession_parse_peer_options (const gchar * stun_server, PyObject * relays)
{
  FridaPeerOptions * options;
  PyObject * relay;

  options = frida_peer_options_new ();

  frida_peer_options_set_stun_server (options, stun_server);

  if (relays != NULL)
  {
    Py_ssize_t n, i;

    n = PySequence_Length (relays);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      relay = PySequence_GetItem (relays, i);
      if (relay == NULL)
        goto propagate_error;

      if (!PyObject_IsInstance (relay, PYFRIDA_TYPE_OBJECT (Relay)))
        goto expected_relay;

      frida_peer_options_add_relay (options, PY_GOBJECT_HANDLE (relay));

      Py_DecRef (relay);
    }
  }

  return options;

expected_relay:
  {
    Py_DecRef (relay);

    PyErr_SetString (PyExc_TypeError, "expected sequence of Relay objects");
    goto propagate_error;
  }
propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PySession_join_portal (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "address", "certificate", "token", "acl", NULL };
  char * address;
  char * certificate = NULL;
  char * token = NULL;
  PyObject * acl = NULL;
  FridaPortalOptions * options;
  GError * error = NULL;
  FridaPortalMembership * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esesO", keywords,
        "utf-8", &address,
        "utf-8", &certificate,
        "utf-8", &token,
        &acl))
    return NULL;

  options = PySession_parse_portal_options (certificate, token, acl);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_join_portal_sync (PY_GOBJECT_HANDLE (self), address, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyPortalMembership_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (token);
  PyMem_Free (certificate);
  PyMem_Free (address);

  return result;
}

static FridaPortalOptions *
PySession_parse_portal_options (const gchar * certificate_value, const gchar * token, PyObject * acl_value)
{
  FridaPortalOptions * options;

  options = frida_portal_options_new ();

  if (certificate_value != NULL)
  {
    GTlsCertificate * certificate;

    if (!PyGObject_unmarshal_certificate (certificate_value, &certificate))
      goto propagate_error;

    frida_portal_options_set_certificate (options, certificate);

    g_object_unref (certificate);
  }

  if (token != NULL)
    frida_portal_options_set_token (options, token);

  if (acl_value != NULL)
  {
    gchar ** acl;
    gint acl_length;

    if (!PyGObject_unmarshal_strv (acl_value, &acl, &acl_length))
      goto propagate_error;

    frida_portal_options_set_acl (options, acl, acl_length);

    g_strfreev (acl);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}


static PyObject *
PyScript_new_take_handle (FridaScript * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Script));
}

static PyObject *
PyScript_is_destroyed (PyScript * self)
{
  gboolean is_destroyed;

  Py_BEGIN_ALLOW_THREADS
  is_destroyed = frida_script_is_destroyed (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  return PyBool_FromLong (is_destroyed);
}

static PyObject *
PyScript_load (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_load_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyScript_unload (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_unload_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyScript_eternalize (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_eternalize_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyScript_post (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "message", "data", NULL };
  char * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|z#", keywords, "utf-8", &message, &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_post (PY_GOBJECT_HANDLE (self), message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyScript_enable_debugger (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "port", NULL };
  unsigned short int port = 0;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|H", keywords, &port))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_enable_debugger_sync (PY_GOBJECT_HANDLE (self), port, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyScript_disable_debugger (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_disable_debugger_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}


static int
PyRelay_init (PyRelay * self, PyObject * args, PyObject * kw)
{
  int result = -1;
  static char * keywords[] = { "address", "username", "password", "kind", NULL };
  char * address = NULL;
  char * username = NULL;
  char * password = NULL;
  char * kind_value = NULL;
  FridaRelayKind kind;
  FridaRelay * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "eseseses", keywords,
        "utf-8", &address,
        "utf-8", &username,
        "utf-8", &password,
        "utf-8", &kind_value))
    return -1;

  if (!PyGObject_unmarshal_enum (kind_value, FRIDA_TYPE_RELAY_KIND, &kind))
    goto beach;

  handle = frida_relay_new (address, username, password, kind);

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (Relay));

  PyRelay_init_from_handle (self, handle);

  result = 0;

beach:
  PyMem_Free (kind_value);
  PyMem_Free (password);
  PyMem_Free (username);
  PyMem_Free (address);

  return result;
}

static void
PyRelay_init_from_handle (PyRelay * self, FridaRelay * handle)
{
  self->address = PyUnicode_FromString (frida_relay_get_address (handle));
  self->username = PyUnicode_FromString (frida_relay_get_username (handle));
  self->password = PyUnicode_FromString (frida_relay_get_password (handle));
  self->kind = PyGObject_marshal_enum (frida_relay_get_kind (handle), FRIDA_TYPE_RELAY_KIND);
}

static void
PyRelay_dealloc (PyRelay * self)
{
  Py_DecRef (self->kind);
  Py_DecRef (self->password);
  Py_DecRef (self->username);
  Py_DecRef (self->address);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyRelay_repr (PyRelay * self)
{
  PyObject * result, * address_bytes, * username_bytes, * password_bytes, * kind_bytes;

  address_bytes = PyUnicode_AsUTF8String (self->address);
  username_bytes = PyUnicode_AsUTF8String (self->username);
  password_bytes = PyUnicode_AsUTF8String (self->password);
  kind_bytes = PyUnicode_AsUTF8String (self->kind);

  result = PyUnicode_FromFormat ("Relay(address=\"%s\", username=\"%s\", password=\"%s\", kind='%s')",
      PyBytes_AsString (address_bytes),
      PyBytes_AsString (username_bytes),
      PyBytes_AsString (password_bytes),
      PyBytes_AsString (kind_bytes));

  Py_DecRef (kind_bytes);
  Py_DecRef (password_bytes);
  Py_DecRef (username_bytes);
  Py_DecRef (address_bytes);

  return result;
}


static PyObject *
PyPortalMembership_new_take_handle (FridaPortalMembership * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (PortalMembership));
}

static PyObject *
PyPortalMembership_terminate (PyPortalMembership * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_membership_terminate_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}


static int
PyPortalService_init (PyPortalService * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "cluster_params", "control_params", NULL };
  PyEndpointParameters * cluster_params;
  PyEndpointParameters * control_params = NULL;
  FridaPortalService * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "O!|O!", keywords,
        PYFRIDA_TYPE_OBJECT (EndpointParameters), &cluster_params,
        PYFRIDA_TYPE_OBJECT (EndpointParameters), &control_params))
    return -1;

  g_atomic_int_inc (&toplevel_objects_alive);

  handle = frida_portal_service_new (PY_GOBJECT_HANDLE (cluster_params),
      (control_params != NULL) ? PY_GOBJECT_HANDLE (control_params) : NULL);

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (PortalService));

  PyPortalService_init_from_handle (self, handle);

  return 0;
}

static void
PyPortalService_init_from_handle (PyPortalService * self, FridaPortalService * handle)
{
  self->device = PyDevice_new_take_handle (g_object_ref (frida_portal_service_get_device (handle)));
}

static void
PyPortalService_dealloc (PyPortalService * self)
{
  FridaPortalService * handle;

  g_atomic_int_dec_and_test (&toplevel_objects_alive);

  handle = PyGObject_steal_handle (&self->parent);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    frida_portal_service_stop_sync (handle, NULL, NULL);
    frida_unref (handle);
    Py_END_ALLOW_THREADS
  }

  Py_DecRef (self->device);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyPortalService_start (PyPortalService * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_start_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyPortalService_stop (PyPortalService * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_stop_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyPortalService_kick (PyScript * self, PyObject * args)
{
  unsigned int connection_id;

  if (!PyArg_ParseTuple (args, "I", &connection_id))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_kick (PY_GOBJECT_HANDLE (self), connection_id);
  Py_END_ALLOW_THREADS

  PyFrida_RETURN_NONE;
}

static PyObject *
PyPortalService_post (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "connection_id", "message", "data", NULL };
  unsigned int connection_id;
  char * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "Ies|z#", keywords,
        &connection_id,
        "utf-8", &message,
        &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_post (PY_GOBJECT_HANDLE (self), connection_id, message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyPortalService_narrowcast (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "tag", "message", "data", NULL };
  char * tag, * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "eses|z#", keywords,
        "utf-8", &tag,
        "utf-8", &message,
        &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_narrowcast (PY_GOBJECT_HANDLE (self), tag, message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);
  PyMem_Free (tag);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyPortalService_broadcast (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "message", "data", NULL };
  char * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|z#", keywords,
        "utf-8", &message,
        &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_broadcast (PY_GOBJECT_HANDLE (self), message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyPortalService_enumerate_tags (PyScript * self, PyObject * args)
{
  PyObject * result;
  unsigned int connection_id;
  gchar ** tags;
  gint tags_length;

  if (!PyArg_ParseTuple (args, "I", &connection_id))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  tags = frida_portal_service_enumerate_tags (PY_GOBJECT_HANDLE (self), connection_id, &tags_length);
  Py_END_ALLOW_THREADS

  result = PyGObject_marshal_strv (tags, tags_length);
  g_strfreev (tags);

  return result;
}

static PyObject *
PyPortalService_tag (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "connection_id", "tag", NULL };
  unsigned int connection_id;
  char * tag;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "Ies", keywords,
        &connection_id,
        "utf-8", &tag))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_tag (PY_GOBJECT_HANDLE (self), connection_id, tag);
  Py_END_ALLOW_THREADS

  PyMem_Free (tag);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyPortalService_untag (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "connection_id", "tag", NULL };
  unsigned int connection_id;
  char * tag;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "Ies", keywords,
        &connection_id,
        "utf-8", &tag))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_untag (PY_GOBJECT_HANDLE (self), connection_id, tag);
  Py_END_ALLOW_THREADS

  PyMem_Free (tag);

  PyFrida_RETURN_NONE;
}


static int
PyEndpointParameters_init (PyEndpointParameters * self, PyObject * args, PyObject * kw)
{
  int result = -1;
  static char * keywords[] = { "address", "port", "certificate", "origin", "auth_token", "auth_callback", "asset_root", NULL };
  char * address = NULL;
  unsigned short int port = 0;
  char * certificate_value = NULL;
  char * origin = NULL;
  char * auth_token = NULL;
  PyObject * auth_callback = NULL;
  char * asset_root_value = NULL;
  GTlsCertificate * certificate = NULL;
  FridaAuthenticationService * auth_service = NULL;
  GFile * asset_root = NULL;
  FridaEndpointParameters * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|esHesesesOes", keywords,
        "utf-8", &address,
        &port,
        "utf-8", &certificate_value,
        "utf-8", &origin,
        "utf-8", &auth_token,
        &auth_callback,
        "utf-8", &asset_root_value))
    return -1;

  if (certificate_value != NULL && !PyGObject_unmarshal_certificate (certificate_value, &certificate))
    goto beach;

  if (auth_token != NULL)
    auth_service = FRIDA_AUTHENTICATION_SERVICE (frida_static_authentication_service_new (auth_token));
  else if (auth_callback != NULL)
    auth_service = FRIDA_AUTHENTICATION_SERVICE (frida_python_authentication_service_new (auth_callback));

  if (asset_root_value != NULL)
    asset_root = g_file_new_for_path (asset_root_value);

  handle = frida_endpoint_parameters_new (address, port, certificate, origin, auth_service, asset_root);

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (EndpointParameters));

  result = 0;

beach:
  g_clear_object (&asset_root);
  g_clear_object (&auth_service);
  g_clear_object (&certificate);

  PyMem_Free (asset_root_value);
  PyMem_Free (auth_token);
  PyMem_Free (origin);
  PyMem_Free (certificate_value);
  PyMem_Free (address);

  return result;
}


G_DEFINE_TYPE_EXTENDED (FridaPythonAuthenticationService, frida_python_authentication_service, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE (FRIDA_TYPE_AUTHENTICATION_SERVICE, frida_python_authentication_service_iface_init))

static FridaPythonAuthenticationService *
frida_python_authentication_service_new (PyObject * callback)
{
  FridaPythonAuthenticationService * service;

  service = g_object_new (FRIDA_TYPE_PYTHON_AUTHENTICATION_SERVICE, NULL);
  service->callback = callback;
  Py_IncRef (callback);

  return service;
}

static void
frida_python_authentication_service_class_init (FridaPythonAuthenticationServiceClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = frida_python_authentication_service_dispose;
}

static void
frida_python_authentication_service_iface_init (gpointer g_iface, gpointer iface_data)
{
  FridaAuthenticationServiceIface * iface = g_iface;

  iface->authenticate = frida_python_authentication_service_authenticate;
  iface->authenticate_finish = frida_python_authentication_service_authenticate_finish;
}

static void
frida_python_authentication_service_init (FridaPythonAuthenticationService * self)
{
  self->pool = g_thread_pool_new ((GFunc) frida_python_authentication_service_do_authenticate, self, 1, FALSE, NULL);
}

static void
frida_python_authentication_service_dispose (GObject * object)
{
  FridaPythonAuthenticationService * self = FRIDA_PYTHON_AUTHENTICATION_SERVICE (object);

  if (self->pool != NULL)
  {
    g_thread_pool_free (self->pool, FALSE, FALSE);
    self->pool = NULL;
  }

  if (self->callback != NULL)
  {
    PyGILState_STATE gstate;
```