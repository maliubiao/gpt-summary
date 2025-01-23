Response:
The user wants a functional overview of the provided C code, which is a part of the Frida dynamic instrumentation tool, specifically the Python binding.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The file name `extension.c` within the `frida-python` project strongly suggests this code is the bridge between the core Frida library (written in C/C++) and the Python API. It's about exposing Frida's functionality to Python.

2. **Scan for Key Structures and Definitions:** Look for prominent data structures and function definitions. The `#define PYFRIDA_...` macros are crucial. They define how Frida's C types are mapped to Python types. The `struct _Py...` definitions describe the Python object representations of Frida's core concepts.

3. **Categorize Functionality by Structure:**  Group the functions and members based on the Python objects they operate on. For instance, functions starting with `PyDeviceManager_` are related to managing devices, `PyDevice_` to individual devices, `PySession_` to sessions, and so on.

4. **Infer Functionality from Names:**  Even without knowing the specifics of Frida, the function names are often descriptive. `enumerate_devices`, `attach`, `spawn`, `create_script`, `load`, `unload`, `post`, `on`, `off` are strong indicators of what the code does.

5. **Look for Interactions with External Systems:**  The presence of terms like "remote device," "USB device," "network address," and functions like `add_remote_device` and `open_channel` suggests interaction beyond the local process.

6. **Identify Core Frida Concepts:**  The defined structures (Device, Application, Process, Session, Script, etc.) represent the fundamental entities that Frida manipulates. Understanding these is key to understanding the functionality.

7. **Connect to Reverse Engineering Concepts:** Frida is a reverse engineering tool. The ability to attach to processes, inject code (scripts, libraries), intercept function calls (implied by signal handling with "on" and "off"), and manipulate process behavior (spawn, resume, kill) directly relates to common reverse engineering tasks.

8. **Relate to System-Level Knowledge:** Frida interacts with the operating system kernel and frameworks. The ability to enumerate processes, spawn new processes, inject libraries, and intercept system calls requires understanding OS internals. The mention of Linux and Android kernels reinforces this.

9. **Consider User Interaction and Errors:** Think about how a user would interact with these Python APIs. They would call methods on the Python objects, potentially with incorrect arguments or at inappropriate times (e.g., calling methods on a detached session).

10. **Focus on the Requested Elements:** The prompt specifically asks for functionality, connections to reverse engineering, OS knowledge, logical reasoning (hypothetical input/output), user errors, and the user's path to this code. Ensure these aspects are covered.

11. **Structure the Response:** Organize the information logically, starting with a high-level summary, then detailing the functionalities, and finally addressing the specific points about reverse engineering, OS knowledge, etc.

12. **Refine and Clarify:** Ensure the language is clear and concise. Use examples where appropriate to illustrate points. For the hypothetical input/output, choose a simple function and demonstrate its behavior.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the C code details. **Correction:** Shift focus to the *purpose* of the C code within the context of Frida and its Python bindings.
* **Initial thought:** List every single function. **Correction:** Group related functions by the object they belong to for better readability and understanding of the overall functionality.
* **Initial thought:** Assume deep technical knowledge from the reader. **Correction:** Explain concepts in a way that is understandable to someone familiar with programming and basic reverse engineering concepts, even if they haven't used Frida before.
* **Initial thought:**  Miss the "how a user gets here" part. **Correction:** Realize this relates to the import process in Python and the structure of the Frida Python package.

By following this structured approach and incorporating self-correction, it's possible to generate a comprehensive and accurate overview of the provided C code snippet within its intended context.
This is the first part of the `extension.c` file, which serves as the core C extension module for Frida's Python bindings. Its primary function is to **bridge the gap between Frida's core C API and the Python world**, allowing Python developers to interact with and control Frida's dynamic instrumentation capabilities.

Here's a breakdown of its functionalities based on the provided code:

**Core Functionality:**

1. **Defines Python Types for Frida Objects:** It defines Python representations (using `PyType_Spec`) for various core Frida objects like `DeviceManager`, `Device`, `Application`, `Process`, `Session`, `Script`, and many more. This involves defining the structure of these Python objects (`struct _Py...`), their methods (functions callable on these objects in Python), and their members (attributes accessible in Python).

2. **Manages Object Lifecycles:** It handles the creation, initialization (`init_func`), and destruction (`destroy_func`, `dealloc`) of these Python-wrapped Frida objects. This ensures proper memory management and resource cleanup.

3. **Implements Signal Handling:**  It provides mechanisms (`PyGObject_on`, `PyGObject_off`) to connect Frida signals (events emitted by Frida's core) to Python callbacks. This allows Python code to react to events happening within the target process or Frida itself.

4. **Marshals Data Between C and Python:** It handles the conversion of data types between C and Python. This includes converting basic types (integers, strings), but also more complex types like GObjects, GVariants, and custom Frida structures. Functions like `PyGObject_marshal_...` convert C data to Python objects, and (implicitly through argument parsing in method implementations) Python objects back to C data.

5. **Exposes Frida Functionality as Python Methods:** Each Python type defined has associated methods that wrap the corresponding Frida C API functions. For example, `PyDevice_spawn` wraps the Frida C function to spawn a new process.

6. **Handles Errors:** It includes functionality (`PyFrida_raise`) to translate Frida's GError mechanism into Python exceptions, making error handling more Pythonic.

7. **Supports Asynchronous Operations:** While not explicitly shown in this first part, the presence of `GCancellable` and asynchronous callbacks in later parts of the code hints at support for non-blocking operations.

**Relationship to Reverse Engineering:**

This file is fundamental to using Frida for reverse engineering because it provides the Python interface to Frida's core capabilities. Here are some examples:

* **Enumerating Processes:** The `PyDevice_enumerate_processes` function (and related C API) allows a reverse engineer to get a list of running processes on a target device. In Python, this would be used to find the process to attach to.
    ```python
    import frida

    device = frida.get_usb_device() # Assuming a USB connected device
    processes = device.enumerate_processes()
    for process in processes:
        print(f"PID: {process.pid}, Name: {process.name}")
    ```
* **Attaching to a Process:** The `PyDevice_attach` function enables attaching Frida to a running process, which is a core step in dynamic analysis.
    ```python
    import frida

    session = frida.attach("target_process_name_or_pid")
    ```
* **Spawning and Instrumenting:** The `PyDevice_spawn` function allows launching a new process under Frida's control, enabling instrumentation from the very beginning.
    ```python
    import frida

    pid = frida.spawn(["/path/to/executable"])
    session = frida.attach(pid)
    # ... load a script to instrument the spawned process ...
    device.resume(pid)
    ```
* **Injecting Scripts:** The `PySession_create_script` function is crucial for loading JavaScript code into the target process, which is where the actual instrumentation logic resides.
    ```python
    import frida

    session = frida.attach("target_process")
    script = session.create_script("""
        console.log("Hello from Frida!");
    """)
    script.load()
    ```
* **Receiving Messages from Scripts:** The signal handling mechanism (`PyGObject_on`) is used to receive messages sent from the injected JavaScript code back to the Python script.
    ```python
    import frida

    def on_message(message, data):
        print(f"Message from script: {message}")

    session = frida.attach("target_process")
    script = session.create_script("""
        send("This is a message from the script");
    """)
    script.on('message', on_message)
    script.load()
    ```

**Binary Underlying, Linux, Android Kernel and Framework Knowledge:**

This code interacts heavily with these concepts:

* **Binary Underlying:**  Frida fundamentally works at the binary level, manipulating process memory, intercepting function calls, and injecting code. This C extension is the interface through which Python code can orchestrate these binary-level manipulations.
* **Linux and Android Kernel:** Frida is commonly used on Linux and Android. The ability to enumerate processes, attach to them, and inject code requires deep interaction with the operating system kernel. Frida's core library (linked with this extension) uses system calls and kernel-level mechanisms to achieve this.
* **Framework Knowledge:**  On Android, Frida can interact with the Android runtime (ART) and framework. While this specific file doesn't show framework-specific code, the higher-level Python API exposed through this extension is used to interact with Android framework components. For example, you can use Frida to hook into Java methods within Android applications.

**Logical Reasoning, Assumptions, Inputs and Outputs:**

* **Assumption:** The code assumes that the underlying Frida core library (`frida-core.h`) is correctly implemented and provides the necessary functionalities.
* **Assumption:** The Python interpreter is running and the necessary Python headers are available.
* **Hypothetical Input and Output (for `PyDevice_enumerate_processes`):**
    * **Input:** A `PyDevice` object representing a connected device.
    * **Output:** A Python list of `PyProcess` objects. Each `PyProcess` object would have attributes like `pid` (integer) and `name` (string).

**User or Programming Common Usage Errors:**

* **Calling methods on detached sessions:**  Users might try to call methods like `script.load()` on a session that has been detached, leading to errors.
* **Passing incorrect argument types:** For example, providing a string where an integer (PID) is expected for `device.attach()`.
* **Trying to attach to non-existent processes:** Providing an invalid PID to `device.attach()`.
* **Not handling exceptions:**  Frida operations can fail, and users need to wrap their calls in `try...except` blocks to handle potential exceptions like `frida.ProcessNotFoundError` or connection errors.
* **Incorrectly using signal handlers:** Forgetting to `load()` a script before expecting messages, or providing a callback function with the wrong signature.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User installs the `frida` Python package:**  `pip install frida`. This downloads and installs the pre-compiled binary extension (`_frida.cpython-*.so` or similar).
2. **User imports the `frida` module in their Python script:** `import frida`. This triggers the Python interpreter to load the `_frida` extension module.
3. **When the module is loaded, the `PyInit__frida` function (not shown in this snippet, but standard for Python C extensions) is called.** This function initializes the module and registers the types defined in `extension.c`.
4. **The user then interacts with Frida objects:**
   * `device_manager = frida.get_device_manager()`  would likely instantiate a `PyDeviceManager` object.
   * `device = device_manager.get_device('local')` would call a method on the `PyDeviceManager` object, potentially leading to the creation of a `PyDevice` object.
   * `session = device.attach('com.example.app')` would call the `PyDevice_attach` method, which in turn calls the underlying Frida C API.

**Summary of Functionality (Part 1):**

This first part of `extension.c` lays the groundwork for the Frida Python bindings by:

* **Defining the fundamental structure of how Frida objects are represented in Python.**
* **Providing mechanisms for managing the lifecycle of these Python objects.**
* **Enabling communication between Frida's core and Python through signal handling.**
* **Implementing data type conversion between the two languages.**
* **Exposing core Frida functionalities as methods on Python objects.**
* **Setting up basic error handling.**

In essence, it's the foundational layer that allows Python developers to programmatically interact with the powerful dynamic instrumentation capabilities of Frida.

### 提示词
```
这是目录为frida/subprojects/frida-python/frida/_frida/extension.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2013-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <frida-core.h>
#include <string.h>

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4115)
# pragma warning (disable: 4211)
#endif
#ifdef _POSIX_C_SOURCE
# undef _POSIX_C_SOURCE
#endif

#define PY_SSIZE_T_CLEAN

/*
 * Don't propagate _DEBUG state to pyconfig as it incorrectly attempts to load
 * debug libraries that don't normally ship with Python (e.g. 2.x). Debuggers
 * wishing to spelunk the Python core can override this workaround by defining
 * _FRIDA_ENABLE_PYDEBUG.
 */
#if defined (_DEBUG) && !defined (_FRIDA_ENABLE_PYDEBUG)
# undef _DEBUG
# include <pyconfig.h>
# define _DEBUG
#else
# include <pyconfig.h>
#endif

#include <Python.h>
#include <structmember.h>
#include <string.h>
#ifdef _MSC_VER
# pragma warning (pop)
#endif
#ifdef __APPLE__
# include <TargetConditionals.h>
# if TARGET_OS_OSX
#  include <crt_externs.h>
# endif
#endif

#define PYFRIDA_TYPE(name) \
  (&_PYFRIDA_TYPE_VAR (name, type))
#define PYFRIDA_TYPE_OBJECT(name) \
  PYFRIDA_TYPE (name)->object
#define _PYFRIDA_TYPE_VAR(name, var) \
  G_PASTE (G_PASTE (G_PASTE (Py, name), _), var)
#define PYFRIDA_DEFINE_BASETYPE(pyname, cname, init_func, destroy_func, ...) \
  _PYFRIDA_DEFINE_TYPE_SLOTS (cname, __VA_ARGS__); \
  _PYFRIDA_DEFINE_TYPE_SPEC (cname, pyname, Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE); \
  static PyGObjectType _PYFRIDA_TYPE_VAR (cname, type) = \
  { \
    .parent = NULL, \
    .object = NULL, \
    .init_from_handle = (PyGObjectInitFromHandleFunc) init_func, \
    .destroy = destroy_func, \
  }
#define PYFRIDA_DEFINE_TYPE(pyname, cname, parent_cname, init_func, destroy_func, ...) \
  _PYFRIDA_DEFINE_TYPE_SLOTS (cname, __VA_ARGS__); \
  _PYFRIDA_DEFINE_TYPE_SPEC (cname, pyname, Py_TPFLAGS_DEFAULT); \
  static PyGObjectType _PYFRIDA_TYPE_VAR (cname, type) = \
  { \
    .parent = PYFRIDA_TYPE (parent_cname), \
    .object = NULL, \
    .init_from_handle = (PyGObjectInitFromHandleFunc) init_func, \
    .destroy = destroy_func, \
  }
#define PYFRIDA_REGISTER_TYPE(cname, gtype) \
  G_BEGIN_DECLS \
  { \
    PyGObjectType * t = PYFRIDA_TYPE (cname); \
    t->object = PyType_FromSpecWithBases (&_PYFRIDA_TYPE_VAR (cname, spec), \
        (t->parent != NULL) ? PyTuple_Pack (1, t->parent->object) : NULL); \
    PyGObject_register_type (gtype, t); \
    Py_IncRef (t->object); \
    PyModule_AddObject (module, G_STRINGIFY (cname), t->object); \
  } \
  G_END_DECLS
#define _PYFRIDA_DEFINE_TYPE_SPEC(cname, pyname, type_flags) \
  static PyType_Spec _PYFRIDA_TYPE_VAR (cname, spec) = \
  { \
    .name = pyname, \
    .basicsize = sizeof (G_PASTE (Py, cname)), \
    .itemsize = 0, \
    .flags = type_flags, \
    .slots = _PYFRIDA_TYPE_VAR (cname, slots), \
  }
#define _PYFRIDA_DEFINE_TYPE_SLOTS(cname, ...) \
  static PyType_Slot _PYFRIDA_TYPE_VAR (cname, slots)[] = \
  { \
    __VA_ARGS__ \
    { 0 }, \
  }

#define PY_GOBJECT(o) ((PyGObject *) (o))
#define PY_GOBJECT_HANDLE(o) (PY_GOBJECT (o)->handle)
#define PY_GOBJECT_SIGNAL_CLOSURE(o) ((PyGObjectSignalClosure *) (o))

#define PyFrida_RETURN_NONE \
  G_STMT_START \
  { \
    Py_IncRef (Py_None); \
    return Py_None; \
  } \
  G_STMT_END

static struct PyModuleDef PyFrida_moduledef = { PyModuleDef_HEAD_INIT, "_frida", "Frida", -1, NULL, };

static volatile gint toplevel_objects_alive = 0;

static PyObject * inspect_getargspec;
static PyObject * inspect_ismethod;

static PyObject * datetime_constructor;

static initproc PyGObject_tp_init;
static destructor PyGObject_tp_dealloc;
static GHashTable * pygobject_type_spec_by_type;
static GHashTable * frida_exception_by_error_code;
static PyObject * cancelled_exception;

typedef struct _PyGObject                      PyGObject;
typedef struct _PyGObjectType                  PyGObjectType;
typedef struct _PyGObjectSignalClosure         PyGObjectSignalClosure;
typedef struct _PyDeviceManager                PyDeviceManager;
typedef struct _PyDevice                       PyDevice;
typedef struct _PyApplication                  PyApplication;
typedef struct _PyProcess                      PyProcess;
typedef struct _PySpawn                        PySpawn;
typedef struct _PyChild                        PyChild;
typedef struct _PyCrash                        PyCrash;
typedef struct _PyBus                          PyBus;
typedef struct _PyService                      PyService;
typedef struct _PySession                      PySession;
typedef struct _PyScript                       PyScript;
typedef struct _PyRelay                        PyRelay;
typedef struct _PyPortalMembership             PyPortalMembership;
typedef struct _PyPortalService                PyPortalService;
typedef struct _PyEndpointParameters           PyEndpointParameters;
typedef struct _PyCompiler                     PyCompiler;
typedef struct _PyFileMonitor                  PyFileMonitor;
typedef struct _PyIOStream                     PyIOStream;
typedef struct _PyCancellable                  PyCancellable;

#define FRIDA_TYPE_PYTHON_AUTHENTICATION_SERVICE (frida_python_authentication_service_get_type ())
G_DECLARE_FINAL_TYPE (FridaPythonAuthenticationService, frida_python_authentication_service, FRIDA, PYTHON_AUTHENTICATION_SERVICE, GObject)

typedef void (* PyGObjectInitFromHandleFunc) (PyObject * self, gpointer handle);

struct _PyGObject
{
  PyObject_HEAD

  gpointer handle;
  const PyGObjectType * type;

  GSList * signal_closures;
};

struct _PyGObjectType
{
  PyGObjectType * parent;
  PyObject * object;
  PyGObjectInitFromHandleFunc init_from_handle;
  GDestroyNotify destroy;
};

struct _PyGObjectSignalClosure
{
  GClosure parent;
  guint signal_id;
  guint max_arg_count;
};

struct _PyDeviceManager
{
  PyGObject parent;
};

struct _PyDevice
{
  PyGObject parent;
  PyObject * id;
  PyObject * name;
  PyObject * icon;
  PyObject * type;
  PyObject * bus;
};

struct _PyApplication
{
  PyGObject parent;
  PyObject * identifier;
  PyObject * name;
  guint pid;
  PyObject * parameters;
};

struct _PyProcess
{
  PyGObject parent;
  guint pid;
  PyObject * name;
  PyObject * parameters;
};

struct _PySpawn
{
  PyGObject parent;
  guint pid;
  PyObject * identifier;
};

struct _PyChild
{
  PyGObject parent;
  guint pid;
  guint parent_pid;
  PyObject * origin;
  PyObject * identifier;
  PyObject * path;
  PyObject * argv;
  PyObject * envp;
};

struct _PyCrash
{
  PyGObject parent;
  guint pid;
  PyObject * process_name;
  PyObject * summary;
  PyObject * report;
  PyObject * parameters;
};

struct _PyBus
{
  PyGObject parent;
};

struct _PyService
{
  PyGObject parent;
};

struct _PySession
{
  PyGObject parent;
  guint pid;
};

struct _PyScript
{
  PyGObject parent;
};

struct _PyRelay
{
  PyGObject parent;
  PyObject * address;
  PyObject * username;
  PyObject * password;
  PyObject * kind;
};

struct _PyPortalMembership
{
  PyGObject parent;
};

struct _PyPortalService
{
  PyGObject parent;
  PyObject * device;
};

struct _PyEndpointParameters
{
  PyGObject parent;
};

struct _FridaPythonAuthenticationService
{
  GObject parent;
  PyObject * callback;
  GThreadPool * pool;
};

struct _PyCompiler
{
  PyGObject parent;
};

struct _PyFileMonitor
{
  PyGObject parent;
};

struct _PyIOStream
{
  PyGObject parent;
  GInputStream * input;
  GOutputStream * output;
};

struct _PyCancellable
{
  PyGObject parent;
};

static PyObject * PyGObject_new_take_handle (gpointer handle, const PyGObjectType * type);
static PyObject * PyGObject_try_get_from_handle (gpointer handle);
static int PyGObject_init (PyGObject * self);
static void PyGObject_dealloc (PyGObject * self);
static void PyGObject_take_handle (PyGObject * self, gpointer handle, const PyGObjectType * type);
static gpointer PyGObject_steal_handle (PyGObject * self);
static PyObject * PyGObject_on (PyGObject * self, PyObject * args);
static PyObject * PyGObject_off (PyGObject * self, PyObject * args);
static gint PyGObject_compare_signal_closure_callback (PyGObjectSignalClosure * closure, PyObject * callback);
static gboolean PyGObject_parse_signal_method_args (PyObject * args, GType instance_type, guint * signal_id, PyObject ** callback);
static const gchar * PyGObject_class_name_from_c (const gchar * cname);
static GClosure * PyGObject_make_closure_for_signal (guint signal_id, PyObject * callback, guint max_arg_count);
static void PyGObjectSignalClosure_finalize (PyObject * callback);
static void PyGObjectSignalClosure_marshal (GClosure * closure, GValue * return_gvalue, guint n_param_values, const GValue * param_values,
    gpointer invocation_hint, gpointer marshal_data);
static PyObject * PyGObjectSignalClosure_marshal_params (const GValue * params, guint params_length);
static PyObject * PyGObject_marshal_value (const GValue * value);
static PyObject * PyGObject_marshal_string (const gchar * str);
static gboolean PyGObject_unmarshal_string (PyObject * value, gchar ** str);
static PyObject * PyGObject_marshal_datetime (const gchar * iso8601_text);
static PyObject * PyGObject_marshal_strv (gchar * const * strv, gint length);
static gboolean PyGObject_unmarshal_strv (PyObject * value, gchar *** strv, gint * length);
static PyObject * PyGObject_marshal_envp (gchar * const * envp, gint length);
static gboolean PyGObject_unmarshal_envp (PyObject * value, gchar *** envp, gint * length);
static PyObject * PyGObject_marshal_enum (gint value, GType type);
static gboolean PyGObject_unmarshal_enum (const gchar * str, GType type, gpointer value);
static PyObject * PyGObject_marshal_bytes (GBytes * bytes);
static PyObject * PyGObject_marshal_bytes_non_nullable (GBytes * bytes);
static PyObject * PyGObject_marshal_variant (GVariant * variant);
static PyObject * PyGObject_marshal_variant_byte_array (GVariant * variant);
static PyObject * PyGObject_marshal_variant_dict (GVariant * variant);
static PyObject * PyGObject_marshal_variant_array (GVariant * variant);
static gboolean PyGObject_unmarshal_variant (PyObject * value, GVariant ** variant);
static gboolean PyGObject_unmarshal_variant_from_mapping (PyObject * mapping, GVariant ** variant);
static gboolean PyGObject_unmarshal_variant_from_sequence (PyObject * sequence, GVariant ** variant);
static PyObject * PyGObject_marshal_parameters_dict (GHashTable * dict);
static PyObject * PyGObject_marshal_socket_address (GSocketAddress * address);
static gboolean PyGObject_unmarshal_certificate (const gchar * str, GTlsCertificate ** certificate);
static PyObject * PyGObject_marshal_object (gpointer handle, GType type);

static int PyDeviceManager_init (PyDeviceManager * self, PyObject * args, PyObject * kwds);
static void PyDeviceManager_dealloc (PyDeviceManager * self);
static PyObject * PyDeviceManager_close (PyDeviceManager * self);
static PyObject * PyDeviceManager_get_device_matching (PyDeviceManager * self, PyObject * args);
static gboolean PyDeviceManager_is_matching_device (FridaDevice * device, PyObject * predicate);
static PyObject * PyDeviceManager_enumerate_devices (PyDeviceManager * self);
static PyObject * PyDeviceManager_add_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw);
static PyObject * PyDeviceManager_remove_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw);
static FridaRemoteDeviceOptions * PyDeviceManager_parse_remote_device_options (const gchar * certificate_value, const gchar * origin,
    const gchar * token, gint keepalive_interval);

static PyObject * PyDevice_new_take_handle (FridaDevice * handle);
static int PyDevice_init (PyDevice * self, PyObject * args, PyObject * kw);
static void PyDevice_init_from_handle (PyDevice * self, FridaDevice * handle);
static void PyDevice_dealloc (PyDevice * self);
static PyObject * PyDevice_repr (PyDevice * self);
static PyObject * PyDevice_is_lost (PyDevice * self);
static PyObject * PyDevice_query_system_parameters (PyDevice * self);
static PyObject * PyDevice_get_frontmost_application (PyDevice * self, PyObject * args, PyObject * kw);
static PyObject * PyDevice_enumerate_applications (PyDevice * self, PyObject * args, PyObject * kw);
static FridaApplicationQueryOptions * PyDevice_parse_application_query_options (PyObject * identifiers_value, const gchar * scope_value);
static PyObject * PyDevice_enumerate_processes (PyDevice * self, PyObject * args, PyObject * kw);
static FridaProcessQueryOptions * PyDevice_parse_process_query_options (PyObject * pids_value, const gchar * scope_value);
static PyObject * PyDevice_enable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_disable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_enumerate_pending_spawn (PyDevice * self);
static PyObject * PyDevice_enumerate_pending_children (PyDevice * self);
static PyObject * PyDevice_spawn (PyDevice * self, PyObject * args, PyObject * kw);
static PyObject * PyDevice_input (PyDevice * self, PyObject * args);
static PyObject * PyDevice_resume (PyDevice * self, PyObject * args);
static PyObject * PyDevice_kill (PyDevice * self, PyObject * args);
static PyObject * PyDevice_attach (PyDevice * self, PyObject * args, PyObject * kw);
static FridaSessionOptions * PyDevice_parse_session_options (const gchar * realm_value, guint persist_timeout);
static PyObject * PyDevice_inject_library_file (PyDevice * self, PyObject * args);
static PyObject * PyDevice_inject_library_blob (PyDevice * self, PyObject * args);
static PyObject * PyDevice_open_channel (PyDevice * self, PyObject * args);
static PyObject * PyDevice_open_service (PyDevice * self, PyObject * args);
static PyObject * PyDevice_unpair (PyDevice * self);

static PyObject * PyApplication_new_take_handle (FridaApplication * handle);
static int PyApplication_init (PyApplication * self, PyObject * args, PyObject * kw);
static void PyApplication_init_from_handle (PyApplication * self, FridaApplication * handle);
static void PyApplication_dealloc (PyApplication * self);
static PyObject * PyApplication_repr (PyApplication * self);
static PyObject * PyApplication_marshal_parameters_dict (GHashTable * dict);

static PyObject * PyProcess_new_take_handle (FridaProcess * handle);
static int PyProcess_init (PyProcess * self, PyObject * args, PyObject * kw);
static void PyProcess_init_from_handle (PyProcess * self, FridaProcess * handle);
static void PyProcess_dealloc (PyProcess * self);
static PyObject * PyProcess_repr (PyProcess * self);
static PyObject * PyProcess_marshal_parameters_dict (GHashTable * dict);

static PyObject * PySpawn_new_take_handle (FridaSpawn * handle);
static int PySpawn_init (PySpawn * self, PyObject * args, PyObject * kw);
static void PySpawn_init_from_handle (PySpawn * self, FridaSpawn * handle);
static void PySpawn_dealloc (PySpawn * self);
static PyObject * PySpawn_repr (PySpawn * self);

static PyObject * PyChild_new_take_handle (FridaChild * handle);
static int PyChild_init (PyChild * self, PyObject * args, PyObject * kw);
static void PyChild_init_from_handle (PyChild * self, FridaChild * handle);
static void PyChild_dealloc (PyChild * self);
static PyObject * PyChild_repr (PyChild * self);

static int PyCrash_init (PyCrash * self, PyObject * args, PyObject * kw);
static void PyCrash_init_from_handle (PyCrash * self, FridaCrash * handle);
static void PyCrash_dealloc (PyCrash * self);
static PyObject * PyCrash_repr (PyCrash * self);

static PyObject * PyBus_new_take_handle (FridaBus * handle);
static PyObject * PyBus_attach (PySession * self);
static PyObject * PyBus_post (PyScript * self, PyObject * args, PyObject * kw);

static PyObject * PyService_new_take_handle (FridaService * handle);
static PyObject * PyService_activate (PyService * self);
static PyObject * PyService_cancel (PyService * self);
static PyObject * PyService_request (PyService * self, PyObject * args);

static PyObject * PySession_new_take_handle (FridaSession * handle);
static int PySession_init (PySession * self, PyObject * args, PyObject * kw);
static void PySession_init_from_handle (PySession * self, FridaSession * handle);
static PyObject * PySession_repr (PySession * self);
static PyObject * PySession_is_detached (PySession * self);
static PyObject * PySession_detach (PySession * self);
static PyObject * PySession_resume (PySession * self);
static PyObject * PySession_enable_child_gating (PySession * self);
static PyObject * PySession_disable_child_gating (PySession * self);
static PyObject * PySession_create_script (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_create_script_from_bytes (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_compile_script (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_snapshot_script (PySession * self, PyObject * args, PyObject * kw);
static FridaScriptOptions * PySession_parse_script_options (const gchar * name, gconstpointer snapshot_data, gsize snapshot_size,
    const gchar * runtime_value);
static PyObject * PySession_snapshot_script (PySession * self, PyObject * args, PyObject * kw);
static FridaSnapshotOptions * PySession_parse_snapshot_options (const gchar * warmup_script, const gchar * runtime_value);
static PyObject * PySession_setup_peer_connection (PySession * self, PyObject * args, PyObject * kw);
static FridaPeerOptions * PySession_parse_peer_options (const gchar * stun_server, PyObject * relays);
static PyObject * PySession_join_portal (PySession * self, PyObject * args, PyObject * kw);
static FridaPortalOptions * PySession_parse_portal_options (const gchar * certificate_value, const gchar * token, PyObject * acl_value);

static PyObject * PyScript_new_take_handle (FridaScript * handle);
static PyObject * PyScript_is_destroyed (PyScript * self);
static PyObject * PyScript_load (PyScript * self);
static PyObject * PyScript_unload (PyScript * self);
static PyObject * PyScript_eternalize (PyScript * self);
static PyObject * PyScript_post (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyScript_enable_debugger (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyScript_disable_debugger (PyScript * self);

static int PyRelay_init (PyRelay * self, PyObject * args, PyObject * kw);
static void PyRelay_init_from_handle (PyRelay * self, FridaRelay * handle);
static void PyRelay_dealloc (PyRelay * self);
static PyObject * PyRelay_repr (PyRelay * self);

static PyObject * PyPortalMembership_new_take_handle (FridaPortalMembership * handle);
static PyObject * PyPortalMembership_terminate (PyPortalMembership * self);

static int PyPortalService_init (PyPortalService * self, PyObject * args, PyObject * kw);
static void PyPortalService_init_from_handle (PyPortalService * self, FridaPortalService * handle);
static void PyPortalService_dealloc (PyPortalService * self);
static PyObject * PyPortalService_start (PyPortalService * self);
static PyObject * PyPortalService_stop (PyPortalService * self);
static PyObject * PyPortalService_kick (PyScript * self, PyObject * args);
static PyObject * PyPortalService_post (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_narrowcast (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_broadcast (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_enumerate_tags (PyScript * self, PyObject * args);
static PyObject * PyPortalService_tag (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_untag (PyScript * self, PyObject * args, PyObject * kw);

static int PyEndpointParameters_init (PyEndpointParameters * self, PyObject * args, PyObject * kw);

static FridaPythonAuthenticationService * frida_python_authentication_service_new (PyObject * callback);
static void frida_python_authentication_service_iface_init (gpointer g_iface, gpointer iface_data);
static void frida_python_authentication_service_dispose (GObject * object);
static void frida_python_authentication_service_authenticate (FridaAuthenticationService * service, const gchar * token,
    GCancellable * cancellable, GAsyncReadyCallback callback, gpointer user_data);
static gchar * frida_python_authentication_service_authenticate_finish (FridaAuthenticationService * service, GAsyncResult * result,
    GError ** error);
static void frida_python_authentication_service_do_authenticate (GTask * task, FridaPythonAuthenticationService * self);

static int PyCompiler_init (PyCompiler * self, PyObject * args, PyObject * kw);
static PyObject * PyCompiler_build (PyCompiler * self, PyObject * args, PyObject * kw);
static PyObject * PyCompiler_watch (PyCompiler * self, PyObject * args, PyObject * kw);
static gboolean PyCompiler_set_options (FridaCompilerOptions * options, const gchar * project_root_value, const gchar * source_maps_value,
    const gchar * compression_value);

static int PyFileMonitor_init (PyFileMonitor * self, PyObject * args, PyObject * kw);
static PyObject * PyFileMonitor_enable (PyFileMonitor * self);
static PyObject * PyFileMonitor_disable (PyFileMonitor * self);

static PyObject * PyIOStream_new_take_handle (GIOStream * handle);
static int PyIOStream_init (PyIOStream * self, PyObject * args, PyObject * kw);
static void PyIOStream_init_from_handle (PyIOStream * self, GIOStream * handle);
static PyObject * PyIOStream_repr (PyIOStream * self);
static PyObject * PyIOStream_is_closed (PyIOStream * self);
static PyObject * PyIOStream_close (PyIOStream * self);
static PyObject * PyIOStream_read (PyIOStream * self, PyObject * args);
static PyObject * PyIOStream_read_all (PyIOStream * self, PyObject * args);
static PyObject * PyIOStream_write (PyIOStream * self, PyObject * args);
static PyObject * PyIOStream_write_all (PyIOStream * self, PyObject * args);

static int PyCancellable_init (PyCancellable * self, PyObject * args, PyObject * kw);
static PyObject * PyCancellable_repr (PyCancellable * self);
static PyObject * PyCancellable_is_cancelled (PyCancellable * self);
static PyObject * PyCancellable_raise_if_cancelled (PyCancellable * self);
static PyObject * PyCancellable_get_fd (PyCancellable * self);
static PyObject * PyCancellable_release_fd (PyCancellable * self);
static PyObject * PyCancellable_get_current (PyCancellable * self);
static PyObject * PyCancellable_push_current (PyCancellable * self);
static PyObject * PyCancellable_pop_current (PyCancellable * self);
static PyObject * PyCancellable_connect (PyCancellable * self, PyObject * args);
static PyObject * PyCancellable_disconnect (PyCancellable * self, PyObject * args);
static void PyCancellable_on_cancelled (GCancellable * cancellable, PyObject * callback);
static void PyCancellable_destroy_callback (PyObject * callback);
static PyObject * PyCancellable_cancel (PyCancellable * self);

static PyObject * PyFrida_raise (GError * error);
static gchar * PyFrida_repr (PyObject * obj);
static guint PyFrida_get_max_argument_count (PyObject * callable);

static PyMethodDef PyGObject_methods[] =
{
  { "on", (PyCFunction) PyGObject_on, METH_VARARGS, "Add a signal handler." },
  { "off", (PyCFunction) PyGObject_off, METH_VARARGS, "Remove a signal handler." },
  { NULL }
};

static PyMethodDef PyDeviceManager_methods[] =
{
  { "close", (PyCFunction) PyDeviceManager_close, METH_NOARGS, "Close the device manager." },
  { "get_device_matching", (PyCFunction) PyDeviceManager_get_device_matching, METH_VARARGS, "Get device matching predicate." },
  { "enumerate_devices", (PyCFunction) PyDeviceManager_enumerate_devices, METH_NOARGS, "Enumerate devices." },
  { "add_remote_device", (PyCFunction) PyDeviceManager_add_remote_device, METH_VARARGS | METH_KEYWORDS, "Add a remote device." },
  { "remove_remote_device", (PyCFunction) PyDeviceManager_remove_remote_device, METH_VARARGS | METH_KEYWORDS, "Remove a remote device." },
  { NULL }
};

static PyMethodDef PyDevice_methods[] =
{
  { "is_lost", (PyCFunction) PyDevice_is_lost, METH_NOARGS, "Query whether the device has been lost." },
  { "query_system_parameters", (PyCFunction) PyDevice_query_system_parameters, METH_NOARGS, "Returns a dictionary of information about the host system." },
  { "get_frontmost_application", (PyCFunction) PyDevice_get_frontmost_application, METH_VARARGS | METH_KEYWORDS, "Get details about the frontmost application." },
  { "enumerate_applications", (PyCFunction) PyDevice_enumerate_applications, METH_VARARGS | METH_KEYWORDS, "Enumerate applications." },
  { "enumerate_processes", (PyCFunction) PyDevice_enumerate_processes, METH_VARARGS | METH_KEYWORDS, "Enumerate processes." },
  { "enable_spawn_gating", (PyCFunction) PyDevice_enable_spawn_gating, METH_NOARGS, "Enable spawn gating." },
  { "disable_spawn_gating", (PyCFunction) PyDevice_disable_spawn_gating, METH_NOARGS, "Disable spawn gating." },
  { "enumerate_pending_spawn", (PyCFunction) PyDevice_enumerate_pending_spawn, METH_NOARGS, "Enumerate pending spawn." },
  { "enumerate_pending_children", (PyCFunction) PyDevice_enumerate_pending_children, METH_NOARGS, "Enumerate pending children." },
  { "spawn", (PyCFunction) PyDevice_spawn, METH_VARARGS | METH_KEYWORDS, "Spawn a process into an attachable state." },
  { "input", (PyCFunction) PyDevice_input, METH_VARARGS, "Input data on stdin of a spawned process." },
  { "resume", (PyCFunction) PyDevice_resume, METH_VARARGS, "Resume a process from the attachable state." },
  { "kill", (PyCFunction) PyDevice_kill, METH_VARARGS, "Kill a PID." },
  { "attach", (PyCFunction) PyDevice_attach, METH_VARARGS | METH_KEYWORDS, "Attach to a PID." },
  { "inject_library_file", (PyCFunction) PyDevice_inject_library_file, METH_VARARGS, "Inject a library file to a PID." },
  { "inject_library_blob", (PyCFunction) PyDevice_inject_library_blob, METH_VARARGS, "Inject a library blob to a PID." },
  { "open_channel", (PyCFunction) PyDevice_open_channel, METH_VARARGS, "Open a device-specific communication channel." },
  { "open_service", (PyCFunction) PyDevice_open_service, METH_VARARGS, "Open a device-specific service." },
  { "unpair", (PyCFunction) PyDevice_unpair, METH_NOARGS, "Unpair device." },
  { NULL }
};

static PyMemberDef PyDevice_members[] =
{
  { "id", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, id), READONLY, "Device ID." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, name), READONLY, "Human-readable device name." },
  { "icon", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, icon), READONLY, "Icon." },
  { "type", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, type), READONLY, "Device type. One of: local, remote, usb." },
  { "bus", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, bus), READONLY, "Message bus." },
  { NULL }
};

static PyMemberDef PyApplication_members[] =
{
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, identifier), READONLY, "Application identifier." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, name), READONLY, "Human-readable application name." },
  { "pid", T_UINT, G_STRUCT_OFFSET (PyApplication, pid), READONLY, "Process ID, or 0 if not running." },
  { "parameters", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, parameters), READONLY, "Parameters." },
  { NULL }
};

static PyMemberDef PyProcess_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PyProcess, pid), READONLY, "Process ID." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyProcess, name), READONLY, "Human-readable process name." },
  { "parameters", T_OBJECT_EX, G_STRUCT_OFFSET (PyProcess, parameters), READONLY, "Parameters." },
  { NULL }
};

static PyMemberDef PySpawn_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PySpawn, pid), READONLY, "Process ID." },
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PySpawn, identifier), READONLY, "Application identifier." },
  { NULL }
};

static PyMemberDef PyChild_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PyChild, pid), READONLY, "Process ID." },
  { "parent_pid", T_UINT, G_STRUCT_OFFSET (PyChild, parent_pid), READONLY, "Parent Process ID." },
  { "origin", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, origin), READONLY, "Origin." },
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, identifier), READONLY, "Application identifier." },
  { "path", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, path), READONLY, "Path of executable." },
  { "argv", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, argv), READONLY, "Argument vector." },
  { "envp", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, envp), READONLY, "Environment vector." },
  { NULL }
};

static PyMemberDef PyCrash_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PyCrash, pid), READONLY, "Process ID." },
  { "process_name", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, process_name), READONLY, "Process name." },
  { "summary", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, summary), READONLY, "Human-readable crash summary." },
  { "report", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, report), READONLY, "Human-readable crash report." },
  { "parameters", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, parameters), READONLY, "Parameters." },
  { NULL }
};

static PyMethodDef PyBus_methods[] =
{
  { "attach", (PyCFunction) PyBus_attach, METH_NOARGS, "Attach to the bus." },
  { "post", (PyCFunction) PyBus_post, METH_VARARGS | METH_KEYWORDS, "Post a JSON-encoded message to the bus." },
  { NULL }
};

static PyMethodDef PyService_methods[] =
{
  { "activate", (PyCFunction) PyService_activate, METH_NOARGS, "Activate the service." },
  { "cancel", (PyCFunction) PyService_cancel, METH_NOARGS, "Cancel the service." },
  { "request", (PyCFunction) PyService_request, METH_VARARGS, "Perform a request." },
  { NULL }
};

static PyMethodDef PySession_methods[] =
{
  { "is_detached", (PyCFunction) PySession_is_detached, METH_NOARGS, "Query whether the session is detached." },
  { "detach", (PyCFunction) PySession_detach, METH_NOARGS, "Detach session from the process." },
  { "resume", (PyCFunction) PySession_resume, METH_NOARGS, "Resume session after network error." },
  { "enable_child_gating", (PyCFunction) PySession_enable_child_gating, METH_NOARGS, "Enable child gating." },
  { "disable_child_gating", (PyCFunction) PySession_disable_child_gating, METH_NOARGS, "Disable child gating." },
  { "create_script", (PyCFunction) PySession_create_script, METH_VARARGS | METH_KEYWORDS, "Create a new script." },
  { "create_script_from_bytes", (PyCFunction) PySession_create_script_from_bytes, METH_VARARGS | METH_KEYWORDS, "Create a new script from bytecode." },
  { "compile_script", (PyCFunction) PySession_compile_script, METH_VARARGS | METH_KEYWORDS, "Compile script source code to bytecode." },
  { "snapshot_script", (PyCFunction) PySession_snapshot_script, METH_VARARGS | METH_KEYWORDS, "Evaluate script and snapshot the resulting VM state." },
  { "setup_peer_connection", (PyCFunction) PySession_setup_peer_connection, METH_VARARGS | METH_KEYWORDS, "Set up a peer connection with the target process." },
  { "join_portal", (PyCFunction) PySession_join_portal, METH_VARARGS | METH_KEYWORDS, "Join a portal." },
  { NULL }
};

static PyMemberDef PySession_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PySession, pid), READONLY, "Process ID." },
  { NULL }
};

static PyMethodDef PyScript_methods[] =
{
  { "is_destroyed", (PyCFunction) PyScript_is_destroyed, METH_NOARGS, "Query whether the script has been destroyed." },
  { "load", (PyCFunction) PyScript_load, METH_NOARGS, "Load the script." },
  { "unload", (PyCFunction) PyScript_unload, METH_NOARGS, "Unload the script." },
  { "eternalize", (PyCFunction) PyScript_eternalize, METH_NOARGS, "Eternalize the script." },
  { "post", (PyCFunction) PyScript_post, METH_VARARGS | METH_KEYWORDS, "Post a JSON-encoded message to the script." },
  { "enable_debugger", (PyCFunction) PyScript_enable_debugger, METH_VARARGS | METH_KEYWORDS, "Enable the Node.js compatible script debugger." },
  { "disable_debugger", (PyCFunction) PyScript_disable_debugger, METH_NOARGS, "Disable the Node.js compatible script debugger." },
  { NULL }
};

static PyMemberDef PyRelay_members[] =
{
  { "address", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, address), READONLY, "Network address or address:port of the TURN server." },
  { "username", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, username), READONLY, "The TURN username to use for the allocate request." },
  { "password", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, password), READONLY, "The TURN password to use for the allocate request." },
  { "kind", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, kind), READONLY, "Relay kind. One of: turn-udp, turn-tcp, turn-tls." },
  { NULL }
};

static PyMethodDef PyPortalMembership_methods[] =
{
  { "terminate", (PyCFunction) PyPortalMembership_terminate, METH_NOARGS, "Terminate the membership." },
  { NULL }
};

static PyMethodDef PyPortalService_methods[] =
{
  { "start", (PyCFunction
```