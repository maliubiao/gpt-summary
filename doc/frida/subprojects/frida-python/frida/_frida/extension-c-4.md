Response:
Let's break down the thought process for analyzing the provided C code snippet from the Frida project.

**1. Understanding the Goal:**

The initial prompt asks for a functional breakdown of a specific C file within Frida's Python bindings. Key areas of focus are its relation to reverse engineering, low-level details, logical reasoning, common errors, debugging, and a final summary. The "Part 5 of 5" suggests we should provide a comprehensive overview, not just isolated observations.

**2. Initial Scan and Keyword Spotting:**

I'd start by quickly scanning the code for recognizable keywords and patterns. This helps to get a general idea of the file's purpose:

* **`Py...`:**  This prefix immediately indicates interaction with the Python C API. It signifies that this C code is part of the bridge between Frida's core C++ functionality and its Python interface.
* **`Frida...`:**  Functions and structures with this prefix likely belong to Frida's internal C API. This confirms the file's role as part of the Python bindings.
* **`GObject`:**  This suggests the use of the GLib object system, a common framework in projects like Frida. It often involves object creation, destruction, and signal handling.
* **`AsyncReadyCallback`, `GTask`, `g_thread_pool_push`:** These indicate asynchronous operations and thread management. This is relevant for performance and non-blocking behavior.
* **`PyArg_ParseTuple`, `PyObject_CallFunction`:** These are standard Python C API functions for interacting with Python objects and function calls.
* **`GCancellable`:** This points to support for cancelling operations, crucial for long-running or potentially stuck tasks.
* **`build`, `watch`, `compile`:** These terms suggest functionality related to code compilation or bundling, likely for injecting JavaScript into target processes.
* **`FileMonitor`:**  This suggests the ability to monitor file system events, a common technique in dynamic analysis and hooking.
* **`IOStream`:** This indicates handling of input/output streams, essential for communication with target processes.
* **`repr`:** This method is for generating string representations of objects, useful for debugging in Python.
* **`raise`:** This suggests error handling and propagation to the Python layer.

**3. Categorizing Functionality:**

Based on the keywords and initial scan, I'd start grouping related functions:

* **Authentication:**  The `FridaPythonAuthenticationService` functions clearly deal with authentication.
* **Code Compilation/Building:** The `PyCompiler` functions (`build`, `watch`) are related to compiling code (likely Frida scripts).
* **File Monitoring:** The `PyFileMonitor` functions (`enable`, `disable`) handle file system monitoring.
* **IO Streams:** The `PyIOStream` functions (`read`, `write`, `close`) manage input/output streams.
* **Cancellation:** The `PyCancellable` functions (`cancel`, `is_cancelled`, `connect`) deal with cancelling operations.
* **Error Handling:** `PyFrida_raise` is a dedicated error handling function.
* **Utility/Helpers:**  `PyFrida_repr`, `PyFrida_get_max_argument_count` provide utility functions.
* **Module Initialization:** `PyInit__frida` is the entry point for the C extension.

**4. Analyzing Each Functional Group and Connecting to Concepts:**

Now, I would delve into each group, connecting the C code to the concepts mentioned in the prompt:

* **Authentication:**  Relate to security, bypassing checks, and how Frida might authenticate with a target process.
* **Code Compilation:** Connect to the core of Frida's scripting capabilities, injecting and running JavaScript. Explain how this interacts with reverse engineering (dynamic analysis). Think about the binary level (compiling to bytecode or similar).
* **File Monitoring:**  Explain how this is used in reverse engineering to track file access, which can reveal program behavior. Link to OS-level APIs for file monitoring (though the C code doesn't directly show those).
* **IO Streams:**  Essential for communication. In reverse engineering, this could be for sending commands to a hooked process or receiving data back. Think about inter-process communication (IPC) at the kernel level.
* **Cancellation:** Explain why this is important in dynamic analysis to avoid getting stuck.
* **Error Handling:** Explain how errors are translated from the C layer to Python exceptions.

**5. Considering the "Why" and "How":**

For each functional area, consider:

* **Why is this needed?** (e.g., Authentication for security, compilation for scripting, file monitoring for behavior analysis).
* **How does it work at a basic level?** (e.g., calling Python callbacks, using GLib's asynchronous mechanisms).
* **What are the potential user errors?** (e.g., providing incorrect arguments, not handling exceptions).
* **How would a user reach this code?** (Trace back the Python API calls to the underlying C functions).

**6. Logical Reasoning and Assumptions:**

Look for places where assumptions are made or logical flows are apparent:

* **Authentication:** The code assumes a callback function is provided by the Python user.
* **Compilation:**  It assumes a valid entry point and project structure.
* **Error Handling:**  It assumes that GError structures are properly populated by Frida's core.

**7. Structuring the Answer:**

Organize the findings into the categories requested by the prompt:

* **Functionality:** List each group of functions and their purpose.
* **Relationship to Reverse Engineering:** Provide concrete examples for each relevant area (compilation, file monitoring, IO streams).
* **Binary/Kernel/Framework Knowledge:** Point out where the code interacts with low-level concepts (threading, file system, IPC).
* **Logical Reasoning:** Explain the assumptions and logical flows.
* **Common User Errors:** Give practical examples of mistakes users might make.
* **User Path to Code:** Describe the Python API calls that would lead to these C functions.
* **Summary:**  Provide a concise overview of the file's role.

**8. Iteration and Refinement:**

After the initial analysis, review and refine the answer. Ensure clarity, accuracy, and completeness. Check for any missed connections or areas that need further explanation. The "Part 5 of 5" requires a holistic view, so ensure that individual points are tied together to illustrate the overall purpose of the file within the Frida ecosystem. For instance, how the compiler builds scripts that are then injected and communicate via IO streams.

By following these steps, I can systematically analyze the provided C code and generate a comprehensive and informative response that addresses all aspects of the prompt. The process involves a combination of code understanding, domain knowledge (reverse engineering, operating systems), and analytical thinking.
This is the source code for the `extension.c` file in the Frida Python bindings. It serves as a crucial bridge connecting Frida's core C/C++ functionality with the Python API that users interact with. Let's break down its functionalities based on the provided code snippet.

**General Functionality:**

This file defines several Python classes that wrap corresponding Frida core functionalities. It uses the Python C API and the GLib/GObject framework (indicated by `GObject`, `GTask`, `GCancellable`, etc.) to achieve this. The primary function of this file is to **expose Frida's features to Python developers in a Pythonic way.**

**Specific Functionalities and Connections to Concepts:**

Here's a breakdown of the functionalities exposed in the snippet, along with connections to reverse engineering, low-level details, logical reasoning, user errors, and debugging:

**1. Authentication (`FridaPythonAuthenticationService`)**

* **Functionality:**  Provides a way for Frida to handle custom authentication mechanisms. It takes a token as input and uses a Python callback to validate it.
* **Reverse Engineering Relevance:**  When connecting to a Frida server or agent, authentication might be required. This allows for custom authentication schemes beyond standard methods. For example, a target application might have its own authentication protocol that needs to be replicated in Frida.
    * **Example:**  Imagine a mobile app that uses a specific device ID and a secret key for authentication. This service could be used to implement that logic in Python and pass the generated token to the Frida core.
* **Binary/Kernel/Framework Knowledge:** This uses GLib's asynchronous task mechanism (`GTask`, `g_thread_pool_push`) for non-blocking authentication. This interacts with the underlying operating system's threading capabilities.
* **Logical Reasoning:**
    * **Assumption:** The Python callback function (`self->callback`) will return a string representing session information if authentication is successful, otherwise `NULL` or raise an exception.
    * **Input:** A string `token`.
    * **Output:** A string `session_info` (on success) or an error.
* **Common User Errors:**
    * Providing an invalid or incorrectly formatted token.
    * The Python callback function raising an unhandled exception, causing the authentication to fail.
    * The Python callback not returning a string when authentication is successful.
* **User Path (Debugging):** A user might interact with authentication when connecting to a remote Frida server or a Frida agent running in a specific process. The Python code would initiate the connection, and if custom authentication is configured, this C code would be involved. Debugging might involve setting breakpoints in the Python callback or examining the `token` being passed.

**2. Code Compilation (`PyCompiler`)**

* **Functionality:**  Allows compilation of JavaScript code (likely Frida scripts) using the Frida compiler. It supports options like entry point, project root, source maps, and compression.
* **Reverse Engineering Relevance:**  Frida heavily relies on injecting JavaScript into target processes to perform dynamic instrumentation. This functionality is crucial for preparing and bundling those scripts.
    * **Example:** A reverse engineer writes a Frida script to hook specific functions in an Android app. This `PyCompiler` class would be used to build that script into a deployable bundle.
* **Binary/Kernel/Framework Knowledge:**  The compilation process itself likely involves lower-level operations like reading files, parsing code, and potentially generating bytecode or optimized JavaScript. The `frida_compiler_build_sync` function interacts with Frida's core compilation engine. The concept of "source maps" relates to debugging and mapping compiled code back to the original source, a common technique in web development that Frida leverages.
* **Logical Reasoning:**
    * **Assumption:** The provided `entrypoint` is a valid file path to the main JavaScript file.
    * **Input:** `entrypoint` (string), optional `project_root`, `source_maps`, `compression` (strings).
    * **Output:** A string containing the compiled script bundle (on success) or an error.
* **Common User Errors:**
    * Providing an incorrect or non-existent `entrypoint`.
    * Specifying invalid values for `source_maps` or `compression`.
    * Issues with the project structure or dependencies if `project_root` is used.
* **User Path (Debugging):** A user would typically use the `frida.Compiler` class in Python and call its `build()` or `watch()` methods. Debugging might involve checking the file paths, compiler options, or looking at the output bundle for errors.

**3. File Monitoring (`PyFileMonitor`)**

* **Functionality:** Enables monitoring of file system events for a specific path.
* **Reverse Engineering Relevance:**  Tracking file access can be a powerful technique in reverse engineering to understand how an application interacts with the file system, what files it reads or writes, and when.
    * **Example:** Monitoring the configuration files of an application to see when and how it loads its settings.
* **Binary/Kernel/Framework Knowledge:**  This relies on underlying operating system APIs for file system monitoring (e.g., `inotify` on Linux, `FSEvents` on macOS). Frida's core abstracts these platform-specific details.
* **Logical Reasoning:**
    * **Assumption:** The provided `path` is a valid file or directory.
    * **Input:** `path` (string).
    * **Output:** None (methods `enable` and `disable` perform actions). Events would be emitted through signals (not shown in this snippet).
* **Common User Errors:**
    * Providing an invalid or inaccessible file path.
    * Not properly handling the file system events emitted by the monitor.
* **User Path (Debugging):** A user would create a `frida.FileMonitor` object in Python and call `enable()`. They would then typically connect to signals emitted by the monitor to receive file system events. Debugging might involve checking if the monitor is enabled, if the correct path is being monitored, and examining the received events.

**4. IO Streams (`PyIOStream`)**

* **Functionality:** Provides an interface to interact with input and output streams, likely for communication with Frida agents or processes.
* **Reverse Engineering Relevance:**  Essential for sending data to and receiving data from injected Frida scripts. This allows for more complex interactions beyond simple function hooking.
    * **Example:** Sending commands to an injected script to trigger certain actions or receiving log messages from the script.
* **Binary/Kernel/Framework Knowledge:** This wraps the `GIOStream` from GLib, which abstracts the underlying operating system's mechanisms for handling I/O.
* **Logical Reasoning:**
    * **Assumption:** The stream is open and valid for reading or writing.
    * **Input:**  For `read`: the number of bytes to read. For `write`: the data to write.
    * **Output:** For `read`: the bytes read. For `write`: the number of bytes written.
* **Common User Errors:**
    * Trying to read from a closed stream or write to a closed stream.
    * Trying to read more bytes than are available.
    * Sending or receiving data in an unexpected format.
* **User Path (Debugging):**  IO Streams are often obtained when attaching to a process or creating a session with a Frida agent. Python code would use methods like `read()` and `write()` on the stream object. Debugging might involve inspecting the data being sent and received.

**5. Cancellable Operations (`PyCancellable`)**

* **Functionality:**  Provides a mechanism to cancel asynchronous operations.
* **Reverse Engineering Relevance:**  Important for controlling long-running Frida operations, such as attaching to a process or waiting for events. Allows users to interrupt these operations if needed.
* **Binary/Kernel/Framework Knowledge:** Wraps the `GCancellable` from GLib, which provides a standard way to handle operation cancellation.
* **Logical Reasoning:**
    * **Assumption:** The cancellable object is associated with an ongoing operation.
    * **Input:** None (methods like `cancel()` perform actions).
    * **Output:** None (methods like `is_cancelled()` return status).
* **Common User Errors:**
    * Trying to cancel an operation that is already completed.
    * Not properly checking the cancellation status.
* **User Path (Debugging):** A `frida.Cancellable` object can be created and passed to asynchronous Frida functions. The user can then call `cancel()` on this object. Debugging involves checking the cancellation status and ensuring that operations are terminated as expected.

**6. Error Handling (`PyFrida_raise`)**

* **Functionality:**  A utility function to convert Frida's C-level `GError` objects into Python exceptions.
* **Reverse Engineering Relevance:**  Ensures that errors occurring within Frida's core are properly propagated to the Python user in a way that can be handled gracefully.
* **Binary/Kernel/Framework Knowledge:**  Deals with the translation between different error reporting mechanisms (GLib's `GError` and Python's exceptions).
* **Logical Reasoning:**
    * **Assumption:** A `GError` object represents an error condition.
    * **Input:** A `GError` pointer.
    * **Output:** Raises a Python exception.
* **Common User Errors:**  Users don't directly interact with this function, but understanding how errors are raised is crucial for debugging Frida scripts.
* **User Path (Debugging):** When a Frida operation fails, this function is invoked to raise the corresponding Python exception. Debugging involves examining the traceback and the specific exception type to understand the cause of the error.

**7. Module Initialization (`PyInit__frida`)**

* **Functionality:** The entry point for the C extension module. It initializes the module, registers the Python classes, and sets up constants and exceptions.
* **Reverse Engineering Relevance:** This is the foundation that makes Frida's core accessible from Python.
* **Binary/Kernel/Framework Knowledge:**  Uses the Python C API to define and register the module and its contents.
* **Logical Reasoning:** This function sets up the necessary structures for the Python interpreter to understand and use the C extension.
* **Common User Errors:**  Generally, users don't directly interact with this function. Issues here would likely indicate problems with the Frida installation or the Python bindings.
* **User Path (Debugging):** When you import the `frida` module in Python, this function is executed. Errors here would prevent the module from being imported.

**Summary of Functionality (Part 5/5):**

This `extension.c` file is the **cornerstone of the Frida Python bindings.** It acts as a **glue layer**, wrapping Frida's core C/C++ functionalities and making them accessible and usable within the Python environment. It provides Python classes for essential Frida features like authentication, code compilation, file monitoring, inter-process communication (through IO Streams), and managing asynchronous operations (using Cancellable). It also handles the crucial task of translating errors from the C layer to Python exceptions, ensuring a smooth and understandable experience for Python developers using Frida for dynamic instrumentation and reverse engineering tasks.

Prompt: 
```
这是目录为frida/subprojects/frida-python/frida/_frida/extension.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
gstate = PyGILState_Ensure ();

    Py_DecRef (self->callback);
    self->callback = NULL;

    PyGILState_Release (gstate);
  }

  G_OBJECT_CLASS (frida_python_authentication_service_parent_class)->dispose (object);
}

static void
frida_python_authentication_service_authenticate (FridaAuthenticationService * service, const gchar * token, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data)
{
  FridaPythonAuthenticationService * self;
  GTask * task;

  self = FRIDA_PYTHON_AUTHENTICATION_SERVICE (service);

  task = g_task_new (self, cancellable, callback, user_data);
  g_task_set_task_data (task, g_strdup (token), g_free);

  g_thread_pool_push (self->pool, task, NULL);
}

static gchar *
frida_python_authentication_service_authenticate_finish (FridaAuthenticationService * service, GAsyncResult * result, GError ** error)
{
  return g_task_propagate_pointer (G_TASK (result), error);
}

static void
frida_python_authentication_service_do_authenticate (GTask * task, FridaPythonAuthenticationService * self)
{
  const gchar * token;
  PyGILState_STATE gstate;
  PyObject * result;
  gchar * session_info = NULL;
  gchar * message = NULL;

  token = g_task_get_task_data (task);

  gstate = PyGILState_Ensure ();

  result = PyObject_CallFunction (self->callback, "s", token);
  if (result == NULL || !PyGObject_unmarshal_string (result, &session_info))
  {
    PyObject * type, * value, * traceback;

    PyErr_Fetch (&type, &value, &traceback);

    if (value != NULL)
    {
      PyObject * message_value = PyObject_Str (value);
      PyGObject_unmarshal_string (message_value, &message);
      Py_DecRef (message_value);
    }
    else
    {
      message = g_strdup ("Internal error");
    }

    Py_DecRef (type);
    Py_DecRef (value);
    Py_DecRef (traceback);
  }

  Py_DecRef (result);

  PyGILState_Release (gstate);

  if (session_info != NULL)
    g_task_return_pointer (task, session_info, g_free);
  else
    g_task_return_new_error (task, FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT, "%s", message);

  g_free (message);
  g_object_unref (task);
}


static int
PyCompiler_init (PyCompiler * self, PyObject * args, PyObject * kw)
{
  PyDeviceManager * manager;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTuple (args, "O!", PYFRIDA_TYPE_OBJECT (DeviceManager), &manager))
    return -1;

  PyGObject_take_handle (&self->parent, frida_compiler_new (PY_GOBJECT_HANDLE (manager)), PYFRIDA_TYPE (Compiler));

  return 0;
}

static PyObject *
PyCompiler_build (PyCompiler * self, PyObject * args, PyObject * kw)
{
  PyObject * result;
  static char * keywords[] = { "entrypoint", "project_root", "source_maps", "compression", NULL };
  const char * entrypoint;
  const char * project_root = NULL;
  const char * source_maps = NULL;
  const char * compression = NULL;
  FridaBuildOptions * options;
  GError * error = NULL;
  gchar * bundle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|sss", keywords, &entrypoint, &project_root, &source_maps, &compression))
    return NULL;

  options = frida_build_options_new ();
  if (!PyCompiler_set_options (FRIDA_COMPILER_OPTIONS (options), project_root, source_maps, compression))
    goto invalid_option_value;

  Py_BEGIN_ALLOW_THREADS
  bundle = frida_compiler_build_sync (PY_GOBJECT_HANDLE (self), entrypoint, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result = PyUnicode_FromString (bundle);
  g_free (bundle);

  return result;

invalid_option_value:
  {
    g_object_unref (options);
    return NULL;
  }
}

static PyObject *
PyCompiler_watch (PyCompiler * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "entrypoint", "project_root", "source_maps", "compression", NULL };
  const char * entrypoint;
  const char * project_root = NULL;
  const char * source_maps = NULL;
  const char * compression = NULL;
  FridaWatchOptions * options;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|sss", keywords, &entrypoint, &project_root, &source_maps, &compression))
    return NULL;

  options = frida_watch_options_new ();
  if (!PyCompiler_set_options (FRIDA_COMPILER_OPTIONS (options), project_root, source_maps, compression))
    goto invalid_option_value;

  Py_BEGIN_ALLOW_THREADS
  frida_compiler_watch_sync (PY_GOBJECT_HANDLE (self), entrypoint, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;

invalid_option_value:
  {
    g_object_unref (options);
    return NULL;
  }
}

static gboolean
PyCompiler_set_options (FridaCompilerOptions * options, const gchar * project_root_value, const gchar * source_maps_value,
    const gchar * compression_value)
{
  if (project_root_value != NULL)
    frida_compiler_options_set_project_root (options, project_root_value);

  if (source_maps_value != NULL)
  {
    FridaSourceMaps source_maps;

    if (!PyGObject_unmarshal_enum (source_maps_value, FRIDA_TYPE_SOURCE_MAPS, &source_maps))
      return FALSE;

    frida_compiler_options_set_source_maps (options, source_maps);
  }

  if (compression_value != NULL)
  {
    FridaJsCompression compression;

    if (!PyGObject_unmarshal_enum (compression_value, FRIDA_TYPE_JS_COMPRESSION, &compression))
      return FALSE;

    frida_compiler_options_set_compression (options, compression);
  }

  return TRUE;
}


static int
PyFileMonitor_init (PyFileMonitor * self, PyObject * args, PyObject * kw)
{
  const char * path;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTuple (args, "s", &path))
    return -1;

  PyGObject_take_handle (&self->parent, frida_file_monitor_new (path), PYFRIDA_TYPE (FileMonitor));

  return 0;
}

static PyObject *
PyFileMonitor_enable (PyFileMonitor * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_file_monitor_enable_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyFileMonitor_disable (PyFileMonitor * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_file_monitor_disable_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}


static PyObject *
PyIOStream_new_take_handle (GIOStream * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (IOStream));
}

static int
PyIOStream_init (PyIOStream * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->input = NULL;
  self->output = NULL;

  return 0;
}

static void
PyIOStream_init_from_handle (PyIOStream * self, GIOStream * handle)
{
  self->input = g_io_stream_get_input_stream (handle);
  self->output = g_io_stream_get_output_stream (handle);
}

static PyObject *
PyIOStream_repr (PyIOStream * self)
{
  GIOStream * handle = PY_GOBJECT_HANDLE (self);

  return PyUnicode_FromFormat ("IOStream(handle=%p, is_closed=%s)",
      handle,
      g_io_stream_is_closed (handle) ? "TRUE" : "FALSE");
}

static PyObject *
PyIOStream_is_closed (PyIOStream * self)
{
  return PyBool_FromLong (g_io_stream_is_closed (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyIOStream_close (PyIOStream * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  g_io_stream_close (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyIOStream_read (PyIOStream * self, PyObject * args)
{
  PyObject * result;
  unsigned long count;
  PyObject * buffer;
  GError * error = NULL;
  gssize bytes_read;

  if (!PyArg_ParseTuple (args, "k", &count))
    return NULL;

  buffer = PyBytes_FromStringAndSize (NULL, count);
  if (buffer == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  bytes_read = g_input_stream_read (self->input, PyBytes_AsString (buffer), count, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    if ((unsigned long) bytes_read == count)
    {
      result = buffer;
    }
    else
    {
      result = PyBytes_FromStringAndSize (PyBytes_AsString (buffer), bytes_read);

      Py_DecRef (buffer);
    }
  }
  else
  {
    result = PyFrida_raise (error);

    Py_DecRef (buffer);
  }

  return result;
}

static PyObject *
PyIOStream_read_all (PyIOStream * self, PyObject * args)
{
  PyObject * result;
  unsigned long count;
  PyObject * buffer;
  gsize bytes_read;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "k", &count))
    return NULL;

  buffer = PyBytes_FromStringAndSize (NULL, count);
  if (buffer == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  g_input_stream_read_all (self->input, PyBytes_AsString (buffer), count, &bytes_read, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    result = buffer;
  }
  else
  {
    result = PyFrida_raise (error);

    Py_DecRef (buffer);
  }

  return result;
}

static PyObject *
PyIOStream_write (PyIOStream * self, PyObject * args)
{
  const char * data;
  Py_ssize_t size;
  GError * error = NULL;
  gssize bytes_written;

  if (!PyArg_ParseTuple (args, "y#", &data, &size))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  bytes_written = g_output_stream_write (self->output, data, size, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromSsize_t (bytes_written);
}

static PyObject *
PyIOStream_write_all (PyIOStream * self, PyObject * args)
{
  const char * data;
  Py_ssize_t size;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "y#", &data, &size))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  g_output_stream_write_all (self->output, data, size, NULL, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}


static PyObject *
PyCancellable_new_take_handle (GCancellable * handle)
{
  PyObject * object;

  object = (handle != NULL) ? PyGObject_try_get_from_handle (handle) : NULL;
  if (object == NULL)
  {
    object = PyObject_CallFunction (PYFRIDA_TYPE_OBJECT (Cancellable), "z#", (char *) &handle, (Py_ssize_t) sizeof (handle));
  }
  else
  {
    g_object_unref (handle);
    Py_IncRef (object);
  }

  return object;
}

static int
PyCancellable_init (PyCancellable * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "handle", NULL };
  GCancellable ** handle_buffer = NULL;
  Py_ssize_t handle_size = 0;
  GCancellable * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|z#", keywords, &handle_buffer, &handle_size))
    return -1;

  if (handle_size == sizeof (gpointer))
    handle = *handle_buffer;
  else
    handle = g_cancellable_new ();

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (Cancellable));

  return 0;
}

static PyObject *
PyCancellable_repr (PyCancellable * self)
{
  GCancellable * handle = PY_GOBJECT_HANDLE (self);

  return PyUnicode_FromFormat ("Cancellable(handle=%p, is_cancelled=%s)",
      handle,
      g_cancellable_is_cancelled (handle) ? "TRUE" : "FALSE");
}

static PyObject *
PyCancellable_is_cancelled (PyCancellable * self)
{
  return PyBool_FromLong (g_cancellable_is_cancelled (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyCancellable_raise_if_cancelled (PyCancellable * self)
{
  GError * error = NULL;

  g_cancellable_set_error_if_cancelled (PY_GOBJECT_HANDLE (self), &error);
  if (error != NULL)
    return PyFrida_raise (error);

  PyFrida_RETURN_NONE;
}

static PyObject *
PyCancellable_get_fd (PyCancellable * self)
{
  return PyLong_FromLong (g_cancellable_get_fd (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyCancellable_release_fd (PyCancellable * self)
{
  g_cancellable_release_fd (PY_GOBJECT_HANDLE (self));

  PyFrida_RETURN_NONE;
}

static PyObject *
PyCancellable_get_current (PyCancellable * self)
{
  GCancellable * handle;

  handle = g_cancellable_get_current ();

  if (handle != NULL)
    g_object_ref (handle);

  return PyCancellable_new_take_handle (handle);
}

static PyObject *
PyCancellable_push_current (PyCancellable * self)
{
  g_cancellable_push_current (PY_GOBJECT_HANDLE (self));

  PyFrida_RETURN_NONE;
}

static PyObject *
PyCancellable_pop_current (PyCancellable * self)
{
  GCancellable * handle = PY_GOBJECT_HANDLE (self);

  if (g_cancellable_get_current () != handle)
    goto invalid_operation;

  g_cancellable_pop_current (handle);

  PyFrida_RETURN_NONE;

invalid_operation:
  {
    return PyFrida_raise (g_error_new (
          FRIDA_ERROR,
          FRIDA_ERROR_INVALID_OPERATION,
          "Cancellable is not on top of the stack"));
  }
}

static PyObject *
PyCancellable_connect (PyCancellable * self, PyObject * args)
{
  GCancellable * handle = PY_GOBJECT_HANDLE (self);
  gulong handler_id;
  PyObject * callback;

  if (!PyArg_ParseTuple (args, "O", &callback))
    return NULL;

  if (!PyCallable_Check (callback))
    goto not_callable;

  if (handle != NULL)
  {
    Py_IncRef (callback);

    Py_BEGIN_ALLOW_THREADS
    handler_id = g_cancellable_connect (handle, G_CALLBACK (PyCancellable_on_cancelled), callback,
        (GDestroyNotify) PyCancellable_destroy_callback);
    Py_END_ALLOW_THREADS
  }
  else
  {
    handler_id = 0;
  }

  return PyLong_FromUnsignedLong (handler_id);

not_callable:
  {
    PyErr_SetString (PyExc_TypeError, "object must be callable");
    return NULL;
  }
}

static PyObject *
PyCancellable_disconnect (PyCancellable * self, PyObject * args)
{
  gulong handler_id;

  if (!PyArg_ParseTuple (args, "k", &handler_id))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  g_cancellable_disconnect (PY_GOBJECT_HANDLE (self), handler_id);
  Py_END_ALLOW_THREADS

  PyFrida_RETURN_NONE;
}

static void
PyCancellable_on_cancelled (GCancellable * cancellable, PyObject * callback)
{
  PyGILState_STATE gstate;
  PyObject * result;

  gstate = PyGILState_Ensure ();

  result = PyObject_CallObject (callback, NULL);
  if (result != NULL)
    Py_DecRef (result);
  else
    PyErr_Print ();

  PyGILState_Release (gstate);
}

static void
PyCancellable_destroy_callback (PyObject * callback)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();
  Py_DecRef (callback);
  PyGILState_Release (gstate);
}

static PyObject *
PyCancellable_cancel (PyCancellable * self)
{
  Py_BEGIN_ALLOW_THREADS
  g_cancellable_cancel (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  PyFrida_RETURN_NONE;
}


static void
PyFrida_object_decref (gpointer obj)
{
  PyObject * o = obj;
  Py_DecRef (o);
}

static PyObject *
PyFrida_raise (GError * error)
{
  PyObject * exception;
  GString * message;

  if (error->domain == FRIDA_ERROR)
  {
    exception = g_hash_table_lookup (frida_exception_by_error_code, GINT_TO_POINTER (error->code));
    g_assert (exception != NULL);
  }
  else
  {
    g_assert (error->domain == G_IO_ERROR);
    g_assert (error->code == G_IO_ERROR_CANCELLED);
    exception = cancelled_exception;
  }

  message = g_string_new ("");
  g_string_append_unichar (message, g_unichar_tolower (g_utf8_get_char (error->message)));
  g_string_append (message, g_utf8_offset_to_pointer (error->message, 1));

  PyErr_SetString (exception, message->str);

  g_string_free (message, TRUE);
  g_error_free (error);

  return NULL;
}

static gchar *
PyFrida_repr (PyObject * obj)
{
  gchar * result;
  PyObject * repr_value;

  repr_value = PyObject_Repr (obj);

  PyGObject_unmarshal_string (repr_value, &result);

  Py_DecRef (repr_value);

  return result;
}

static guint
PyFrida_get_max_argument_count (PyObject * callable)
{
  guint result = G_MAXUINT;
  PyObject * spec;
  PyObject * varargs = NULL;
  PyObject * args = NULL;
  PyObject * is_method;

  spec = PyObject_CallFunction (inspect_getargspec, "O", callable);
  if (spec == NULL)
  {
    PyErr_Clear ();
    goto beach;
  }

  varargs = PyTuple_GetItem (spec, 1);
  if (varargs != Py_None)
    goto beach;

  args = PyTuple_GetItem (spec, 0);

  result = PyObject_Size (args);

  is_method = PyObject_CallFunction (inspect_ismethod, "O", callable);
  g_assert (is_method != NULL);
  if (is_method == Py_True)
    result--;
  Py_DecRef (is_method);

beach:
  Py_DecRef (spec);

  return result;
}


PyMODINIT_FUNC
PyInit__frida (void)
{
  PyObject * inspect, * datetime, * module;

  inspect = PyImport_ImportModule ("inspect");
  inspect_getargspec = PyObject_GetAttrString (inspect, "getfullargspec");
  inspect_ismethod = PyObject_GetAttrString (inspect, "ismethod");
  Py_DecRef (inspect);

  datetime = PyImport_ImportModule ("datetime");
  datetime_constructor = PyObject_GetAttrString (datetime, "datetime");
  Py_DecRef (datetime);

  frida_init ();

  PyGObject_class_init ();

  module = PyModule_Create (&PyFrida_moduledef);

  PyModule_AddStringConstant (module, "__version__", frida_version_string ());

  PYFRIDA_REGISTER_TYPE (GObject, G_TYPE_OBJECT);
  PyGObject_tp_init = PyType_GetSlot ((PyTypeObject *) PYFRIDA_TYPE_OBJECT (GObject), Py_tp_init);
  PyGObject_tp_dealloc = PyType_GetSlot ((PyTypeObject *) PYFRIDA_TYPE_OBJECT (GObject), Py_tp_dealloc);

  PYFRIDA_REGISTER_TYPE (DeviceManager, FRIDA_TYPE_DEVICE_MANAGER);
  PYFRIDA_REGISTER_TYPE (Device, FRIDA_TYPE_DEVICE);
  PYFRIDA_REGISTER_TYPE (Application, FRIDA_TYPE_APPLICATION);
  PYFRIDA_REGISTER_TYPE (Process, FRIDA_TYPE_PROCESS);
  PYFRIDA_REGISTER_TYPE (Spawn, FRIDA_TYPE_SPAWN);
  PYFRIDA_REGISTER_TYPE (Child, FRIDA_TYPE_CHILD);
  PYFRIDA_REGISTER_TYPE (Crash, FRIDA_TYPE_CRASH);
  PYFRIDA_REGISTER_TYPE (Bus, FRIDA_TYPE_BUS);
  PYFRIDA_REGISTER_TYPE (Service, FRIDA_TYPE_SERVICE);
  PYFRIDA_REGISTER_TYPE (Session, FRIDA_TYPE_SESSION);
  PYFRIDA_REGISTER_TYPE (Script, FRIDA_TYPE_SCRIPT);
  PYFRIDA_REGISTER_TYPE (Relay, FRIDA_TYPE_RELAY);
  PYFRIDA_REGISTER_TYPE (PortalMembership, FRIDA_TYPE_PORTAL_MEMBERSHIP);
  PYFRIDA_REGISTER_TYPE (PortalService, FRIDA_TYPE_PORTAL_SERVICE);
  PYFRIDA_REGISTER_TYPE (EndpointParameters, FRIDA_TYPE_ENDPOINT_PARAMETERS);
  PYFRIDA_REGISTER_TYPE (Compiler, FRIDA_TYPE_COMPILER);
  PYFRIDA_REGISTER_TYPE (FileMonitor, FRIDA_TYPE_FILE_MONITOR);
  PYFRIDA_REGISTER_TYPE (IOStream, G_TYPE_IO_STREAM);
  PYFRIDA_REGISTER_TYPE (Cancellable, G_TYPE_CANCELLABLE);

  frida_exception_by_error_code = g_hash_table_new_full (NULL, NULL, NULL, PyFrida_object_decref);
#define PYFRIDA_DECLARE_EXCEPTION(code, name) \
    do \
    { \
      PyObject * exception = PyErr_NewException ("frida." name "Error", NULL, NULL); \
      g_hash_table_insert (frida_exception_by_error_code, GINT_TO_POINTER (G_PASTE (FRIDA_ERROR_, code)), exception); \
      Py_IncRef (exception); \
      PyModule_AddObject (module, name "Error", exception); \
    } while (FALSE)
  PYFRIDA_DECLARE_EXCEPTION (SERVER_NOT_RUNNING, "ServerNotRunning");
  PYFRIDA_DECLARE_EXCEPTION (EXECUTABLE_NOT_FOUND, "ExecutableNotFound");
  PYFRIDA_DECLARE_EXCEPTION (EXECUTABLE_NOT_SUPPORTED, "ExecutableNotSupported");
  PYFRIDA_DECLARE_EXCEPTION (PROCESS_NOT_FOUND, "ProcessNotFound");
  PYFRIDA_DECLARE_EXCEPTION (PROCESS_NOT_RESPONDING, "ProcessNotResponding");
  PYFRIDA_DECLARE_EXCEPTION (INVALID_ARGUMENT, "InvalidArgument");
  PYFRIDA_DECLARE_EXCEPTION (INVALID_OPERATION, "InvalidOperation");
  PYFRIDA_DECLARE_EXCEPTION (PERMISSION_DENIED, "PermissionDenied");
  PYFRIDA_DECLARE_EXCEPTION (ADDRESS_IN_USE, "AddressInUse");
  PYFRIDA_DECLARE_EXCEPTION (TIMED_OUT, "TimedOut");
  PYFRIDA_DECLARE_EXCEPTION (NOT_SUPPORTED, "NotSupported");
  PYFRIDA_DECLARE_EXCEPTION (PROTOCOL, "Protocol");
  PYFRIDA_DECLARE_EXCEPTION (TRANSPORT, "Transport");

  cancelled_exception = PyErr_NewException ("frida.OperationCancelledError", NULL, NULL);
  Py_IncRef (cancelled_exception);
  PyModule_AddObject (module, "OperationCancelledError", cancelled_exception);

  return module;
}

"""


```